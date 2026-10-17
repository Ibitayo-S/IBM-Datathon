'use strict';

// ================================================================== helpers
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtMs = ms => (ms >= 1000 ? (ms / 1000).toFixed(2) + ' s' : Math.round(ms) + ' ms');
const fmtMbps = v => (v >= 100 ? Math.round(v) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + ' Mbps';
const keyOf = r => r.ee_alg + '|' + r.ca_alg;
const mean = a => a.reduce((s, x) => s + x, 0) / a.length;
const median = a => { const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const reduceMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const sleep = ms => new Promise(r => setTimeout(r, reduceMotion() ? 0 : ms));
const familyOf = name => (name.startsWith('ML-DSA') ? 'ml' : 'slh');
const groupOf = r => { const a = familyOf(r.ee_alg), b = familyOf(r.ca_alg); return a === b ? a : 'mixed'; };
const GROUP_NAMES = { ml: 'ML-DSA chains', mixed: 'Mixed chains', slh: 'SLH-DSA chains' };
function applyWidths(root) {
  root.querySelectorAll('[data-w]').forEach(el => { el.style.width = el.dataset.w + '%'; });
  root.querySelectorAll('[data-l]').forEach(el => { el.style.left = el.dataset.l + '%'; });
}
class SignedOut extends Error {}

// Network probe endpoints. tools/build_demo.py swaps these for the demo build.
const PROBE = {
  ping: () => `/api/probe/ping?_=${Date.now()}${Math.random().toString(36).slice(2)}`,
  pingMethod: 'GET',
  download: bytes => `/api/probe/download?bytes=${bytes}&_=${Date.now()}`,
};

// "What if the network gets busier" scenarios. Hypothetical, clearly labelled in the report.
const SCENARIOS = [
  { key: 'now', label: 'Your network', note: 'As measured', lat: 1, bw: 1 },
  { key: 'busy', label: 'Busier', note: 'Latency doubled, bandwidth halved', lat: 2, bw: 0.5 },
  { key: 'heavy', label: 'Heavily loaded', note: 'Latency x4, bandwidth a quarter', lat: 4, bw: 0.25 },
];

// ================================================================== why post-quantum is slower
// First-principles estimate of the authentication bytes in a TLS 1.3 server flight, and how many
// round trips TCP needs to deliver them. Independent of the ML model; shown as an explanation.
const CLASSICAL = { name: 'ECDSA P-256', pk: 65, sig: 72 };  // a typical classical chain today
const CERT_OVERHEAD = 300;     // bytes of X.509 fields per certificate besides key and signature (approx.)
const OTHER_HANDSHAKE = 400;   // ServerHello, EncryptedExtensions, Finished, record headers (approx.)
const MSS = 1460, INITCWND = 10;  // TCP initial congestion window: 10 segments, about 14.6 KB
const INITCWND_BYTES = MSS * INITCWND;
let ALG = {};                  // algorithm name -> { pk, sig, category }

// EE certificate (EE key + CA signature) + CA certificate (CA key + CA signature) + CertificateVerify (EE signature)
const authBytes = (ee, ca) => (ee.pk + ca.sig + CERT_OVERHEAD) + (ca.pk + ca.sig + CERT_OVERHEAD) + ee.sig + OTHER_HANDSHAKE;
function flightsFor(bytes) {   // TCP slow start: 10 segments, then 20, 40, ...
  const segs = Math.ceil(bytes / MSS);
  let cwnd = INITCWND, sent = 0, rounds = 0;
  while (sent < segs) { sent += cwnd; cwnd *= 2; rounds++; }
  return rounds;
}
const CLASSICAL_BYTES = authBytes(CLASSICAL, CLASSICAL);
const CLASSICAL_FLIGHTS = flightsFor(CLASSICAL_BYTES);
const fmtKB = b => (b >= 102400 ? Math.round(b / 1024) : (b / 1024).toFixed(1)) + ' KB';

// Network numbers the estimate needs: a round trip and a bandwidth, measured if possible.
function netFor(m) {
  const rtt = m.pings.length ? median(m.pings) : (m.hint && m.hint.rtt) || null;
  const mbps = m.download ? m.download.mbps : (m.hint && m.hint.downlink) || null;
  return { rtt, mbps };
}
function overheadFor(eeName, caName, net) {
  const ee = ALG[eeName], ca = ALG[caName];
  if (!ee || !ca) return null;
  const bytes = authBytes(ee, ca), flights = flightsFor(bytes);
  const extraBytes = bytes - CLASSICAL_BYTES, extraTrips = flights - CLASSICAL_FLIGHTS;
  const tripMs = net.rtt != null ? extraTrips * net.rtt : null;
  const transferMs = net.mbps ? extraBytes * 8 / (net.mbps * 1e6) * 1000 : null;
  const addedMs = tripMs != null && transferMs != null ? tripMs + transferMs : null;
  return { bytes, flights, extraBytes, extraTrips, tripMs, transferMs, addedMs };
}

// ================================================================== state
let csrf = null;
let meta = null;
let lastRun = null;       // /api/recommend response + inputs for the latest test
let prevRun = null;       // previous test, for the change column
let measurement = null;   // what the browser measured
let inputsUsed = null;    // { telemetry, rows } sent to the model, with a source per input
let scenarios = null;     // [{ ...SCENARIOS[i], data | error }]
let net = null;           // { rtt, mbps } used for the overhead estimate
let sortKey = 'predicted_ms';
let sortAsc = true;
let running = false;
let slide = 0;

// ================================================================== API and session
async function api(path, { method = 'GET', json, form } = {}) {
  const opts = { method, credentials: 'same-origin', headers: {} };
  if (method !== 'GET') opts.headers['X-CSRF-Token'] = csrf || '';
  if (json !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(json); }
  if (form) opts.body = form;
  let res;
  try { res = await fetch(path, opts); } catch (_) { throw new Error('Cannot reach the PQConnect server. Check your connection.'); }
  let data = null;
  try { data = await res.json(); } catch (_) { /* not JSON */ }
  if (res.status === 401 && path !== '/api/login') {
    showLogin('Your session ended. Sign in again.');
    throw new SignedOut('Signed out');
  }
  if (!res.ok) throw new Error((data && data.error) || `Request failed (HTTP ${res.status}).`);
  return data;
}

async function refreshSession() {
  const s = await api('/api/session');
  csrf = s.csrf;
  return s;
}

function showLogin(msg) {
  $('appView').hidden = true;
  $('loginView').hidden = false;
  $('loginError').textContent = msg || '';
  $('username').focus();
  refreshSession().catch(() => {});
}

async function enterApp() {
  meta = await api('/api/meta');
  $('userName').textContent = meta.user;
  $('userInitial').textContent = (meta.user || '?').slice(0, 1);
  const badge = $('modeBadge');
  if (meta.model.loaded) { badge.textContent = 'Model live on ' + meta.host.arch; badge.className = 'pill live'; }
  else if (meta.mock) { badge.textContent = 'Mock predictions'; badge.className = 'pill mock'; }
  else { badge.textContent = 'Model not loaded'; badge.className = 'pill mock'; }
  ALG = Object.fromEntries(meta.algorithms.map(a => [a.name, a]));
  buildAlgorithms();
  setCategory($('minCat').value);
  updatePolicySummary();
  resetHero();
  $('loginView').hidden = true;
  $('appView').hidden = false;
}

// ================================================================== policy (not network input, so it stays)
function buildAlgorithms() {
  const groups = {};
  for (const a of meta.algorithms) (groups[a.family] = groups[a.family] || []).push(a);
  $('algGroups').innerHTML = Object.entries(groups).map(([fam, list]) => `
    <div class="alg-group"><div class="alg-fam">${esc(fam)}</div><div class="chips">
      ${list.map(a => `<label class="chip" title="${esc(a.name)}, NIST category ${a.category}"><input type="checkbox" class="alg" value="${esc(a.name)}" checked><span>${esc(a.name.split('-').pop())}<small>Cat ${a.category}</small></span></label>`).join('')}
    </div></div>`).join('');
  document.querySelectorAll('.alg').forEach(c => c.addEventListener('change', updatePolicySummary));
}
function setCategory(cat) {
  $('minCat').value = String(cat);
  document.querySelectorAll('#catSeg button').forEach(b => {
    const on = b.dataset.cat === String(cat);
    b.classList.toggle('on', on);
    b.setAttribute('aria-checked', on ? 'true' : 'false');
  });
  updatePolicySummary();
}
const selectedAlgs = () => [...document.querySelectorAll('.alg:checked')].map(c => c.value);
function setAlgs(pred) { document.querySelectorAll('.alg').forEach(c => { c.checked = pred(c.value); }); updatePolicySummary(); }
function updatePolicySummary() {
  if (!meta) return;
  $('pCat').textContent = `Category ${$('minCat').value}+`;
  $('pTarget').textContent = `${fmtMs(parseFloat($('targetMs').value) || 0)} target`;
  $('pAlgs').textContent = `${selectedAlgs().length} of ${meta.algorithms.length} algorithms`;
}
function readPolicy() {
  const allowed = selectedAlgs();
  if (!allowed.length) throw new Error('Allow at least one algorithm in your policy.');
  const target = parseFloat($('targetMs').value);
  if (!Number.isFinite(target) || target < 1) throw new Error('Set a login delay target in your policy.');
  return { min_category: parseInt($('minCat').value, 10), target_ms: target, allowed_algs: allowed };
}
function togglePolicy(open) {
  const panel = $('policyPanel');
  const show = open === undefined ? panel.hidden : open;
  panel.hidden = !show;
  $('policyToggle').setAttribute('aria-expanded', show ? 'true' : 'false');
}
function setPolicyEnabled(on) { $('policyToggle').disabled = !on; if (!on) togglePolicy(false); }

// ================================================================== dial
// Ticks are evenly spaced on the dial, like a speed test. Values between ticks are linear.
const MS_TICKS = [0, 50, 100, 200, 300, 500, 750, 1000, 2000, 5000];
const MBPS_TICKS = [0, 1, 5, 10, 25, 50, 100, 250, 500, 1000];
const CX = 150, CY = 150, R = 118, SWEEP = 270;
let gaugeTicks = MS_TICKS, gaugeUnit = 'ms', gaugeFrac = 0, gaugeVal = 0;

function valToFrac(v, ticks = gaugeTicks) {
  const n = ticks.length - 1;
  if (v <= 0) return 0;
  for (let i = 0; i < n; i++) if (v <= ticks[i + 1]) return (i + (v - ticks[i]) / (ticks[i + 1] - ticks[i])) / n;
  return 1;
}
function point(f, r) {
  const a = (-SWEEP / 2 + SWEEP * f) * Math.PI / 180;
  return [CX + r * Math.sin(a), CY - r * Math.cos(a)];
}
function arcPath(f0, f1, r) {
  const [x0, y0] = point(f0, r), [x1, y1] = point(f1, r);
  return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${(f1 - f0) * SWEEP > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}
function buildGauge(ticks, unit) {
  gaugeTicks = ticks; gaugeUnit = unit; gaugeFrac = 0; gaugeVal = 0;
  const n = ticks.length - 1;
  let s = '<defs><linearGradient id="gGrad" x1="0" y1="1" x2="1" y2="0"><stop offset="0" class="g-stop1"/><stop offset="1" class="g-stop2"/></linearGradient></defs>';
  s += `<path class="g-track" d="${arcPath(0, 1, R)}"/>`;
  s += `<path id="gProg" class="g-prog" d="${arcPath(0, 1, R)}" pathLength="1000" stroke-dasharray="0 1000"/>`;
  ticks.forEach((t, i) => {
    const [x0, y0] = point(i / n, R - 13), [x1, y1] = point(i / n, R - 19), [tx, ty] = point(i / n, R - 33);
    const label = unit === 'ms' && t >= 1000 ? t / 1000 + 's' : t;
    s += `<line class="g-tickline" x1="${x0}" y1="${y0}" x2="${x1}" y2="${y1}"/>`;
    s += `<text class="g-tick" x="${tx}" y="${ty}" text-anchor="middle" dominant-baseline="middle">${label}</text>`;
  });
  s += '<g id="gTargetG" visibility="hidden"><line id="gTarget" class="g-target"/><text id="gTargetLabel" class="g-target-label" text-anchor="middle" dominant-baseline="middle">target</text></g>';
  s += `<g id="gNeedle"><polygon class="g-needle" points="${CX - 4},${CY} ${CX + 4},${CY} ${CX},${CY - R + 24}"/><circle class="g-hub" cx="${CX}" cy="${CY}" r="8"/></g>`;
  $('gaugeSvg').innerHTML = s;
  setGauge(0, 0);
}
function placeTarget(ms) {
  if (ms == null) { $('gTargetG').setAttribute('visibility', 'hidden'); return; }
  const f = valToFrac(ms);
  const [x0, y0] = point(f, R + 11), [x1, y1] = point(f, R - 11), [lx, ly] = point(f, R + 22);
  const line = $('gTarget');
  line.setAttribute('x1', x0); line.setAttribute('y1', y0); line.setAttribute('x2', x1); line.setAttribute('y2', y1);
  $('gTargetLabel').setAttribute('x', lx); $('gTargetLabel').setAttribute('y', ly);
  $('gTargetG').setAttribute('visibility', 'visible');
}
function setGauge(f, v) {
  $('gNeedle').setAttribute('transform', `rotate(${(-SWEEP / 2 + SWEEP * f).toFixed(2)} ${CX} ${CY})`);
  $('gProg').setAttribute('stroke-dasharray', `${(f * 1000).toFixed(1)} 1000`);
  if (gaugeUnit === 'Mbps') { $('gaugeValue').textContent = v >= 100 ? String(Math.round(v)) : v.toFixed(1); $('gaugeUnit').textContent = 'Mbps'; }
  else if (v >= 1000) { $('gaugeValue').textContent = (v / 1000).toFixed(2); $('gaugeUnit').textContent = 's'; }
  else { $('gaugeValue').textContent = String(Math.round(v)); $('gaugeUnit').textContent = 'ms'; }
}
function tweenTo(v, dur) {
  const f0 = gaugeFrac, v0 = gaugeVal, f1 = valToFrac(v);
  if (reduceMotion() || dur <= 0) { gaugeFrac = f1; gaugeVal = v; setGauge(f1, v); return Promise.resolve(); }
  return new Promise(resolve => {
    const t0 = performance.now();
    const step = now => {
      const t = Math.min(1, (now - t0) / dur), k = 1 - Math.pow(1 - t, 3);
      gaugeFrac = f0 + (f1 - f0) * k; gaugeVal = v0 + (v - v0) * k;
      setGauge(gaugeFrac, gaugeVal);
      if (t < 1) requestAnimationFrame(step); else resolve();
    };
    requestAnimationFrame(step);
  });
}
// Spread samples from slowest to fastest so the needle hunts down towards the best chain.
function sweepSample(rows, k) {
  const sorted = [...rows].sort((a, b) => b.predicted_ms - a.predicted_ms);
  if (sorted.length <= k) return sorted;
  return Array.from({ length: k }, (_, i) => sorted[Math.round(i * (sorted.length - 1) / (k - 1))]);
}
function setStat(id, text, cls) { $(id).textContent = text; $(id).className = 'stat-val' + (cls ? ' ' + cls : ''); }
function setPhase(text) { $('phase').textContent = text; }

// ================================================================== network measurement
// A browser cannot read Wi-Fi radio statistics. What it can do is time requests to the
// PQConnect server over the network this device is on, and read the browser's own hints.
function readHint() {
  const c = navigator.connection;
  if (!c || (!c.rtt && !c.downlink)) return null;
  return { type: c.effectiveType || null, rtt: c.rtt || null, downlink: c.downlink || null };
}
function readHandshake() {
  const nav = performance.getEntriesByType && performance.getEntriesByType('navigation')[0];
  if (!nav || !(nav.secureConnectionStart > 0) || !(nav.connectEnd > nav.secureConnectionStart)) return null;
  return { tls: nav.connectEnd - nav.secureConnectionStart, tcp: Math.max(0, nav.secureConnectionStart - nav.connectStart) };
}
// Resource Timing gives network-level timestamps for each request, so the numbers exclude
// JavaScript overhead and (for round trips) the time spent downloading response headers.
function timingFor(url) {
  const abs = new URL(url, location.href).href;
  const list = performance.getEntriesByName ? performance.getEntriesByName(abs, 'resource') : [];
  return list.length ? list[list.length - 1] : null;
}
async function timedFetch(url, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const t0 = performance.now();
  try {
    const res = await fetch(url, { method: PROBE.pingMethod, cache: 'no-store', credentials: 'same-origin', signal: ctrl.signal });
    if (res.status === 401) { showLogin('Your session ended. Sign in again.'); throw new SignedOut('Signed out'); }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    await res.arrayBuffer();
    const wall = performance.now() - t0;
    const t = timingFor(url);
    // request sent -> first byte back: one network round trip plus server time
    if (t && t.requestStart > 0 && t.responseStart > t.requestStart) return { ms: t.responseStart - t.requestStart, method: 'resource' };
    return { ms: wall, method: 'wallclock' };
  } finally { clearTimeout(timer); }
}
async function downloadOnce(bytes, onProgress, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const url = PROBE.download(bytes);
  try {
    const t0 = performance.now();
    const res = await fetch(url, { cache: 'no-store', credentials: 'same-origin', signal: ctrl.signal });
    if (res.status === 401) { showLogin('Your session ended. Sign in again.'); throw new SignedOut('Signed out'); }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const expected = Number(res.headers.get('Content-Length')) || bytes;
    const tFirst = performance.now();
    let got = 0;
    if (res.body && res.body.getReader) {
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        got += value.byteLength;
        const sec = (performance.now() - tFirst) / 1000;
        if (sec > 0.05) onProgress(got * 8 / sec / 1e6, Math.min(1, got / expected));
      }
    } else {
      got = (await res.arrayBuffer()).byteLength;
    }
    const wallSec = (performance.now() - t0) / 1000;
    if (!got) throw new Error('empty download');
    const t = timingFor(url);
    // first byte -> last byte: transfer only, no request round trip or server time
    if (t && t.responseEnd > t.responseStart && t.responseStart > 0) {
      const sec = (t.responseEnd - t.responseStart) / 1000;
      return { bytes: got, sec, mbps: got * 8 / sec / 1e6, method: 'resource' };
    }
    return { bytes: got, sec: wallSec, mbps: got * 8 / wallSec / 1e6, method: 'wallclock' };
  } finally { clearTimeout(timer); }
}
// Start small so very slow links still finish, then grow until a transfer lasts at least ~1 s.
async function downloadTest(onProgress) {
  let size = 64 * 1024, r = null;
  for (let round = 0; round < 4; round++) {
    r = await downloadOnce(size, onProgress, 30000);
    if (r.sec >= 1 || size >= 8 * 1024 * 1024) break;
    size = Math.min(8 * 1024 * 1024, Math.max(size * 2, Math.round(r.bytes / Math.max(r.sec, 0.01) * 2)));
  }
  return r;
}

// The server maps measurements onto the model's inputs (POST /api/estimate-telemetry) and says
// where each value came from. One mapping, kept next to the model.
async function estimateInputs(m) {
  const r = await api('/api/estimate-telemetry', { method: 'POST', json: {
    pings_ms: m.pings, download_mbps: m.download ? m.download.mbps : null, download_bytes: m.download ? m.download.bytes : null, download_timing: m.download ? m.download.method : null,
    timing: m.timing, hint: m.hint || {}, typical: !!m.typical } });
  const rows = r.inputs;
  return { rows, telemetry: Object.fromEntries(rows.map(x => [x.key, x.value])) };
}
function enrich(results) {
  for (const r of results) {
    const ee = ALG[r.ee_alg], ca = ALG[r.ca_alg];
    r.bytes = ee && ca ? authBytes(ee, ca) : 0;
    r.flights = r.bytes ? flightsFor(r.bytes) : 0;
  }
}
function scaleTelemetry(t, s) {
  const out = { ...t };
  for (const k of meta.latency_keys || []) if (k in out) out[k] = Math.min(600000, out[k] * s.lat);
  for (const k of meta.bandwidth_keys || []) if (k in out) out[k] = Math.max(0.01, out[k] * s.bw);
  return out;
}

// ================================================================== the test
function resetHero() {
  $('heroLede').hidden = false;
  $('stats').hidden = true;
  $('runBtn').hidden = false;
  $('gauge').hidden = true;
  $('heroError').hidden = true;
  $('heroDone').hidden = true;
  setPhase(''); $('ticker').textContent = '';
  ['statLatency', 'statDownload', 'statCount', 'statResult'].forEach(id => setStat(id, '-'));
  resetStatSubs();
}
const STAT_SUBS = { subLatency: 'cost of each extra handshake trip', subDownload: 'how fast big certificates arrive', subCount: 'TLS handshake, ECDSA or RSA', subResult: 'predicted by the model' };
function resetStatSubs() { for (const [id, t] of Object.entries(STAT_SUBS)) $(id).textContent = t; }
function showHeroError(msg, offerTypical) {
  $('gauge').hidden = true; $('runBtn').hidden = true; $('heroDone').hidden = true;
  setPhase(''); $('ticker').textContent = '';
  $('heroErrorText').textContent = msg;
  $('typicalBtn').hidden = !offerTypical;
  $('heroError').hidden = false;
}

async function runTest({ typical = false } = {}) {
  if (running) return;
  let policy;
  try { policy = readPolicy(); } catch (e) { togglePolicy(true); showHeroError(e.message, false); return; }
  running = true;
  setPolicyEnabled(false);
  $('heroLede').hidden = true; $('heroError').hidden = true; $('heroDone').hidden = true;
  $('runBtn').hidden = true; $('gauge').hidden = false; $('stats').hidden = false;
  ['statLatency', 'statDownload', 'statCount', 'statResult'].forEach(id => setStat(id, '-'));
  resetStatSubs();

  try {
    const m = { pings: [], failures: 0, attempts: 0, download: null, hint: readHint(), handshake: readHandshake(), typical, at: new Date(), timing: null };
    if (!typical) {
      if (performance.clearResourceTimings) performance.clearResourceTimings();
      if (performance.setResourceTimingBufferSize) performance.setResourceTimingBufferSize(500);
      // 1. latency: one warm-up request, then up to 10 timed round trips
      buildGauge(MS_TICKS, 'ms'); placeTarget(null);
      setPhase('Measuring the round trip to the server');
      for (let i = 0; i < 11; i++) {
        try {
          const { ms: dt, method } = await timedFetch(PROBE.ping(), 3000);
          if (i === 0) continue;
          m.attempts++; m.pings.push(dt); m.timing = method;
          setStat('statLatency', fmtMs(median(m.pings)));
          await tweenTo(dt, 160);
        } catch (e) {
          if (e instanceof SignedOut) throw e;
          if (i > 0) { m.attempts++; m.failures++; }
          if (!m.pings.length && i >= 2) break;  // server unreachable: stop early
        }
      }
      if (!m.pings.length) setStat('statLatency', m.hint && m.hint.rtt ? `~${m.hint.rtt} ms` : 'n/a');

      // 2. download
      buildGauge(MBPS_TICKS, 'Mbps');
      setPhase('Measuring bandwidth to this device');
      try {
        m.download = await downloadTest(mbps => { gaugeFrac = valToFrac(mbps); gaugeVal = mbps; setGauge(gaugeFrac, mbps); });
        await tweenTo(m.download.mbps, 250);
        setStat('statDownload', fmtMbps(m.download.mbps));
      } catch (e) {
        if (e instanceof SignedOut) throw e;
        setStat('statDownload', m.hint && m.hint.downlink ? `~${m.hint.downlink} Mbps` : 'n/a');
      }
      await sleep(250);
      if (!m.pings.length && !m.download && !(m.hint && (m.hint.rtt || m.hint.downlink))) {
        const err = new Error("Couldn't measure this network. Check you're online and the PQConnect server is reachable, or continue with typical values.");
        err.offerTypical = true;
        throw err;
      }
    } else {
      setStat('statLatency', 'typical'); setStat('statDownload', 'typical');
    }
    measurement = m;
    inputsUsed = await estimateInputs(m);
    net = netFor(m);
    if (m.handshake) { setStat('statCount', fmtMs(m.handshake.tcp + m.handshake.tls)); $('subCount').textContent = 'measured when this page connected'; }
    else if (net.rtt != null) { setStat('statCount', '~' + fmtMs(2 * net.rtt)); $('subCount').textContent = 'estimate: 2 round trips (TCP + TLS 1.3)'; }
    else setStat('statCount', 'n/a');

    // 3. score every allowed chain
    buildGauge(MS_TICKS, 'ms'); placeTarget(policy.target_ms);
    setPhase('Predicting post-quantum login time for every chain');
    const body = { ...policy, telemetry: inputsUsed.telemetry };
    const data = await api('/api/recommend', { method: 'POST', json: body });
    enrich(data.results);
    const what = SCENARIOS.slice(1).map(s => api('/api/recommend', { method: 'POST', json: { ...body, telemetry: scaleTelemetry(body.telemetry, s) } })
      .then(d => ({ ...s, data: d }), e => { if (e instanceof SignedOut) throw e; return { ...s, error: e.message }; }));
    const pool = data.results.filter(r => r.eligible);
    const sample = sweepSample(pool.length ? pool : data.results, 18);
    for (let i = 0; i < sample.length; i++) {
      $('ticker').textContent = `${sample[i].ee_alg} / ${sample[i].ca_alg}   ${Math.round(data.results.length * (i + 1) / sample.length)} of ${data.results.length}`;
      await tweenTo(sample[i].predicted_ms, 150);
    }
    $('ticker').textContent = '';

    // 4. land on the recommendation
    if (lastRun) prevRun = { label: 'previous test', map: Object.fromEntries(lastRun.results.map(r => [keyOf(r), r.predicted_ms])) };
    lastRun = { ...data, inputs: body, at: m.at };
    const best = data.recommended;
    if (best) {
      setPhase('Fastest chain your policy allows');
      await tweenTo(best.predicted_ms, 800);
      const ok = best.predicted_ms <= data.target_ms;
      $('gProg').setAttribute('class', 'g-prog ' + (ok ? 'pass' : 'over'));
      setStat('statResult', fmtMs(best.predicted_ms), ok ? 'pass' : 'warn');
      const oh = overheadFor(best.ee_alg, best.ca_alg, net);
      $('subResult').textContent = oh && oh.addedMs != null ? `about +${fmtMs(oh.addedMs)} vs classical (estimate)` : (ok ? 'inside your target' : 'over your target');
      $('doneLine').innerHTML = `Use <strong>${esc(best.ee_alg)}</strong> with a <strong>${esc(best.ca_alg)}</strong> CA: about <strong>${fmtMs(best.predicted_ms)}</strong> per login, ${ok ? 'inside' : 'over'} your ${fmtMs(data.target_ms)} target.`;
    } else {
      setPhase('No chain meets your policy');
      await tweenTo(0, 500);
      setStat('statResult', 'none', 'warn'); $('subResult').textContent = 'no chain meets your policy';
      $('doneLine').textContent = `No allowed chain reaches Category ${data.min_category}. Edit your policy and test again.`;
    }
    scenarios = [{ ...SCENARIOS[0], data }, ...(await Promise.all(what))];

    renderReport();
    renderSlides();
    $('report').hidden = false; $('slides').hidden = false; $('foot').hidden = false; $('navLinks').hidden = false;
    setupReveal();
    $('heroDone').hidden = false;
  } catch (e) {
    if (e instanceof SignedOut) { resetHero(); return; }
    showHeroError(e.message, !!e.offerTypical);
  } finally {
    running = false;
    setPolicyEnabled(true);
  }
}

// ================================================================== charts (SVG/HTML strings)
function niceLogTicks(lo, hi) {
  const out = [];
  for (let e = Math.floor(Math.log10(lo)); e <= Math.ceil(Math.log10(hi)); e++)
    for (const m of [1, 2, 5]) { const v = m * 10 ** e; if (v >= lo && v <= hi) out.push(v); }
  return out;
}
const tickLabel = v => (v >= 1000 ? v / 1000 + 's' : String(v));

function sparkSVG(values, w = 640, h = 140) {
  if (!values.length) return '<p class="empty">No round trips were measured.</p>';
  const pad = 14, lo = Math.min(...values) * 0.9, hi = Math.max(...values) * 1.1 || 1;
  const x = i => pad + (values.length === 1 ? (w - 2 * pad) / 2 : i * (w - 2 * pad) / (values.length - 1));
  const y = v => h - pad - (v - lo) / (hi - lo || 1) * (h - 2 * pad);
  const med = median(values);
  const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" role="img" aria-label="Round trip times for each probe">
    <line class="spark-med" x1="${pad}" x2="${w - pad}" y1="${y(med)}" y2="${y(med)}"/>
    <text class="spark-medlabel" x="${w - pad}" y="${y(med) - 6}" text-anchor="end">median ${fmtMs(med)}</text>
    <polyline class="spark-line" points="${pts}"/>
    ${values.map((v, i) => `<circle class="spark-dot" cx="${x(i)}" cy="${y(v)}" r="3.5"><title>Probe ${i + 1}: ${v.toFixed(1)} ms</title></circle>`).join('')}
  </svg>`;
}

function stripSVG(rows, target, best, w = 760, rowH = 58) {
  const groups = ['ml', 'mixed', 'slh'].filter(g => rows.some(r => groupOf(r) === g));
  if (!groups.length) return '<p class="empty">No chains to plot.</p>';
  const vals = rows.map(r => r.predicted_ms).concat([target]);
  const lo = Math.max(1, Math.min(...vals) / 1.4), hi = Math.max(...vals) * 1.25;
  const L = 128, Rp = 18, top = 8, axis = 28, H = top + groups.length * rowH + axis;
  const x = v => L + (Math.log(v) - Math.log(lo)) / (Math.log(hi) - Math.log(lo)) * (w - L - Rp);
  let s = `<svg class="strip" viewBox="0 0 ${w} ${H}" role="img" aria-label="Predicted login time for every chain, grouped by family">`;
  for (const t of niceLogTicks(lo, hi)) {
    s += `<line class="strip-grid" x1="${x(t)}" x2="${x(t)}" y1="${top}" y2="${H - axis}"/>`;
    s += `<text class="strip-tick" x="${x(t)}" y="${H - 8}" text-anchor="middle">${tickLabel(t)}</text>`;
  }
  groups.forEach((g, gi) => {
    const cy = top + gi * rowH + rowH / 2;
    s += `<text class="strip-label" x="0" y="${cy}" dominant-baseline="middle">${GROUP_NAMES[g]}</text>`;
    rows.filter(r => groupOf(r) === g).forEach((r, i) => {
      const jitter = (((i * 37) % 11) - 5) * 3;
      const cls = !r.eligible ? 'off' : r.predicted_ms > target ? 'over' : 'pass';
      const isBest = best && keyOf(r) === keyOf(best);
      s += `<circle class="dot ${cls}${isBest ? ' best' : ''}" cx="${x(r.predicted_ms).toFixed(1)}" cy="${(cy + jitter).toFixed(1)}" r="${isBest ? 7 : 4.5}"><title>${esc(r.ee_alg)} / ${esc(r.ca_alg)}: ${fmtMs(r.predicted_ms)}${r.eligible ? '' : ' (below your minimum category)'}</title></circle>`;
    });
  });
  s += `<line class="strip-target" x1="${x(target)}" x2="${x(target)}" y1="${top - 4}" y2="${H - axis}"/>`;
  const tx = x(target), flip = tx > w - 110;
  s += `<text class="strip-targetlabel" x="${flip ? tx - 6 : tx + 6}" y="${top + 8}" text-anchor="${flip ? 'end' : 'start'}">target ${fmtMs(target)}</text>`;
  return s + '</svg>';
}
function stripLegend() {
  return `<div class="legend"><span><i class="lg pass"></i>Meets target</span><span><i class="lg over"></i>Over target</span><span><i class="lg off"></i>Below your minimum category</span><span><i class="lg best"></i>Recommended</span></div>`;
}

// Fastest chain at or above each NIST category, from the chains actually scored.
function ladderRows(results) {
  return [1, 2, 3, 5].map(c => {
    const pool = results.filter(r => r.chain_category >= c).sort((a, b) => a.predicted_ms - b.predicted_ms);
    return pool.length ? { cat: c, best: pool[0] } : null;
  }).filter(Boolean);
}
function ladderHTML(rows, minCat, target, big) {
  if (!rows.length) return '<p class="empty">No chains were scored.</p>';
  const max = Math.max(target, ...rows.map(r => r.best.predicted_ms)) * 1.08;
  return `<div class="ladder${big ? ' big' : ''}">` + rows.map((r, i) => {
    const prev = rows[i - 1];
    const delta = prev ? r.best.predicted_ms - prev.best.predicted_ms : null;
    const over = r.best.predicted_ms > target;
    return `<div class="lrow${r.cat === minCat ? ' is-min' : ''}${r.cat < minCat ? ' below' : ''}">
      <div class="lcat">Cat ${r.cat}+${r.cat === minCat ? '<span class="lmin">your minimum</span>' : ''}</div>
      <div class="lbar"><span class="lfill${over ? ' over' : ''}" data-w="${(r.best.predicted_ms / max * 100).toFixed(2)}"></span><span class="ltarget" data-l="${(target / max * 100).toFixed(2)}"></span></div>
      <div class="lval">${fmtMs(r.best.predicted_ms)}${delta !== null ? `<span class="ldelta">${delta >= 0.5 ? '+' + fmtMs(delta) : 'no extra cost'}</span>` : ''}</div>
      <div class="lchain">${esc(r.best.ee_alg)} / ${esc(r.best.ca_alg)}</div>
    </div>`;
  }).join('') + '</div>';
}

function loadHTML(list, target, big) {
  const ok = list.filter(s => s.data);
  if (!ok.length) return '<p class="empty">The load scenarios could not be scored.</p>';
  const max = Math.max(target, ...ok.map(s => (s.data.recommended ? s.data.recommended.predicted_ms : 0))) * 1.08;
  return `<div class="load${big ? ' big' : ''}">` + list.map(s => {
    if (s.error) return `<div class="lrow"><div class="lcat">${esc(s.label)}</div><div class="empty err">${esc(s.error)}</div></div>`;
    const rec = s.data.recommended;
    if (!rec) return `<div class="lrow"><div class="lcat">${esc(s.label)}<span class="lnote">${esc(s.note)}</span></div><div class="empty">No chain meets the policy.</div></div>`;
    const over = rec.predicted_ms > target;
    const passing = s.data.results.filter(r => r.eligible && r.predicted_ms <= target).length;
    const eligible = s.data.results.filter(r => r.eligible).length;
    return `<div class="lrow">
      <div class="lcat">${esc(s.label)}<span class="lnote">${esc(s.note)}</span></div>
      <div class="lbar"><span class="lfill${over ? ' over' : ''}" data-w="${(rec.predicted_ms / max * 100).toFixed(2)}"></span><span class="ltarget" data-l="${(target / max * 100).toFixed(2)}"></span></div>
      <div class="lval">${fmtMs(rec.predicted_ms)}<span class="tag ${over ? 'warn' : 'pass'}">${over ? 'WARNING' : 'PASS'}</span></div>
      <div class="lchain">${esc(rec.ee_alg)} / ${esc(rec.ca_alg)}, ${passing} of ${eligible} chains pass</div>
    </div>`;
  }).join('') + '</div>';
}

// ================================================================== report
const SOURCE_CLASS = { Measured: 'src-measured', Approximated: 'src-approx', 'Browser estimate': 'src-hint', Assumed: 'src-assumed' };

function renderReport() {
  const run = lastRun, m = measurement, target = run.target_ms, minCat = run.min_category;
  const results = run.results, best = run.recommended;
  const eligible = results.filter(r => r.eligible);
  const passing = eligible.filter(r => r.predicted_ms <= target);
  const slowest = eligible.reduce((a, r) => (!a || r.predicted_ms > a.predicted_ms ? r : a), null);

  $('reportMeta').textContent = `Tested ${m.at.toLocaleString()} from this device against ${run.host.hostname} (${run.host.arch}).`;
  $('reportTags').innerHTML = [`Category ${minCat}+`, `${fmtMs(target)} target`, `${run.inputs.allowed_algs.length} algorithms allowed`]
    .map(t => `<span class="rtag">${esc(t)}</span>`).join('') + (run.mock ? '<span class="rtag warn">Mock predictions</span>' : '');
  const notices = [];
  if (run.mock) notices.push('Predictions come from a placeholder formula, not the trained model. Do not quote these numbers.');
  if (m.typical) notices.push('This network could not be measured, so typical values were used for every input.');
  $('reportNotice').hidden = !notices.length;
  $('reportNotice').textContent = notices.join(' ');

  // --- the answer
  let verdict, kpis = '';
  if (best) {
    const ok = best.predicted_ms <= target, gap = Math.abs(target - best.predicted_ms);
    verdict = `<strong>${esc(best.ee_alg)}</strong> signed by an <strong>${esc(best.ca_alg)}</strong> CA is the fastest chain your policy allows. On this network a login should take about <strong>${fmtMs(best.predicted_ms)}</strong>, `
      + (ok ? `${fmtMs(gap)} inside your ${fmtMs(target)} target.` : `${fmtMs(gap)} over your ${fmtMs(target)} target. No allowed chain meets the target here.`);
    const kpi = (label, val, sub, cls = '') => `<div class="kpi ${cls}"><span class="kpi-label">${label}</span><span class="kpi-val">${val}</span><span class="kpi-sub">${sub}</span></div>`;
    kpis = `<div class="kpis">
      ${kpi('Predicted login', fmtMs(best.predicted_ms), `Category ${best.chain_category} chain`, ok ? 'pass' : 'warn')}
      ${kpi(ok ? 'Headroom' : 'Over target by', fmtMs(gap), `against ${fmtMs(target)}`, ok ? '' : 'warn')}
      ${kpi('Chains that pass', `${passing.length}<small> of ${eligible.length}</small>`, `allowed at Category ${minCat}+`)}
      ${kpi('Slowest allowed', fmtMs(slowest.predicted_ms), `${esc(slowest.ee_alg)} / ${esc(slowest.ca_alg)}`)}
    </div>`;
    const max = Math.max(target, slowest.predicted_ms) * 1.05;
    kpis += `<div class="meter" aria-hidden="true">
      <div class="meter-track"><span class="meter-range" data-l="${(best.predicted_ms / max * 100).toFixed(2)}" data-w="${((slowest.predicted_ms - best.predicted_ms) / max * 100).toFixed(2)}"></span>
        <span class="meter-best${ok ? '' : ' over'}" data-l="${(best.predicted_ms / max * 100).toFixed(2)}"></span>
        <span class="meter-target" data-l="${(target / max * 100).toFixed(2)}"></span></div>
      <div class="meter-labels"><span>0</span><span>Fastest to slowest allowed chain, with your target marked</span><span>${fmtMs(max)}</span></div>
    </div>`;
  } else {
    verdict = `None of the allowed algorithms can build a chain at <strong>Category ${minCat}</strong> or above, so there is nothing to recommend.`;
    kpis = `<div class="empty-state"><p>Allow more algorithms or lower the minimum category, then test again.</p><button type="button" class="btn btn-primary" id="emptyEdit">Edit policy</button></div>`;
  }
  $('secVerdict').innerHTML = `<h2 class="rsec-title">The answer</h2><p class="verdict">${verdict}</p>${kpis}`;
  const ee = $('emptyEdit');
  if (ee) ee.addEventListener('click', () => { $('test').scrollIntoView({ behavior: reduceMotion() ? 'auto' : 'smooth' }); togglePolicy(true); });

  // --- your network path
  let netHtml;
  if (m.typical) {
    netHtml = '<p class="empty">Not measured. Every model input below is a typical value.</p>';
  } else {
    const sd = m.pings.length > 1 ? Math.sqrt(mean(m.pings.map(v => (v - mean(m.pings)) ** 2))) : null;
    const card = (label, val, sub, why) => `<div class="ncard"><span class="kpi-label">${label}</span><span class="kpi-val">${val}</span><span class="kpi-sub">${sub}</span>${why ? `<span class="ncard-why">${why}</span>` : ''}</div>`;
    const cards = [
      card('Round trip to server', m.pings.length ? fmtMs(median(m.pings)) : 'n/a',
        m.pings.length ? `median of ${m.pings.length}, range ${fmtMs(Math.min(...m.pings))} to ${fmtMs(Math.max(...m.pings))}` : 'server did not respond',
        'Every extra round trip a handshake needs costs this much.'),
      card('Bandwidth to you', m.download ? fmtMbps(m.download.mbps) : 'n/a',
        m.download ? `${(m.download.bytes / 1048576).toFixed(1)} MB in ${m.download.sec.toFixed(2)} s` : 'test did not complete',
        'Post-quantum certificates are 10 to 100 times bigger. This sets how long the extra bytes take.'),
      card('Jitter', sd !== null ? fmtMs(sd) : 'n/a', 'standard deviation of the round trips', 'High jitter means login times will vary more.'),
      card('Lost probes', `${m.failures}<small> of ${m.attempts}</small>`, 'requests that failed or timed out', 'Loss forces retransmits, which hurts big handshakes most.'),
      card('Classical login today', m.handshake ? fmtMs(m.handshake.tcp + m.handshake.tls) : 'n/a',
        m.handshake ? `TCP ${fmtMs(m.handshake.tcp)} + TLS ${fmtMs(m.handshake.tls)}, measured` : 'not exposed by this browser', 'Your baseline before switching.'),
    ];
    if (m.hint) cards.push(card('Browser estimate', [m.hint.type, m.hint.rtt ? m.hint.rtt + ' ms' : '', m.hint.downlink ? m.hint.downlink + ' Mbps' : ''].filter(Boolean).join(', '), 'reported by the browser, rounded', 'Used only when a measurement fails.'));
    netHtml = `<div class="ncards">${cards.join('')}</div><div class="chart-card"><div class="chart-title">Round trip of each probe</div>${sparkSVG(m.pings)}</div>`;
  }
  const inputs = `<div class="inputs"><div class="chart-title">What the model received</div>
    <div class="table-wrap"><table class="table"><thead><tr><th>Input</th><th class="num">Value</th><th>Source</th><th>How</th></tr></thead><tbody>
    ${inputsUsed.rows.map(r => `<tr><td>${esc(r.label)}</td><td class="num">${r.value < 1 ? r.value.toFixed(3) : r.value.toFixed(1)}</td><td><span class="src ${SOURCE_CLASS[r.source]}">${esc(r.source)}</span></td><td class="muted-cell">${esc(r.note)}</td></tr>`).join('')}
    </tbody></table></div></div>`;
  $('secNetwork').innerHTML = `<h2 class="rsec-title">Your network path</h2>
    <p class="rsec-lede">Measured between this device and the PQConnect server. This is not your Wi-Fi link speed on its own: it covers the whole path a login travels, which is what decides how long a handshake takes. The two numbers that matter most for post-quantum are the round trip and the bandwidth.</p>${netHtml}${inputs}`;

  // --- where the extra time comes from
  $('secWhy').innerHTML = renderWhy(results, best, eligible);

  // --- every chain
  const groups = ['ml', 'mixed', 'slh'].filter(g => results.some(r => groupOf(r) === g));
  const gcards = groups.map(g => {
    const rows = results.filter(r => groupOf(r) === g && r.eligible).sort((a, b) => a.predicted_ms - b.predicted_ms);
    if (!rows.length) return `<div class="gcard"><span class="kpi-label">${GROUP_NAMES[g]}</span><span class="kpi-sub">None at Category ${minCat}+</span></div>`;
    return `<div class="gcard"><span class="kpi-label">${GROUP_NAMES[g]}</span><span class="kpi-val">${fmtMs(rows[0].predicted_ms)}</span>
      <span class="kpi-sub">fastest: ${esc(rows[0].ee_alg)} / ${esc(rows[0].ca_alg)}</span><span class="kpi-sub">median ${fmtMs(median(rows.map(r => r.predicted_ms)))} across ${rows.length} chains</span></div>`;
  }).join('');
  $('secChains').innerHTML = `<h2 class="rsec-title">Every allowed chain</h2>
    <p class="rsec-lede">Each dot is one end-entity and CA pairing. Further left is a faster login. Hover a dot for its name.</p>
    <div class="chart-card"><div class="chart-scroll">${stripSVG(results, target, best)}</div>${stripLegend()}</div>
    <div class="gcards">${gcards}</div>`;

  // --- cost of security
  const lad = ladderRows(results);
  let ladLede = 'The fastest chain available at each security level, from the chains you allow.';
  const at3 = lad.find(r => r.cat === 3), at5 = lad.find(r => r.cat === 5);
  if (at3 && at5) {
    const d = at5.best.predicted_ms - at3.best.predicted_ms;
    ladLede += d >= 0.5 ? ` Going from Category 3 to 5 adds about ${fmtMs(d)} per login on this network.` : ' Going from Category 3 to 5 costs no extra time on this network.';
  }
  $('secLadder').innerHTML = `<h2 class="rsec-title">What extra security costs</h2><p class="rsec-lede">${ladLede}</p><div class="chart-card">${ladderHTML(lad, minCat, target)}</div>`;

  // --- under load
  let loadLede = 'Hypothetical: the same policy re-scored with this network made slower. These are model predictions, not measurements.';
  const recs = scenarios.filter(s => s.data && s.data.recommended).map(s => keyOf(s.data.recommended));
  if (recs.length === scenarios.length && recs.length > 1) {
    loadLede += new Set(recs).size === 1 ? ' The recommended chain stays the same in every case.' : ' The recommended chain changes as the network slows down.';
  }
  $('secLoad').innerHTML = `<h2 class="rsec-title">If the network gets busier</h2><p class="rsec-lede">${loadLede}</p><div class="chart-card">${loadHTML(scenarios, target)}</div>`;

  // --- all chains + method
  $('allChainsCount').textContent = `${results.length} scored, ${eligible.length} at Category ${minCat}+`;
  renderResults();
  renderTerms();
  renderMethod();
  ['secVerdict', 'secLadder', 'secLoad', 'secWhy'].forEach(id => applyWidths($(id)));
}

// Rows for the "why" table: classical baseline, the pick, and the fastest/slowest alternatives.
function whyRows(results, best, eligible) {
  const pick = [];
  const add = (r, why) => { if (r && !pick.some(p => keyOf(p.r) === keyOf(r))) pick.push({ r, why }); };
  add(best, 'Recommended');
  const byBytes = [...eligible].sort((a, b) => authBytes(ALG[a.ee_alg], ALG[a.ca_alg]) - authBytes(ALG[b.ee_alg], ALG[b.ca_alg]));
  add(byBytes[0], 'Smallest allowed');
  add(eligible.filter(r => groupOf(r) === 'slh').sort((a, b) => a.predicted_ms - b.predicted_ms)[0], 'Fastest SLH-DSA');
  add(byBytes[byBytes.length - 1], 'Largest allowed');
  return pick.map(p => ({ ...p, oh: overheadFor(p.r.ee_alg, p.r.ca_alg, net) }));
}

function renderWhy(results, best, eligible) {
  if (!eligible.length) return '<h2 class="rsec-title">Where the extra time comes from</h2><p class="empty">No chain meets your policy, so there is nothing to compare.</p>';
  const rows = whyRows(results, best, eligible);
  const fmtTrip = n => (n > 0 ? `+${n}` : '0');
  const tr = (label, name, bytes, flights, extraTrips, tripMs, transferMs, addedMs, cls = '') => `<tr class="${cls}"><td>${label}</td><td class="alg-name">${name}</td>
    <td class="num">${fmtKB(bytes)}</td><td class="num">${flights}</td><td class="num">${extraTrips}</td>
    <td class="num">${tripMs == null ? 'n/a' : fmtMs(tripMs)}</td><td class="num">${transferMs == null ? 'n/a' : fmtMs(transferMs)}</td>
    <td class="num"><strong>${cls === 'base-row' ? 'baseline' : addedMs == null ? 'n/a' : '+' + fmtMs(addedMs)}</strong></td></tr>`;
  const table = `<div class="table-wrap"><table class="table"><thead><tr><th></th><th>Chain (end-entity / CA)</th><th class="num">Auth bytes</th><th class="num">TCP flights</th><th class="num">Extra trips</th><th class="num">Trip cost</th><th class="num">Extra transfer</th><th class="num">Added vs classical</th></tr></thead><tbody>
    ${tr('Classical baseline', `${CLASSICAL.name} / ${CLASSICAL.name}`, CLASSICAL_BYTES, CLASSICAL_FLIGHTS, '0', 0, 0, 0, 'base-row')}
    ${rows.map(p => tr(p.why, `${esc(p.r.ee_alg)} / ${esc(p.r.ca_alg)}`, p.oh.bytes, p.oh.flights, fmtTrip(p.oh.extraTrips), p.oh.tripMs, p.oh.transferMs, p.oh.addedMs, best && keyOf(p.r) === keyOf(best) ? 'rec-row' : '')).join('')}
    </tbody></table></div>`;

  // size chart: every allowed chain's auth bytes against the TCP initial window
  const sized = rows.map(p => ({ label: `${p.r.ee_alg} / ${p.r.ca_alg}`, bytes: p.oh.bytes, flights: p.oh.flights }));
  const all = [{ label: `${CLASSICAL.name} (classical)`, bytes: CLASSICAL_BYTES, flights: CLASSICAL_FLIGHTS, base: true }, ...sized];
  const maxB = Math.max(INITCWND_BYTES * 1.2, ...all.map(x => x.bytes)) * 1.05;
  const lpos = b => (100 * Math.log(b / 500) / Math.log(maxB / 500)).toFixed(2);
  const chart = `<div class="sizes">${all.map(x => `<div class="srow${x.base ? ' base' : ''}"><div class="sname">${esc(x.label)}</div>
      <div class="sbar"><span class="sfill${x.bytes > INITCWND_BYTES ? ' over' : ''}" data-w="${lpos(x.bytes)}"></span><span class="swin" data-l="${lpos(INITCWND_BYTES)}"></span></div>
      <div class="sval">${fmtKB(x.bytes)}<span>${x.flights} flight${x.flights > 1 ? 's' : ''}</span></div></div>`).join('')}
    <div class="sizes-foot">Line marks the TCP initial window (${fmtKB(INITCWND_BYTES)}). Anything past it waits at least one extra round trip. Log scale.</div></div>`;

  const b = rows[0], oh = b.oh;
  let lede = `A post-quantum login is slower for two network reasons: the certificates and signatures are much bigger, and once the server's reply passes about ${fmtKB(INITCWND_BYTES)} TCP has to wait an extra round trip before sending the rest.`;
  if (best && oh) {
    lede += ` Your recommended chain sends about ${fmtKB(oh.bytes)} against ${fmtKB(CLASSICAL_BYTES)} for a classical ECDSA chain`
      + (oh.extraTrips > 0 ? `, which costs ${oh.extraTrips} extra round trip${oh.extraTrips > 1 ? 's' : ''}` : ', and still fits in the first TCP flight')
      + (oh.addedMs != null ? `. On this network that adds roughly ${fmtMs(oh.addedMs)} per login.` : '.');
  }
  return `<h2 class="rsec-title">Where the extra time comes from</h2><p class="rsec-lede">${lede}</p>
    <div class="chart-card">${chart}</div>
    <div class="inputs why-table">${table}
      <p class="table-note">Estimate from first principles, separate from the model: extra trips × round trip + extra bytes ÷ bandwidth. Signature checking time on the CPU is not included. Sizes assume the server sends its end-entity and CA certificates with about ${CERT_OVERHEAD} bytes of X.509 fields each.</p></div>`;
}

function renderTerms() {
  const terms = [
    ['Round trip (RTT)', 'Time for a small message to reach the server and come back. A TLS 1.3 handshake needs about two of them on a fresh connection, more if the server reply is large.'],
    ['Bandwidth', 'How fast data reaches this device from the server, measured with a timed download. It turns extra certificate bytes into extra time.'],
    ['Classical login', 'Today\'s handshake with ECDSA or RSA certificates. Measured from this page\'s own connection when the browser exposes it.'],
    ['Certificate chain', 'The certificates a server sends to prove who it is: here an end-entity certificate and the CA certificate that signed it.'],
    ['End-entity (EE) and CA', 'The end-entity certificate belongs to the login server. The CA (certificate authority) certificate vouches for it. Each can use a different signature algorithm.'],
    ['ML-DSA and SLH-DSA', 'The two NIST post-quantum signature standards (FIPS 204 and 205). ML-DSA is lattice based with mid-size signatures. SLH-DSA is hash based with tiny keys but much larger signatures.'],
    ['NIST category', 'Security level from 1 to 5. Category 3 is roughly AES-192 strength. A chain counts at the lower category of its two algorithms.'],
    ['TCP initial window', 'How much a server may send before it must wait for the client to reply: usually 10 packets, about 14.6 KB. Bigger replies need extra round trips.'],
    ['Predicted login', 'The model\'s estimate of the full authentication delay for one chain on this network.'],
  ];
  $('secTerms').innerHTML = `<h2 class="rsec-title">What the terms mean</h2><dl class="terms">${terms.map(([t, d]) => `<div><dt>${t}</dt><dd>${d}</dd></div>`).join('')}</dl>`;
}

function renderMethod() {
  const mdl = meta.model || {}, met = mdl.metrics || {};
  const tiles = mdl.loaded || Object.keys(met).length ? `<div class="metrics">${[
    ['Model', esc(mdl.model || '-')], ['Rows trained on', mdl.trained_rows ? mdl.trained_rows.toLocaleString() : '-'],
    ['MAE', met.mae_ms != null ? met.mae_ms.toFixed(1) + ' ms' : '-'], ['R²', met.r2 != null ? met.r2.toFixed(3) : '-'],
    ['Within 100 ms', met.pct_within_100ms != null ? met.pct_within_100ms.toFixed(1) + '%' : '-'],
  ].map(([l, v]) => `<div class="metric"><span class="metric-label">${l}</span><span class="metric-val">${v}</span></div>`).join('')}</div>` : '';
  $('secMethod').innerHTML = `<h2 class="rsec-title">How this was worked out</h2>
    <div class="method">
      <p>Your browser timed a series of small requests and one download to the PQConnect server. Those numbers stand in for the network inputs the model was trained on, and the table above shows where each one came from.</p>
      <p>The model then predicted the login time for every pairing of end-entity and CA signature you allow. Your policy decided which chains count. The model only ranks them by speed, never by security.</p>
      <p>Limits worth knowing: request round trips are not the same as post-quantum login handshakes. Browsers cannot see Wi-Fi MAC retries, PHY frame drops or PHY transmit time, so those use typical values. The model was trained on one simulated 802.11n Wi-Fi network, so treat results as a guide until it is calibrated on your own login telemetry.</p>
    </div>${tiles}`;
}

// ================================================================== full table
function visibleRows() {
  const fam = $('famFilter').value;
  const rows = lastRun.results.filter(r => {
    const e = familyOf(r.ee_alg), c = familyOf(r.ca_alg);
    if (fam === 'same' && e !== c) return false;
    if (fam === 'ml' && (e !== 'ml' || c !== 'ml')) return false;
    if (fam === 'slh' && (e !== 'slh' || c !== 'slh')) return false;
    return $('showExcluded').checked || r.eligible;
  });
  rows.sort((a, b) => {
    const x = a[sortKey], y = b[sortKey];
    const d = typeof x === 'number' ? x - y : String(x).localeCompare(String(y));
    return sortAsc ? d : -d;
  });
  const n = $('topN').value === 'all' ? rows.length : parseInt($('topN').value, 10);
  return rows.slice(0, n);
}

function renderResults() {
  if (!lastRun) return;
  const target = lastRun.target_ms;
  const best = lastRun.recommended;
  const rows = visibleRows();
  const vals = rows.map(r => r.predicted_ms);
  const maxMs = Math.max(target, ...vals, 1);
  const minMs = Math.max(1, Math.min(target, ...vals) / 2);
  const span = Math.log(maxMs) - Math.log(minMs) || 1;
  const pos = ms => (100 * (Math.log(Math.max(ms, minMs)) - Math.log(minMs)) / span).toFixed(2);

  const cols = [
    ['rank', '#', false], ['ee_alg', 'End-entity', true], ['ca_alg', 'CA', true],
    ['chain_category', 'Cat', true], ['bytes', 'Auth bytes', true], ['flights', 'TCP flights', true], ['predicted_ms', 'Predicted login', true],
    ['status', 'Target', false], ['delta', prevRun ? 'vs previous test' : 'vs previous', false],
  ];
  const head = '<thead><tr>' + cols.map(([k, l, s]) =>
    `<th class="${[s ? 'sortable' : '', ['chain_category', 'delta', 'bytes', 'flights'].includes(k) ? 'num' : ''].join(' ').trim()}"${s ? ` data-sort="${k}"` : ''}>${esc(l)}${sortKey === k ? (sortAsc ? ' ▲' : ' ▼') : ''}</th>`).join('') + '</tr></thead>';
  const body = '<tbody>' + rows.map((r, i) => {
    const over = r.predicted_ms > target;
    const status = !r.eligible ? '<span class="tag off">Below min</span>'
      : over ? '<span class="tag warn">WARNING</span>' : '<span class="tag pass">PASS</span>';
    let delta = '';
    if (prevRun && prevRun.map[keyOf(r)] !== undefined) {
      const d = r.predicted_ms - prevRun.map[keyOf(r)];
      delta = `<span class="${d > 0 ? 'delta-up' : 'delta-down'}">${d >= 0 ? '+' : '-'}${fmtMs(Math.abs(d))}</span>`;
    }
    const cls = !r.eligible ? 'excluded' : (best && keyOf(r) === keyOf(best) ? 'rec-row' : '');
    return `<tr class="${cls}"><td class="rank">${i + 1}</td><td class="alg-name">${esc(r.ee_alg)}</td><td>${esc(r.ca_alg)}</td>
      <td class="num">${r.chain_category}</td><td class="num">${fmtKB(r.bytes)}</td><td class="num">${r.flights}</td>
      <td><div class="cell-bar"><span class="ibar-track"><span class="ibar${!r.eligible ? ' off' : over ? ' over' : ''}" data-w="${pos(r.predicted_ms)}"></span><span class="ibar-target" data-l="${pos(target)}"></span></span><span class="num">${fmtMs(r.predicted_ms)}</span></div></td>
      <td>${status}</td><td class="num">${delta}</td></tr>`;
  }).join('') + '</tbody>';
  const table = $('resultsTable');
  table.innerHTML = head + body;
  applyWidths(table);  // widths go through the CSSOM so the strict CSP (no inline styles) holds
  table.querySelectorAll('th[data-sort]').forEach(th => th.addEventListener('click', () => {
    const k = th.dataset.sort;
    if (sortKey === k) sortAsc = !sortAsc; else { sortKey = k; sortAsc = true; }
    renderResults();
  }));
}

// ================================================================== four slides
function renderSlides() {
  const run = lastRun, m = measurement, target = run.target_ms, best = run.recommended;
  const big = (val, label) => `<div class="sbig"><span class="sbig-val">${val}</span><span class="sbig-label">${label}</span></div>`;
  const lad = ladderRows(run.results);

  const per10k = net && net.mbps ? 10240 * 8 / (net.mbps * 1e6) * 1000 : null;
  const s1 = m.typical
    ? `<p class="slide-text">This network couldn't be measured, so these findings use typical values.</p>`
    : `<div class="sbigs">${big(net.rtt != null ? fmtMs(net.rtt) : 'n/a', 'each extra round trip')}${big(per10k != null ? fmtMs(per10k) : 'n/a', 'each extra 10 KB of certificate')}${big(m.handshake ? fmtMs(m.handshake.tcp + m.handshake.tls) : 'n/a', 'classical login today')}</div>
       <div class="slide-chart">${sparkSVG(m.pings, 760, 150)}</div>`;

  const eligible = run.results.filter(r => r.eligible);
  const passing = eligible.filter(r => r.predicted_ms <= target).length;
  const s2text = !eligible.length ? `No chain meets your security minimum of Category ${run.min_category}.`
    : passing === eligible.length ? `Every one of the ${eligible.length} chains that meet your security minimum logs in under ${fmtMs(target)}.`
    : passing === 0 ? `None of the ${eligible.length} chains that meet your security minimum log in under ${fmtMs(target)} on this network.`
    : `${passing} of ${eligible.length} chains that meet your security minimum log in under ${fmtMs(target)}. The rest sit to the right of the target line.`;

  let s3text = 'The fastest chain at each security level.';
  const at3 = lad.find(r => r.cat === 3), at5 = lad.find(r => r.cat === 5);
  if (at3 && at5) {
    const d = at5.best.predicted_ms - at3.best.predicted_ms;
    s3text = d >= 0.5 ? `Category 5 costs about ${fmtMs(d)} more per login than Category 3 here.` : 'Category 5 costs no extra time over Category 3 here.';
  }

  const s4head = best
    ? `<div class="pick"><span class="pick-label">Our pick</span><span class="pick-name">${esc(best.ee_alg)} <span class="pick-with">with a</span> ${esc(best.ca_alg)} CA</span>
        <span class="pick-val">${fmtMs(best.predicted_ms)} <span class="tag ${best.predicted_ms <= target ? 'pass' : 'warn'}">${best.predicted_ms <= target ? 'PASS' : 'WARNING'}</span></span></div>`
    : `<p class="slide-text">No allowed chain reaches Category ${run.min_category}, so there is no pick yet.</p>`;

  const slides = [
    { title: 'What your network charges for bigger certificates', body: s1, foot: 'Measured from this browser to the PQConnect server. Post-quantum chains add bytes and sometimes round trips; these are their prices here.' },
    { title: 'Every chain at a glance', body: `<div class="slide-chart chart-scroll">${stripSVG(run.results, target, best, 820, 70)}</div>${stripLegend()}`, foot: s2text },
    { title: 'What extra security costs', body: `<div class="slide-chart">${ladderHTML(lad, run.min_category, target, true)}</div>`, foot: s3text },
    { title: 'Our pick, and how it holds up', body: `${s4head}<div class="slide-chart">${loadHTML(scenarios, target, true)}</div>`, foot: 'Busier networks are hypothetical re-scores of your measured network.' },
  ];
  $('deckTrack').innerHTML = slides.map((s, i) => `
    <article class="slide" id="slide${i}" role="group" aria-roledescription="slide" aria-label="${i + 1} of ${slides.length}: ${esc(s.title)}">
      <div class="slide-step">${i + 1} of ${slides.length}</div>
      <h3 class="slide-title">${esc(s.title)}</h3>
      <div class="slide-body">${s.body}</div>
      <p class="slide-foot">${esc(s.foot)}</p>
    </article>`).join('');
  applyWidths($('deckTrack'));
  $('dots').innerHTML = slides.map((s, i) => `<button type="button" role="tab" class="dotbtn" data-slide="${i}" aria-label="Slide ${i + 1}: ${esc(s.title)}"></button>`).join('');
  $('dots').querySelectorAll('.dotbtn').forEach(b => b.addEventListener('click', () => goSlide(+b.dataset.slide)));
  goSlide(0);
}
function goSlide(i) {
  const n = $('deckTrack').children.length;
  if (!n) return;
  slide = Math.max(0, Math.min(n - 1, i));
  $('deckTrack').style.transform = `translateX(-${slide * 100}%)`;
  [...$('deckTrack').children].forEach((el, k) => { el.setAttribute('aria-hidden', k === slide ? 'false' : 'true'); el.inert = k !== slide; });
  $('dots').querySelectorAll('.dotbtn').forEach((b, k) => { b.setAttribute('aria-selected', k === slide ? 'true' : 'false'); b.classList.toggle('on', k === slide); });
  $('slideCount').textContent = `${slide + 1} / ${n}`;
  $('slidePrev').disabled = slide === 0;
  $('slideNext').disabled = slide === n - 1;
}

// ================================================================== scroll reveal (once per section)
let revealObserver = null;
function setupReveal() {
  const els = document.querySelectorAll('.reveal');
  if (revealObserver) revealObserver.disconnect();
  if (reduceMotion() || !('IntersectionObserver' in window)) { els.forEach(el => el.classList.add('in')); return; }
  els.forEach(el => el.classList.remove('in'));
  revealObserver = new IntersectionObserver(entries => entries.forEach(en => {
    if (en.isIntersecting) { en.target.classList.add('in'); revealObserver.unobserve(en.target); }
  }), { threshold: 0.12 });
  els.forEach(el => revealObserver.observe(el));
}

// ================================================================== files and exports
// <saveFile> tools/build_demo.py swaps this block for the hosted viewer's download capability.
async function saveFile(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
// </saveFile>
function download(name, text, type) { return saveFile(name, new Blob([text], { type })); }
const fileStamp = d => d.toISOString().slice(0, 16).replace(/[:T]/g, '-');
function exportCsv() {
  if (!lastRun) return;
  const head = ['ee_alg', 'ca_alg', 'ee_category', 'ca_category', 'chain_category', 'eligible', 'predicted_ms', 'meets_target'];
  const lines = [head.join(',')].concat(lastRun.results.map(r => head.map(h => r[h]).join(',')));
  download('pqconnect_results.csv', lines.join('\n') + '\n', 'text/csv');
}
function exportJson() {
  if (!lastRun) return;
  const report = {
    generated_at: lastRun.at.toISOString(), user: meta.user, mock: lastRun.mock, host: lastRun.host,
    policy: { min_category: lastRun.min_category, target_ms: lastRun.target_ms, allowed_algs: lastRun.inputs.allowed_algs },
    measurement: { pings_ms: measurement.pings, failures: measurement.failures, download: measurement.download, browser_hint: measurement.hint, tls_handshake: measurement.handshake, typical: measurement.typical },
    model_inputs: inputsUsed.rows,
    recommended: lastRun.recommended, results: lastRun.results,
    scenarios: scenarios.map(s => ({ label: s.label, note: s.note, recommended: s.data ? s.data.recommended : null, error: s.error || null })),
  };
  download('pqconnect_report.json', JSON.stringify(report, null, 2), 'application/json');
}

// ================================================================== PDF report (jsPDF, built in the browser)
const JSPDF_SRC = '/static/jspdf.umd.min.js';
function loadJsPDF() {
  if (window.jspdf) return Promise.resolve(window.jspdf.jsPDF);
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = JSPDF_SRC;
    s.onload = () => (window.jspdf ? resolve(window.jspdf.jsPDF) : reject(new Error('The PDF library did not load.')));
    s.onerror = () => reject(new Error('The PDF library did not load.'));
    document.head.append(s);
  });
}

async function downloadPdf() {
  if (!lastRun) return;
  const status = $('pdfStatus'), btns = document.querySelectorAll('[data-pdf]');
  btns.forEach(b => { b.disabled = true; });
  status.className = 'pdf-status'; status.textContent = 'Building the PDF...';
  try {
    const jsPDF = await loadJsPDF();
    const blob = buildPdf(jsPDF).output('blob');
    await saveFile(`pqconnect-report-${fileStamp(lastRun.at)}.pdf`, blob);
    status.textContent = '';
  } catch (e) {
    status.className = 'pdf-status err';
    status.textContent = e.message || 'Could not build the PDF.';
  } finally {
    btns.forEach(b => { b.disabled = false; });
  }
}

function buildPdf(jsPDF) {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const W = 210, H = 297, M = 16, CW = W - 2 * M;
  const INK = [21, 32, 51], MUTED = [93, 103, 121], LINE = [221, 226, 233], BRAND = [15, 133, 151], WARN = [199, 121, 15], PASS = [35, 149, 95];
  const run = lastRun, m = measurement, target = run.target_ms, best = run.recommended;
  const eligible = run.results.filter(r => r.eligible);
  const passing = eligible.filter(r => r.predicted_ms <= target);
  const asc = s => String(s).replace(/[\u2012-\u2015\u2212]/g, '-').replace(/\u00d7/g, 'x').replace(/\u00f7/g, '/').replace(/[^\x20-\x7e\xa0-\xff]/g, '');
  const LH = pt => pt * 0.42;
  let y = M;
  const ensure = h => { if (y + h > H - 18) { doc.addPage(); y = M; } };
  const font = (style, size, color) => { doc.setFont('helvetica', style); doc.setFontSize(size); doc.setTextColor(...color); };
  const h1 = t => { ensure(34); y += 3; font('bold', 12, INK); doc.text(asc(t), M, y + 4); y += 6.5; doc.setDrawColor(...LINE); doc.setLineWidth(0.3); doc.line(M, y, W - M, y); y += 3.5; };
  const para = (t, size = 9, color = MUTED) => {
    font('normal', size, color);
    const lines = doc.splitTextToSize(asc(t), CW);
    ensure(lines.length * LH(size) + 2);
    doc.text(lines, M, y + LH(size) * 0.8);
    y += lines.length * LH(size) + 2;
  };
  const kv = pairs => {
    for (const [k, v, color] of pairs) {
      font('normal', 9, color || INK);
      const lines = doc.splitTextToSize(asc(v), CW - 52);
      ensure(lines.length * LH(9) + 1.6);
      font('bold', 9, MUTED); doc.text(asc(k), M, y + 3.2);
      font('normal', 9, color || INK); doc.text(lines, M + 52, y + 3.2);
      y += lines.length * LH(9) + 1.6;
    }
    y += 1.5;
  };
  // widths in mm; num = indexes of right-aligned columns; hl = row index to highlight
  const table = (head, rows, widths, { num = [], hl = -1, size = 8 } = {}) => {
    const pad = 1.6, lh = LH(size);
    const drawHead = () => {
      font('bold', size, MUTED);
      const hc = head.map((t, i) => doc.splitTextToSize(asc(t), widths[i] - 2 * pad));
      const hh = Math.max(...hc.map(c => c.length)) * lh + 2 * pad;
      doc.setFillColor(244, 246, 249); doc.rect(M, y, CW, hh, 'F');
      let x = M;
      hc.forEach((c, i) => { const tx = num.includes(i) ? x + widths[i] - pad : x + pad; doc.text(c, tx, y + pad + lh * 0.8, { align: num.includes(i) ? 'right' : 'left' }); x += widths[i]; });
      y += hh;
    };
    ensure(lh * 3 + 8); drawHead();
    rows.forEach((row, ri) => {
      font('normal', size, INK);
      const cells = row.map((c, i) => doc.splitTextToSize(asc(c), widths[i] - 2 * pad));
      const h = Math.max(...cells.map(c => c.length)) * lh + 2 * pad;
      if (y + h > H - 18) { doc.addPage(); y = M; drawHead(); font('normal', size, INK); }
      if (ri === hl) { doc.setFillColor(227, 245, 248); doc.rect(M, y, CW, h, 'F'); font('bold', size, INK); }
      let x = M;
      cells.forEach((c, i) => { const tx = num.includes(i) ? x + widths[i] - pad : x + pad; doc.text(c, tx, y + pad + lh * 0.8, { align: num.includes(i) ? 'right' : 'left' }); x += widths[i]; });
      y += h;
      doc.setDrawColor(...LINE); doc.setLineWidth(0.2); doc.line(M, y, W - M, y);
    });
    y += 4;
  };
  const ms = v => (v == null ? 'n/a' : fmtMs(v));

  // ---- title
  font('bold', 18, INK); doc.text('Post-quantum authentication report', M, y + 6); y += 10;
  font('normal', 9, MUTED);
  doc.text(asc(`PQConnect | tested ${m.at.toLocaleString()} | server ${run.host.hostname} (${run.host.arch}) | user ${meta.user}`), M, y + 3); y += 7;
  if (run.mock || m.typical) {
    const msg = [run.mock ? 'MOCK PREDICTIONS: numbers come from a placeholder formula, not the trained model. Do not quote them.' : '', m.typical ? 'The network was not measured; typical values were used for every input.' : ''].filter(Boolean).join(' ');
    font('bold', 8.5, WARN);
    const lines = doc.splitTextToSize(msg, CW - 6);
    doc.setFillColor(251, 239, 220); doc.rect(M, y, CW, lines.length * LH(8.5) + 4, 'F');
    doc.text(lines, M + 3, y + 2 + LH(8.5) * 0.8); y += lines.length * LH(8.5) + 7;
  }

  // ---- 1 summary
  h1('1. Summary');
  const oh = best ? overheadFor(best.ee_alg, best.ca_alg, net) : null;
  const ok = best && best.predicted_ms <= target;
  kv([
    ['Recommended chain', best ? `${best.ee_alg} end-entity, ${best.ca_alg} CA (chain at NIST category ${best.chain_category})` : `None: no allowed chain reaches category ${run.min_category}`],
    ['Predicted login', best ? `${fmtMs(best.predicted_ms)} against a ${fmtMs(target)} target: ${ok ? 'PASS' : 'WARNING'} (${ok ? fmtMs(target - best.predicted_ms) + ' headroom' : fmtMs(best.predicted_ms - target) + ' over'})` : 'n/a', best ? (ok ? PASS : WARN) : null],
    ['Classical login today', m.handshake ? `${fmtMs(m.handshake.tcp + m.handshake.tls)} measured (TCP ${fmtMs(m.handshake.tcp)} + TLS ${fmtMs(m.handshake.tls)})` : (net.rtt != null ? `about ${fmtMs(2 * net.rtt)} estimated as 2 round trips (not exposed by the browser)` : 'not available')],
    ['Added vs classical (est.)', oh ? `${oh.addedMs != null ? '+' + fmtMs(oh.addedMs) : 'n/a'}: ${fmtKB(oh.bytes)} of authentication data vs ${fmtKB(CLASSICAL_BYTES)} for ECDSA P-256, ${oh.extraTrips > 0 ? '+' + oh.extraTrips + ' TCP round trip(s)' : 'no extra round trips'}` : 'n/a'],
    ['Chains', `${run.results.length} scored, ${eligible.length} meet category ${run.min_category}+, ${passing.length} of those meet the target`],
  ]);

  // ---- 2 policy
  h1('2. Policy');
  kv([
    ['Minimum NIST category', `${run.min_category} (a chain counts at the lower category of its two algorithms)`],
    ['Login delay target', fmtMs(target)],
    ['Allowed algorithms', `${run.inputs.allowed_algs.length}: ${run.inputs.allowed_algs.join(', ')}`],
  ]);

  // ---- 3 network path
  h1('3. Network path (this device to the PQConnect server)');
  para('Measured from the browser. These cover the whole path a login travels, not the Wi-Fi link alone. Round trip sets the cost of each extra handshake round trip; bandwidth sets the cost of extra certificate bytes.');
  if (m.typical) para('Not measured: typical values were used.', 9, WARN);
  else {
    const sd = m.pings.length > 1 ? Math.sqrt(mean(m.pings.map(v => (v - mean(m.pings)) ** 2))) : null;
    table(['Metric', 'Value', 'Method'], [
      ['Round trip (median)', m.pings.length ? fmtMs(median(m.pings)) : 'n/a', m.pings.length ? `${m.pings.length} timed GET /api/probe/ping after 1 warm-up (${m.timing === 'resource' ? 'Resource Timing: request sent to first byte' : 'JavaScript clock'}); min ${fmtMs(Math.min(...m.pings))}, max ${fmtMs(Math.max(...m.pings))}` : 'no successful probes'],
      ['Jitter', sd != null ? fmtMs(sd) : 'n/a', 'standard deviation of the round trips'],
      ['Lost probes', `${m.failures} of ${m.attempts}`, 'failed or timed out after 3 s'],
      ['Bandwidth', m.download ? fmtMbps(m.download.mbps) : 'n/a', m.download ? `${m.download.bytes.toLocaleString()} bytes in ${m.download.sec.toFixed(3)} s (${m.download.method === 'resource' ? 'Resource Timing: first to last byte' : 'JavaScript clock, includes one round trip'})` : 'download test did not complete'],
      ['Classical TLS handshake', m.handshake ? fmtMs(m.handshake.tcp + m.handshake.tls) : 'n/a', m.handshake ? 'Navigation Timing of this page: connectStart to connectEnd' : 'not exposed (connection reused or browser limit)'],
      ['Browser estimate', m.hint ? [m.hint.type, m.hint.rtt ? m.hint.rtt + ' ms' : '', m.hint.downlink ? m.hint.downlink + ' Mbps' : ''].filter(Boolean).join(', ') : 'n/a', 'navigator.connection, rounded; used only as a fallback'],
    ], [38, 34, CW - 72]);
  }
  y -= 1;
  para('Model inputs. The model was trained on lagged handshake telemetry; each input below records where its value came from.');
  table(['Input', 'Value', 'Source', 'How'], inputsUsed.rows.map(r => [r.label, r.value < 1 ? r.value.toFixed(3) : r.value.toFixed(1), r.source, r.note]), [52, 18, 26, CW - 96], { num: [1] });

  // ---- 4 why
  h1('4. Where the extra time comes from (first-principles estimate)');
  para(`Added time = extra TCP round trips x round trip + extra bytes / bandwidth. Auth bytes = EE cert (EE key + CA signature) + CA cert (CA key + CA signature) + CertificateVerify (EE signature) + ${CERT_OVERHEAD} B X.509 fields per cert + ${OTHER_HANDSHAKE} B other handshake messages. TCP flights assume an initial window of ${INITCWND} x ${MSS} B (${fmtKB(INITCWND_BYTES)}) doubling each round. CPU time to verify signatures is excluded. Independent of the ML model.`);
  if (eligible.length) {
    const wr = whyRows(run.results, best, eligible);
    table(['Row', 'Chain (EE / CA)', 'Auth bytes', 'Flights', 'Extra trips', 'Trip cost', 'Transfer', 'Added'],
      [['Classical baseline', 'ECDSA P-256 / ECDSA P-256', CLASSICAL_BYTES.toLocaleString(), String(CLASSICAL_FLIGHTS), '0', '-', '-', 'baseline'],
       ...wr.map(p => [p.why, `${p.r.ee_alg} / ${p.r.ca_alg}`, p.oh.bytes.toLocaleString(), String(p.oh.flights), String(p.oh.extraTrips), ms(p.oh.tripMs), ms(p.oh.transferMs), p.oh.addedMs == null ? 'n/a' : '+' + fmtMs(p.oh.addedMs)])],
      [27, 52, 19, 13, 15, 15, 15, CW - 156], { num: [2, 3, 4, 5, 6, 7], hl: 1 });
  }

  // ---- 5 chains
  h1(`5. Fastest chains at category ${run.min_category}+ (model predictions)`);
  const top = [...eligible].sort((a, b) => a.predicted_ms - b.predicted_ms).slice(0, 20);
  if (top.length) {
    table(['#', 'End-entity', 'CA', 'Cat', 'Auth KB', 'Flights', 'Predicted', 'Target'],
      top.map((r, i) => [String(i + 1), r.ee_alg, r.ca_alg, String(r.chain_category), (r.bytes / 1024).toFixed(1), String(r.flights), fmtMs(r.predicted_ms), r.predicted_ms <= target ? 'PASS' : 'WARNING']),
      [8, 42, 42, 10, 17, 14, 22, CW - 155], { num: [0, 3, 4, 5, 6], hl: 0 });
    para(`Showing ${top.length} of ${eligible.length} eligible chains. All ${run.results.length} are in the CSV export.`, 8);
  } else para('No chain meets the policy.', 9, WARN);

  // ---- 6 security levels
  h1('6. Cost of each security level');
  const lad = ladderRows(run.results);
  table(['Category', 'Fastest chain at or above it', 'Predicted', 'Step cost'],
    lad.map((r, i) => [`${r.cat}+${r.cat === run.min_category ? ' (policy)' : ''}`, `${r.best.ee_alg} / ${r.best.ca_alg}`, fmtMs(r.best.predicted_ms), i ? (r.best.predicted_ms - lad[i - 1].best.predicted_ms >= 0.5 ? '+' + fmtMs(r.best.predicted_ms - lad[i - 1].best.predicted_ms) : 'none') : '-']),
    [30, 82, 30, CW - 142], { num: [2, 3] });

  // ---- 7 load
  h1('7. If the network gets busier (hypothetical re-scores)');
  table(['Scenario', 'Change to measured inputs', 'Recommended', 'Predicted', 'Status', 'Passing'],
    scenarios.map(s => {
      if (s.error) return [s.label, s.note, 'error: ' + s.error, '', '', ''];
      const r = s.data.recommended, el = s.data.results.filter(x => x.eligible);
      return [s.label, s.note, r ? `${r.ee_alg} / ${r.ca_alg}` : 'none', r ? fmtMs(r.predicted_ms) : '-', r ? (r.predicted_ms <= target ? 'PASS' : 'WARNING') : '-', `${el.filter(x => x.predicted_ms <= target).length} of ${el.length}`];
    }), [26, 44, 46, 20, 20, CW - 156], { num: [3] });

  // ---- 8 method
  h1('8. Method and limits');
  para(`Model: ${run.mock ? 'placeholder formula (mock), not a trained model' : (meta.model.model || 'trained model') + (meta.model.trained_rows ? ', ' + meta.model.trained_rows.toLocaleString() + ' training rows' : '')}. It predicts authentication delay from the chain's algorithms and lagged network telemetry (${meta.telemetry_fields.map(f => f.key).join(', ')}). No input comes from the handshake being predicted.`);
  para('Limits: request round trips stand in for previous auth delay and are not the same quantity. Browsers cannot observe Wi-Fi MAC retries, PHY frame drops or PHY transmit time, so those use typical values. The training data comes from one simulated 802.11n 2.4 GHz network (ns-3 and OpenSSL), so predictions are a guide until the model is calibrated on your own login telemetry. Security eligibility comes from your policy only; the model ranks by speed, never by security.');
  if (m.pings.length) para('Raw round trips (ms): ' + m.pings.map(v => v.toFixed(1)).join(', '), 8);

  // ---- footer on every page
  const n = doc.getNumberOfPages();
  for (let i = 1; i <= n; i++) {
    doc.setPage(i);
    font('normal', 7.5, MUTED);
    doc.setDrawColor(...LINE); doc.setLineWidth(0.2); doc.line(M, H - 12, W - M, H - 12);
    doc.text(asc(`PQConnect post-quantum authentication report | ${m.at.toISOString().slice(0, 16).replace('T', ' ')} UTC${run.mock ? ' | MOCK PREDICTIONS' : ''}`), M, H - 8);
    doc.text(`Page ${i} of ${n}`, W - M, H - 8, { align: 'right' });
  }
  return doc;
}

// ================================================================== wiring
document.addEventListener('DOMContentLoaded', async () => {
  $('loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    $('loginError').textContent = '';
    $('loginBtn').disabled = true;
    try {
      const r = await api('/api/login', { method: 'POST', json: { username: $('username').value, password: $('password').value } });
      csrf = r.csrf;
      $('password').value = '';
      await enterApp();
    } catch (err) {
      $('loginError').textContent = err.message;
      refreshSession().catch(() => {});
    } finally {
      $('loginBtn').disabled = false;
    }
  });
  $('logoutBtn').addEventListener('click', async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch (_) { /* ignore */ }
    lastRun = prevRun = measurement = inputsUsed = scenarios = null;
    ['report', 'slides', 'foot', 'navLinks'].forEach(id => { $(id).hidden = true; });
    resetHero();
    showLogin('Signed out.');
  });

  // test
  $('runBtn').addEventListener('click', () => runTest());
  $('againBtn').addEventListener('click', () => { window.scrollTo({ top: 0, behavior: reduceMotion() ? 'auto' : 'smooth' }); runTest(); });
  $('retryBtn').addEventListener('click', () => runTest());
  $('typicalBtn').addEventListener('click', () => runTest({ typical: true }));

  // policy
  $('policyToggle').addEventListener('click', () => togglePolicy());
  $('policyDone').addEventListener('click', () => togglePolicy(false));
  document.querySelectorAll('#catSeg button').forEach(b => b.addEventListener('click', () => setCategory(b.dataset.cat)));
  $('targetRange').addEventListener('input', e => { $('targetMs').value = e.target.value; updatePolicySummary(); });
  $('targetMs').addEventListener('input', e => { const v = parseFloat(e.target.value); if (Number.isFinite(v)) $('targetRange').value = Math.min(2000, Math.max(50, v)); updatePolicySummary(); });
  $('algAll').addEventListener('click', () => setAlgs(() => true));
  $('algMl').addEventListener('click', () => setAlgs(n => n.startsWith('ML-DSA')));
  $('algNone').addEventListener('click', () => setAlgs(() => false));

  // report table
  ['famFilter', 'topN', 'showExcluded'].forEach(id => $(id).addEventListener('change', renderResults));
  document.querySelectorAll('[data-pdf]').forEach(b => b.addEventListener('click', downloadPdf));
  if ($('exportCsv')) $('exportCsv').addEventListener('click', exportCsv);
  if ($('exportJson')) $('exportJson').addEventListener('click', exportJson);

  // slides: arrows, keys, swipe
  $('slidePrev').addEventListener('click', () => goSlide(slide - 1));
  $('slideNext').addEventListener('click', () => goSlide(slide + 1));
  $('deck').addEventListener('keydown', e => {
    if (e.key === 'ArrowRight') { e.preventDefault(); goSlide(slide + 1); }
    if (e.key === 'ArrowLeft') { e.preventDefault(); goSlide(slide - 1); }
  });
  let sx = null;
  $('deck').addEventListener('pointerdown', e => { sx = e.clientX; });
  $('deck').addEventListener('pointerup', e => {
    if (sx === null) return;
    const dx = e.clientX - sx; sx = null;
    if (Math.abs(dx) > 50) goSlide(slide + (dx < 0 ? 1 : -1));
  });

  try {
    const s = await refreshSession();
    if (s.authenticated) await enterApp(); else showLogin();
  } catch (e) {
    showLogin(e.message);
  }
});
