/* PQConnect dashboard: recorded-history ML and independent network estimates. */
'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const state = { csrf: '', meta: null, result: null, selected: null, network: null, dirty: false, sequence: 0, probeSequence: 0, controller: null, probeController: null, authenticated: false };
  const number = (value, digits = 1) => Number.isFinite(Number(value)) && value !== null && value !== '' ? Number(value).toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits }) : '—';
  const ms = (value) => `${number(value)} ms`;
  const el = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };
  const setText = (id, text) => { $(id).textContent = text; };
  const setError = (message) => { setText('appError', message || ''); $('appError').hidden = !message; };
  const displayName = (row) => `${row.ee_alg || row.end_entity_algorithm} · ${row.ca_alg || row.ca_algorithm}`;
  const metric = (id, value, unit = '') => { const node = $(id); node.replaceChildren(document.createTextNode(value)); if (unit) node.append(el('span', 'unit', unit)); };
  function signedOut(message = '') {
    state.authenticated = false;
    state.sequence += 1; state.probeSequence += 1;
    state.controller?.abort(); state.probeController?.abort();
    state.meta = null; state.result = null; state.network = null; state.selected = null;
    $('bootView').hidden = true; $('appView').hidden = true; $('loginView').hidden = false;
    setText('loginError', message);
    $('loginButton').disabled = false;
    $('password').value = '';
  }
  async function api(path, { body, signal, method } = {}) {
    const response = await fetch(path, { method: method || (body === undefined ? 'GET' : 'POST'), credentials: 'same-origin', cache: 'no-store', signal, headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401 && path !== '/api/login') signedOut('Your session ended. Sign in again to continue.');
      throw new Error(data.error || data.message || `Request failed (${response.status}).`);
    }
    return data;
  }
  function fillConfigurations(preferred) {
    const previous = preferred || $('configuration').value;
    const configurations = (state.meta?.configurations || []).filter((row) => Number(row.category) >= Number($('minCategory').value));
    $('configuration').replaceChildren(...configurations.map((row) => { const option = el('option', '', displayName(row)); option.value = row.configuration_id; return option; }));
    if (configurations.some((row) => row.configuration_id === previous)) $('configuration').value = previous;
    $('analyzeButton').disabled = configurations.length === 0;
  }
  function addQuality(label, value) { const block = el('div'); block.append(el('dt', '', label), el('dd', '', value)); $('modelMetrics').append(block); }
  function renderMeta(meta) {
    state.meta = meta;
    setText('userName', typeof meta.user === 'string' ? meta.user : (meta.user?.username || 'Researcher'));
    setText('modeBadge', meta.demo ? 'Demo · dataset replay' : 'Dataset replay');
    $('logoutButton').hidden = !!meta.demo;
    setText('modelStatus', meta.model?.loaded ? 'Trained model ready' : 'Model unavailable');
    setText('runtimeLabel', meta.host?.arch ? `Runtime: ${meta.host.arch}` : 'Python inference service');
    if (meta.profiles?.length) {
      $('profile').replaceChildren(...meta.profiles.map((row) => { const option = el('option', '', row.label); option.value = row.id; return option; }));
      $('profile').value = meta.profiles.some((p) => p.id === 'middle') ? 'middle' : meta.profiles[0].id;
    }
    fillConfigurations(meta.default_configuration);
    if (typeof meta.scope === 'string') setText('modelScope', meta.scope);
    const quality = meta.model?.metrics || {};
    $('modelMetrics').replaceChildren();
    addQuality('Mean absolute error', ms(quality.mae_ms));
    addQuality('RMSE', ms(quality.rmse_ms));
    addQuality('R²', number(quality.r2, 3));
    addQuality('Within 100 ms', `${number(quality.within_100ms_percent)}%`);
    addQuality('Previous-delay baseline MAE', ms(meta.model?.baseline_metrics?.mae_ms));
    const limitations = meta.model?.limitations;
    setText('modelLimitations', Array.isArray(limitations) ? limitations.join(' ') : (limitations || 'Simulation performance may not generalize to other hardware or real networks.'));
    const baseline = meta.baseline;
    setText('baselineNote', baseline ? `Transfer reference: ${baseline.label}, ${number(baseline.certificate_message_bytes, 0)} certificate-message bytes. This size reference does not provide a measured classical authentication latency.` : 'No classical authentication-delay measurements are used by this model.');
  }
  async function loadApp() {
    const meta = await api('/api/meta');
    state.authenticated = true;
    renderMeta(meta);
    $('bootView').hidden = true; $('loginView').hidden = true; $('appView').hidden = false;
    $('probeButton').disabled = false;
    $('probeButton').textContent = '↗ Run network test';
    setText('networkRtt', 'Not measured'); setText('networkRate', 'Not measured');
    setText('probeStatus', 'Uses five requests and a 1 MiB download from this server.');
    $('resetProbe').hidden = true;
    await analyze();
  }
  async function boot() {
    $('retryBoot').hidden = true;
    setText('bootMessage', 'Connecting to PQConnect…');
    try {
      const session = await api('/api/session');
      state.csrf = session.csrf;
      if (session.authenticated) await loadApp(); else signedOut();
    } catch (error) {
      if (!$('loginView').hidden) setText('loginError', error.message);
      else { setText('bootMessage', error.message); $('retryBoot').hidden = false; }
    }
  }
  function markDirty() {
    state.dirty = true;
    setText('analysisStatus', 'Settings changed. Analyze to update results.');
    $('analysisStatus').classList.add('dirty');
  }
  async function analyze() {
    if (!state.authenticated || !$('analysisForm').reportValidity()) return;
    const sequence = ++state.sequence;
    state.controller?.abort();
    const controller = new AbortController(); state.controller = controller;
    const timeout = setTimeout(() => controller.abort(), 60000);
    const request = { min_category: Number($('minCategory').value), target_ms: Number($('targetMs').value), profile: $('profile').value, configuration_id: $('configuration').value, network: state.network ? { rtt_ms: state.network.rtt_ms, download_mbps: state.network.download_mbps } : null };
    setError('');
    $('analyzeButton').disabled = true; $('analysisForm').setAttribute('aria-busy', 'true');
    for (const control of $('analysisForm').querySelectorAll('input, select')) control.disabled = true;
    setText('analysisStatus', 'Predicting recorded authentication exchanges…');
    $('analysisStatus').classList.remove('dirty');
    try {
      const result = await api('/api/analyze', { body: request, signal: controller.signal });
      if (sequence !== state.sequence || !state.authenticated) return;
      if (!Array.isArray(result.results) || !result.results.length) throw new Error('No recorded configurations match this security policy.');
      state.result = result;
      state.selected = (typeof result.selected === 'string' ? result.selected : result.selected?.configuration_id) || request.configuration_id || result.results[0].configuration_id;
      if (!result.results.some((row) => row.configuration_id === state.selected)) state.selected = result.results[0].configuration_id;
      state.dirty = String(request.min_category) !== $('minCategory').value || String(request.target_ms) !== $('targetMs').value || request.profile !== $('profile').value;
      renderResults();
      if (state.dirty) markDirty();
      else setText('analysisStatus', 'Analysis complete · recorded telemetry.');
      setText('updatedAt', `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`);
    } catch (error) {
      if (sequence !== state.sequence || !state.authenticated) return;
      setError(error.name === 'AbortError' ? 'The analysis timed out. Please try again.' : error.message);
      setText('analysisStatus', state.result ? 'Update failed. Previous results remain visible.' : 'Analysis unavailable. Please try again.');
    } finally {
      clearTimeout(timeout);
      if (sequence === state.sequence) {
        $('analyzeButton').disabled = false; $('analysisForm').removeAttribute('aria-busy');
        for (const control of $('analysisForm').querySelectorAll('input, select')) control.disabled = false;
      }
    }
  }
  function chooseConfiguration(id) {
    if (!state.result?.results.some((row) => row.configuration_id === id)) return;
    state.selected = id;
    if ([...$('configuration').options].some((option) => option.value === id)) $('configuration').value = id;
    renderResults();
  }
  function renderResults() {
    const result = state.result;
    if (!result) return;
    const selected = result.results.find((row) => row.configuration_id === state.selected) || result.results[0];
    metric('predictionMetric', number(selected.predicted_ms), 'ms');
    setText('predictionCaption', displayName(selected));
    metric('budgetMetric', number(result.target_ms, 0), 'ms');
    const difference = Math.abs(Number(result.target_ms) - Number(selected.predicted_ms));
    setText('budgetCaption', `${ms(difference)} ${selected.meets_target ? 'under' : 'over'} budget · selected configuration`);
    const hasNetwork = selected.network_extra_transfer_ms !== null && selected.network_extra_transfer_ms !== undefined;
    metric('transferMetric', hasNetwork ? number(selected.network_extra_transfer_ms, 2) : '—', hasNetwork ? 'ms' : '');
    setText('transferCaption', hasNetwork ? `Additional certificate bytes · ${number(result.network?.download_mbps || state.network?.download_mbps)} Mbps` : 'Run a network test to estimate');
    metric('eligibleMetric', String(result.results.length));
    const within = result.results.filter((row) => row.meets_target).length;
    setText('eligibleCaption', `${within} within budget · minimum category ${result.min_category}`);
    setText('tableSummary', `${result.results.length} configurations · ${within} within ${ms(result.target_ms)} · ${result.profile} recorded window`);
    setText('comparisonNote', result.comparison_note || 'Each configuration uses its own recorded history; this is not a controlled migration comparison.');
    renderChart(result.results, selected, Number(result.target_ms));
    renderSelected(selected);
    renderTable();
    $('exportCsv').disabled = false; $('exportJson').disabled = false;
  }
  function renderChart(rows, selected, target) {
    const sorted = [...rows].sort((a, b) => a.predicted_ms - b.predicted_ms);
    let visible = sorted.slice(0, 7);
    if (!visible.some((row) => row.configuration_id === selected.configuration_id)) visible = [...visible.slice(0, 6), selected];
    const maximum = Math.max(1, target, ...visible.map((row) => Number(row.predicted_ms))) * 1.09;
    setText('chartCount', `${visible.length} of ${rows.length} shown`);
    $('comparisonChart').replaceChildren(...visible.map((row) => {
      const button = el('button', `chart-row${row.configuration_id === state.selected ? ' selected' : ''}`);
      button.type = 'button'; button.setAttribute('aria-pressed', String(row.configuration_id === state.selected));
      button.setAttribute('aria-label', `${displayName(row)}: predicted ${ms(row.predicted_ms)}. Select configuration.`);
      const label = el('span', 'chart-row-label', row.ee_alg); label.append(el('small', '', `CA: ${row.ca_alg}`));
      const track = el('span', 'chart-track');
      const fill = el('span', 'chart-fill'); fill.style.width = `${Math.max(0, Number(row.predicted_ms)) / maximum * 100}%`;
      const budget = el('span', 'chart-budget'); budget.style.left = `${target / maximum * 100}%`;
      track.append(fill, budget);
      button.append(label, track, el('span', 'chart-row-value', number(row.predicted_ms)));
      button.addEventListener('click', () => chooseConfiguration(row.configuration_id));
      return button;
    }));
  }
  function renderSelected(row) {
    setText('selectedTitle', displayName(row));
    setText('selectedBadge', `NIST category ${row.category}`);
    setText('historyAverage', `Mean ${ms(row.history_mean_ms)}`);
    setText('observedDelay', ms(row.observed_ms));
    setText('certificateBytes', `${number(row.certificate_message_bytes / 1024, 1)} KiB`);
    setText('testRows', number(row.test_rows, 0));
    const provenance = row.provenance || {};
    setText('selectedProvenance', `Dataset replay · device ${provenance.node_id ?? '—'} · next exchange ${provenance.handshake_index ?? '—'}. The observed next exchange is shown for comparison only; it is not a model input.`);
    const warnings = (row.warnings || []).join(' ');
    setText('selectedWarning', warnings); $('selectedWarning').hidden = !warnings;
    renderHistory(row.history || []);
  }
  function svgNode(tag, attributes = {}, text) {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.entries(attributes).forEach(([name, value]) => node.setAttribute(name, String(value)));
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function renderHistory(history) {
    const container = $('historyChart'); container.replaceChildren();
    const rows = history.filter((row) => Number.isFinite(Number(row.handshake_delay_ms)));
    if (!rows.length) { container.append(el('p', 'field-help', 'Recorded history unavailable.')); return; }
    const values = rows.map((row) => Number(row.handshake_delay_ms));
    const low = Math.min(...values), high = Math.max(...values), spread = Math.max(high - low, 10);
    const points = values.map((value, i) => [20 + i * 300 / Math.max(1, values.length - 1), 49 - (value - low) / spread * 30]);
    const svg = svgNode('svg', { viewBox: '0 0 340 85', role: 'img', 'aria-label': `Previous recorded authentication delays: ${values.map(ms).join(', ')}` });
    svg.append(svgNode('path', { d: `M ${points[0][0]} 62 L ${points.map((point) => point.join(' ')).join(' L ')} L ${points.at(-1)[0]} 62 Z`, fill: '#e8f5ef' }));
    svg.append(svgNode('line', { x1: 10, y1: 62, x2: 330, y2: 62, stroke: '#e1e9ee', 'stroke-width': 1 }));
    svg.append(svgNode('polyline', { points: points.map((p) => p.join(',')).join(' '), fill: 'none', stroke: '#188a78', 'stroke-width': 2, 'stroke-linejoin': 'round' }));
    points.forEach(([x, y], index) => {
      const circle = svgNode('circle', { cx: x, cy: y, r: 3, fill: '#fff', stroke: '#188a78', 'stroke-width': 2 });
      circle.append(svgNode('title', {}, `Exchange ${rows[index].handshake_index}: ${ms(values[index])}`));
      svg.append(circle, svgNode('text', { x, y: Math.max(9, y - 9), 'text-anchor': 'middle' }, number(values[index], 0)), svgNode('text', { x, y: 78, 'text-anchor': 'middle' }, `#${rows[index].handshake_index ?? index + 1}`));
    });
    container.append(svg);
  }
  function renderTable() {
    if (!state.result) return;
    const rows = [...state.result.results];
    const sort = $('sortResults').value;
    rows.sort(sort === 'name' ? (a, b) => displayName(a).localeCompare(displayName(b)) : sort === 'category' ? (a, b) => b.category - a.category || a.predicted_ms - b.predicted_ms : (a, b) => a.predicted_ms - b.predicted_ms);
    $('resultsBody').replaceChildren(...rows.map((row) => {
      const tr = el('tr', row.configuration_id === state.selected ? 'selected' : '');
      const config = el('td'); const button = el('button', 'configuration-button', row.ee_alg);
      button.type = 'button'; button.setAttribute('aria-pressed', String(row.configuration_id === state.selected));
      button.append(el('small', '', `Signed by ${row.ca_alg}`)); button.addEventListener('click', () => chooseConfiguration(row.configuration_id)); config.append(button);
      const category = el('td'); category.append(el('span', 'category-badge', `Category ${row.category}`));
      const prediction = el('td'); prediction.append(el('strong', '', ms(row.predicted_ms)));
      const budget = el('td'); budget.append(el('span', `budget-status${row.meets_target ? '' : ' over'}`, row.meets_target ? 'Within budget' : 'Over budget'));
      const transfer = el('td', '', row.network_extra_transfer_ms == null ? 'Not measured' : `${number(row.network_extra_transfer_ms, 2)} ms`);
      tr.append(config, category, prediction, budget, transfer); return tr;
    }));
  }
  async function runProbe() {
    const sequence = ++state.probeSequence;
    state.probeController?.abort();
    const controller = new AbortController(); state.probeController = controller;
    const timeout = setTimeout(() => controller.abort(), 45000);
    $('probeButton').disabled = true; $('resetProbe').disabled = true; setText('probeButton', 'Measuring connection…');
    try {
      const durations = [];
      for (let index = 0; index < 5; index++) {
        setText('probeStatus', `Measuring request duration ${index + 1} of 5…`);
        const start = performance.now();
        const response = await fetch(`/api/probe/ping?t=${Date.now()}-${index}`, { credentials: 'same-origin', cache: 'no-store', signal: controller.signal });
        await response.arrayBuffer();
        if (response.status === 401) { signedOut('Your session ended. Sign in again.'); return; }
        if (!response.ok) throw new Error('The request-duration test failed. Please try again.');
        durations.push(performance.now() - start);
      }
      setText('probeStatus', 'Measuring a 1 MiB download…');
      const start = performance.now();
      const response = await fetch(`/api/probe/download?bytes=1048576&t=${Date.now()}`, { credentials: 'same-origin', cache: 'no-store', signal: controller.signal });
      const bytes = await response.arrayBuffer();
      const elapsed = performance.now() - start;
      if (response.status === 401) { signedOut('Your session ended. Sign in again.'); return; }
      if (!response.ok || !bytes.byteLength || elapsed <= 0) throw new Error('The download measurement failed. Please try again.');
      if (sequence !== state.probeSequence || !state.authenticated) return;
      durations.sort((a, b) => a - b);
      state.network = { rtt_ms: durations[2], download_mbps: bytes.byteLength * 8 / elapsed / 1000, measured_at: new Date().toISOString() };
      setText('networkRtt', ms(state.network.rtt_ms));
      setText('networkRate', `${number(state.network.download_mbps)} Mbps`);
      setText('probeStatus', 'Measured to this dashboard server. Request duration includes browser/server overhead; download rate is not your internet plan speed.');
      $('resetProbe').hidden = false;
      await analyze();
    } catch (error) {
      if (sequence === state.probeSequence && state.authenticated) setText('probeStatus', error.name === 'AbortError' ? 'The network test timed out. Please try again.' : error.message);
    } finally {
      clearTimeout(timeout);
      if (sequence === state.probeSequence) { $('probeButton').disabled = false; $('resetProbe').disabled = false; setText('probeButton', '↗ Run network test'); }
    }
  }
  function download(format) {
    if (!state.result) return;
    const exported = { ...state.result, selected: state.result.results.find((row) => row.configuration_id === state.selected), exported_at: new Date().toISOString(), network_measurement: state.network, note: 'ML estimates use each configuration’s own recorded simulated history. Network transfer estimates are independent and exclude processing, loss and protocol overhead.' };
    let body, type;
    if (format === 'json') { body = JSON.stringify(exported, null, 2); type = 'application/json'; }
    else {
      const columns = ['configuration_id', 'ee_alg', 'ca_alg', 'category', 'predicted_ms', 'meets_target', 'certificate_message_bytes', 'network_extra_transfer_ms', 'observed_ms', 'test_rows', 'target_ms', 'recorded_profile', 'scope'];
      const quote = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`;
      const rows = state.result.results.map((row) => columns.map((key) => quote(key === 'target_ms' ? state.result.target_ms : key === 'recorded_profile' ? state.result.profile : key === 'scope' ? exported.note : row[key])).join(','));
      body = [columns.join(','), ...rows].join('\r\n'); type = 'text/csv;charset=utf-8';
    }
    const url = URL.createObjectURL(new Blob([body], { type }));
    const link = el('a'); link.href = url; link.download = `pqconnect-analysis-${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  $('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault(); $('loginButton').disabled = true; setText('loginError', '');
    try {
      const session = await api('/api/session'); state.csrf = session.csrf;
      const result = await api('/api/login', { body: { username: $('username').value.trim(), password: $('password').value } });
      state.csrf = result.csrf; $('password').value = '';
      await loadApp();
    } catch (error) { setText('loginError', error.message); }
    finally { $('loginButton').disabled = false; }
  });
  $('logoutButton').addEventListener('click', async () => { try { await api('/api/logout', { body: {} }); signedOut(); } catch (error) { setError(error.message); } });
  $('retryBoot').addEventListener('click', boot);
  $('analysisForm').addEventListener('submit', (event) => { event.preventDefault(); analyze(); });
  $('minCategory').addEventListener('change', () => { fillConfigurations(); markDirty(); });
  $('targetMs').addEventListener('input', markDirty);
  $('profile').addEventListener('change', markDirty);
  $('configuration').addEventListener('change', () => { if (!state.dirty && state.result?.results.some((row) => row.configuration_id === $('configuration').value)) chooseConfiguration($('configuration').value); else markDirty(); });
  $('sortResults').addEventListener('change', renderTable);
  $('probeButton').addEventListener('click', runProbe);
  $('resetProbe').addEventListener('click', () => { state.probeSequence += 1; state.probeController?.abort(); state.network = null; $('resetProbe').hidden = true; setText('networkRtt', 'Not measured'); setText('networkRate', 'Not measured'); setText('probeStatus', 'Uses five requests and a 1 MiB download from this server.'); analyze(); });
  $('exportCsv').addEventListener('click', () => download('csv'));
  $('exportJson').addEventListener('click', () => download('json'));
  boot();
})();
