"""Derive compact replay inputs from original CSVs; no synthetic telemetry."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parent
FIELDS = ['handshake_delay_ms', 'mac_retry_rate', 'phy_frame_drop_rate', 'throughput_kbps', 'tx_delay_us']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--classical-csv', type=Path, help='Optional original s1 ECDSA-SHA256 homogeneous CSV')
    args = parser.parse_args()
    output = ROOT / 'pqconnect/artifacts'
    catalog = json.loads((output / 'configurations.json').read_text())
    states = {}
    for config in catalog:
        cid = config['configuration_id']
        if not config['training_rows']:
            continue
        path = ROOT / 'pqconnect/data' / f's2_{cid}.csv'
        rows = list(csv.DictReader(path.open(encoding='utf-8')))
        nodes = {}
        for row in rows:
            nodes.setdefault(int(row['node_id']), []).append(row)
        # Prefer station 1; choose another only if it lacks enough history.
        node = next(n for n in sorted(nodes) if len(nodes[n]) >= 6)
        sequence = sorted(nodes[node], key=lambda r: int(r['handshake_index']))
        windows = [i for i in range(5, len(sequence)) if all(
            int(sequence[j]['handshake_index']) + 1 == int(sequence[j + 1]['handshake_index'])
            for j in range(i - 5, i))]
        if not windows:
            continue
        selections = {'early': windows[0], 'middle': windows[len(windows)//2], 'late': windows[-1]}
        states[cid] = {}
        for label, index in selections.items():
            past = sequence[index-5:index]
            states[cid][label] = {
                'history': [{**{f: float(row[f]) for f in FIELDS},
                             'handshake_index': int(row['handshake_index']), 'node_id': node,
                             'configuration_id': cid} for row in past],
                'observed_ms': float(sequence[index]['handshake_delay_ms']),
                'provenance': {'source': 'dataset replay', 'file': path.name, 'node_id': node,
                               'handshake_index': int(sequence[index]['handshake_index']),
                               'dataset_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}
    (output / 'network_states.json').write_text(json.dumps(states, indent=2), encoding='utf-8')
    if args.classical_csv:
        rows = list(csv.DictReader(args.classical_csv.open(encoding='utf-8')))
        label = 'ECDSA-SHA256_signed-by_ECDSA-SHA256'
        if not rows or any(r['sta_cert_algo'] != label or r['ap_cert_algo'] != label for r in rows):
            raise ValueError('Provide the homogeneous ECDSA-SHA256 reference CSV.')
        reference = {'label': 'ECDSA P-256 / SHA-256 reference',
                     'certificate_message_bytes': statistics.median(float(r['server_cert_msg_bytes']) + float(r['client_cert_msg_bytes']) for r in rows),
                     'source_file': args.classical_csv.name, 'rows': len(rows),
                     'sha256': hashlib.sha256(args.classical_csv.read_bytes()).hexdigest(),
                     'source_url': 'https://github.com/samettonyali29/x-layer_performance_evaluation_of_PQ_X.509',
                     'definition': 'Median combined server and client certificate-message bytes from the classical reference run; not a classical login latency.'}
        (output / 'classical_reference.json').write_text(json.dumps(reference, indent=2), encoding='utf-8')
    print(f'Generated three recorded histories for {len(states)} configurations.')


if __name__ == '__main__':
    main()
