"""Command-line check for the bundled model's required library versions."""
import argparse
import json
import platform

from pqconnect.environment_check import PACKAGES, compatibility_error, installed_versions, model_versions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='Print machine-readable output')
    args = parser.parse_args()
    expected = model_versions()
    installed = installed_versions()
    error = compatibility_error()
    result = {
        'compatible': error is None,
        'python': platform.python_version(),
        'architecture': platform.machine(),
        'expected': {PACKAGES[k]: expected.get(k) for k in PACKAGES},
        'installed': {PACKAGES[k]: installed.get(k) for k in PACKAGES},
        'error': error,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Python {result['python']} on {result['architecture']}")
        for package in result['expected']:
            marker = 'OK' if result['expected'][package] == result['installed'][package] else 'MISMATCH'
            print(f"{marker:8} {package}: installed {result['installed'][package] or 'missing'}, expected {result['expected'][package]}")
        print('\nEnvironment is compatible with the bundled model.' if error is None else '\n' + error)
    return 0 if error is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
