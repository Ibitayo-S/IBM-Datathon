"""Check that runtime libraries match the versions used to serialize the model."""
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path

MODEL_METADATA = Path(__file__).resolve().parent / 'artifacts' / 'metadata.json'
PACKAGES = {
    'numpy': 'numpy',
    'pandas': 'pandas',
    'scikit_learn': 'scikit-learn',
    'joblib': 'joblib',
}


def model_versions(metadata_path=MODEL_METADATA):
    metadata = json.loads(Path(metadata_path).read_text(encoding='utf-8'))
    return metadata.get('versions', {})


def installed_versions():
    found = {}
    for metadata_key, package_name in PACKAGES.items():
        try:
            found[metadata_key] = version(package_name)
        except PackageNotFoundError:
            found[metadata_key] = None
    return found


def mismatches(metadata_path=MODEL_METADATA):
    expected = model_versions(metadata_path)
    installed = installed_versions()
    return {
        key: {'expected': expected.get(key), 'installed': installed.get(key)}
        for key in PACKAGES
        if expected.get(key) != installed.get(key)
    }


def compatibility_error(metadata_path=MODEL_METADATA):
    problems = mismatches(metadata_path)
    if not problems:
        return None
    detail = ', '.join(
        f"{PACKAGES[key]} {item['installed'] or 'missing'} (model requires {item['expected']})"
        for key, item in problems.items()
    )
    return (
        'The Python environment does not match the serialized model: ' + detail + '. '
        'Activate the project virtual environment and run: '
        'python -m pip install -r requirements.txt. If these exact versions are unavailable '
        'on this architecture, retrain the model in that environment before serving it.'
    )
