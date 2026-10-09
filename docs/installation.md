# Installation

Requirements: Python 3.12 or newer, `pip`. No network access is needed at
runtime and no additional services are required.

```powershell
# From a checkout of this repository:
pip install -e .
pip install pytest ruff   # development tools only (tests, lint)

# Verify:
aegisbench version
python -m pytest
```

The `aegisbench` console script is registered via `pyproject.toml`
(`aegisbench.cli:app`). If the script is not on your `PATH`, `python -m`
equivalents work for the benchmark harnesses (`python -m
aegisbench.benchmark`, `python -m aegisbench.heldout`); the CLI itself is
invoked as `aegisbench`.

No telemetry, accounts, or external credentials are involved at any step.
