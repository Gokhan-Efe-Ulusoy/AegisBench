"""Blinded evaluation harness for externally prepared fixture sets.

Two explicit steps (never combined, so labels cannot leak into predictions):

    python -m aegisbench.blind predict --fixtures <dir> --out predictions.json
    python -m aegisbench.blind score --predictions predictions.json --labels labels.json

`predict` never opens any label file: it reads only `*.json` fixtures and
writes predictions plus input hashes, analyzer version/hash, and
environment. `score` reads the frozen predictions plus the reviewer's
labels and refuses to run on missing/mismatched fixture IDs.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from aegisbench import heldout

app = typer.Typer(name="blind", help="Blinded external evaluation harness.", no_args_is_help=True)


@app.callback()
def _callback() -> None:
    """Blinded external evaluation harness."""


@app.command("predict")
def predict_cmd(
    fixtures: Annotated[Path, typer.Option("--fixtures", help="External fixture directory.")],
    out: Annotated[Path, typer.Option("--out", help="Where to write predictions JSON.")],
) -> None:
    try:
        predictions, hashes, t_base, t_graph = heldout.predict(fixtures_dir=fixtures)
    except Exception as exc:
        typer.echo(f"Error: prediction failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    payload = {
        "analyzer_versions": {
            "baseline": "BROAD-CMD-001 v1 (Phase 0, unchanged)",
            "graph": "GRAPH-CHAIN-001 v1 (Phase 1 prototype)",
        },
        "analyzer_freeze": heldout.analyzer_freeze(),
        "fixture_hashes": dict(sorted(hashes.items())),
        "predictions": predictions,
        "elapsed_seconds": {"baseline": round(t_base, 6), "graph": round(t_graph, 6)},
        "python": sys.version.split()[0],
    }
    payload["prediction_hash"] = hashlib.sha256(
        json.dumps(predictions, sort_keys=True).encode()
    ).hexdigest()
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    typer.echo(f"Wrote {len(predictions)} predictions to {out} hash={payload['prediction_hash']}")


@app.command("score")
def score_cmd(
    predictions: Annotated[Path, typer.Option("--predictions", help="Frozen predictions file.")],
    labels: Annotated[Path, typer.Option("--labels", help="Reviewer label file.")],
    out: Annotated[Path | None, typer.Option("--out", help="Optional report destination.")] = None,
) -> None:
    try:
        pred_doc = json.loads(predictions.read_text(encoding="utf-8"))
        report = heldout.score(pred_doc["predictions"], labels_path=labels)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        typer.echo(f"Error: cannot score: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    text = json.dumps(report, indent=2, sort_keys=True)
    if out is not None:
        out.write_text(text + "\n", encoding="utf-8")
    else:
        typer.echo(text)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
