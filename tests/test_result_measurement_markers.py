from __future__ import annotations

from pathlib import Path

FORBIDDEN_MARKERS = ("calibrated", "modelled", "modeled", "synthetic")


def test_result_env_and_summary_files_do_not_mark_measurements_as_modelled() -> None:
    result_files = [
        path
        for pattern in ("env.json", "summary.json")
        for path in Path("results").glob(f"**/{pattern}")
    ]
    assert result_files
    for path in result_files:
        content = path.read_text(encoding="utf-8").lower()
        assert not any(marker in content for marker in FORBIDDEN_MARKERS), path
