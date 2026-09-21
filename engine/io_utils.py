"""Table persistence: parquet when pyarrow is available, pickle otherwise."""
from __future__ import annotations

from pathlib import Path

import pandas as pd


def _has_pyarrow() -> bool:
    try:
        import pyarrow  # noqa: F401
        return True
    except ImportError:
        return False


def write_table(df: pd.DataFrame, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".parquet" and not _has_pyarrow():
        path = path.with_suffix(".pkl")
    if path.suffix == ".parquet":
        df.to_parquet(path, index=False)
    else:
        df.to_pickle(path)
    return path


def read_table(path: Path) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        alt = path.with_suffix(".pkl") if path.suffix == ".parquet" else path.with_suffix(".parquet")
        if alt.exists():
            path = alt
        else:
            raise FileNotFoundError(path)
    return pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_pickle(path)
