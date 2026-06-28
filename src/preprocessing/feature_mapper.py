"""
Converts a flow_tracker feature dict into the exact column format
the trained Random Forest model expects (matches training-time one-hot encoding).
"""

import pandas as pd
import pickle
import os

# Load the exact column order the model was trained on
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_FEATURES_CSV = os.path.join(_PROJECT_ROOT, "data", "processed", "features.csv")

_MODEL_COLUMNS = None  # cached after first load


def _load_model_columns():
    global _MODEL_COLUMNS
    if _MODEL_COLUMNS is None:
        df = pd.read_csv(_FEATURES_CSV, nrows=1)
        cols = list(df.columns)
        cols.remove("binary_label")  # this is the target, not a feature
        _MODEL_COLUMNS = cols
    return _MODEL_COLUMNS


def flow_to_model_row(flow_dict: dict) -> pd.DataFrame:
    """
    Takes a raw flow feature dict (from flow_tracker) and returns
    a single-row DataFrame matching the model's expected 122 columns.
    """
    model_columns = _load_model_columns()

    # Drop tracking-only fields not used by the model
    clean = {k: v for k, v in flow_dict.items() if k not in ("src_ip", "dst_ip")}

    # Build a one-row DataFrame, then one-hot encode the same way training did
    row_df = pd.DataFrame([clean])
    row_df = pd.get_dummies(row_df, columns=["protocol_type", "service", "flag"])

    # Reindex to match training columns exactly — fills missing one-hot columns with 0
    row_df = row_df.reindex(columns=model_columns, fill_value=0)

    return row_df