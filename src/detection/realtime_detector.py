"""
Loads the trained model and runs predictions on finished flows.
"""

import pickle
import os
from src.preprocessing.feature_mapper import flow_to_model_row

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODEL_PATH = os.path.join(_PROJECT_ROOT, "src", "models", "saved", "rf_model.pkl")

_model = None


def _load_model():
    global _model
    if _model is None:
        with open(_MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    return _model


def predict_flow(flow_dict: dict) -> dict:
    """
    Takes a raw flow dict, returns a prediction result:
    {"prediction": "normal"/"attack", "confidence": float, ...flow info}
    """
    model = _load_model()
    row = flow_to_model_row(flow_dict)

    pred = model.predict(row)[0]              # 0 = attack, 1 = normal (per your LabelEncoder)
    proba = model.predict_proba(row)[0]
    confidence = round(max(proba), 3)

    label = "normal" if pred == 1 else "attack"

    return {
        "src_ip": flow_dict.get("src_ip"),
        "dst_ip": flow_dict.get("dst_ip"),
        "service": flow_dict.get("service"),
        "protocol": flow_dict.get("protocol_type"),
        "prediction": label,
        "confidence": confidence,
    }