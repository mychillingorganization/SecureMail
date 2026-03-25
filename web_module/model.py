"""
XGBoost phishing detection model wrapper.

Loads the Booster once at startup and exposes a single ``predict()`` method that
returns a structured dict — never raises on malformed input.
"""

import logging
import os
from pathlib import Path

import xgboost as xgb

logger = logging.getLogger(__name__)

# Resolve model path relative to this module's directory, with env override
_module_dir = Path(__file__).parent.resolve()
_default_model = _module_dir / "models" / "xgboost_phishing_model.json"
MODEL_PATH = os.getenv("MODEL_PATH", str(_default_model))


class PhishingModel:
    """Thin, stateless wrapper around the trained XGBoost Booster.

    The Booster is used directly (not the sklearn wrapper) so that
    ``feature_names`` are read from the saved JSON metadata and the
    feature order is always authoritative.
    """

    def __init__(self, model_path: str = MODEL_PATH) -> None:
        # Resolve path to handle both absolute and relative paths
        resolved_path = Path(model_path).resolve()
        
        if not resolved_path.exists():
            raise FileNotFoundError(
                f"Model file not found at {resolved_path}. "
                f"Set MODEL_PATH env var to override default location."
            )
        
        self._booster = xgb.Booster()
        try:
            self._booster.load_model(str(resolved_path))
        except Exception as e:
            raise RuntimeError(
                f"Failed to load XGBoost model from {resolved_path}: {e}"
            ) from e

        self.feature_names: list[str] = self._booster.feature_names or []
        if not self.feature_names:
            raise RuntimeError(
                f"Model at '{resolved_path}' contains no feature_names. "
                "Re-save the model after setting feature names."
            )

        logger.info(
            "PhishingModel loaded: %d features from '%s'",
            len(self.feature_names),
            resolved_path,
        )

    def predict(self, features: dict[str, float | int]) -> dict[str, float | str]:
        """Run inference on a feature dictionary.

        Missing features default to ``0``.  NaN / ±inf values are clamped to
        ``0`` before inference so the Booster never receives invalid input.

        Returns:
            {
                "risk_score": float,   # P(phishing), range 0–1
                "confidence": float,   # certainty: |risk - 0.5| * 2, range 0–1
                "label":      str,     # "phishing" | "safe"
            }
        """
        vector = [float(features.get(f, 0)) for f in self.feature_names]
        # Sanitize NaN and ±inf
        vector = [
            0.0 if (v != v or v == float("inf") or v == float("-inf")) else v
            for v in vector
        ]

        dmatrix = xgb.DMatrix([vector], feature_names=self.feature_names)
        prob = float(self._booster.predict(dmatrix)[0])
        confidence = abs(prob - 0.5) * 2.0

        return {
            "risk_score": round(prob, 4),
            "confidence": round(confidence, 4),
            "label": "phishing" if prob >= 0.5 else "safe",
        }
