import os, json, joblib, numpy as np
from loguru import logger

FEATURES = [
    'Destination Port', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Fwd PSH Flags', 'SYN Flag Count', 'RST Flag Count',
    'ACK Flag Count', 'PSH Flag Count',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Mean', 'Packet Length Std',
]

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')


class MLPredictor:
    def __init__(self):
        self.rf_model = self.rf_scaler = None
        self.if_model = self.if_scaler = None
        self.if_threshold = 0.0
        self.ready = False
        self._load_models()

    def _load_models(self):
        try:
            self.rf_model  = joblib.load(os.path.join(MODEL_DIR, 'random_forest.joblib'))
            self.rf_scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler_rf.joblib'))
            logger.info("✅ Random Forest model loaded")
            self.if_model  = joblib.load(os.path.join(MODEL_DIR, 'isolation_forest.joblib'))
            self.if_scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.joblib'))
            logger.info("✅ Isolation Forest model loaded")
            with open(os.path.join(MODEL_DIR, 'threshold.json')) as f:
                self.if_threshold = json.load(f).get('best_threshold', 0.0)
            logger.info(f"✅ IF threshold: {self.if_threshold:.4f}")
            self.ready = True
            logger.info("🧠 ML Engine ready (RF + IF dual-layer)")
        except Exception as e:
            logger.warning(f"⚠️  ML models tidak bisa dimuat: {e}")
            self.ready = False

    def predict(self, log_entry: dict):
        if not self.ready:
            return None
        features = self._extract_features(log_entry)
        if features is None:
            return None
        logger.info(f"[ML] ✅ Fitur diekstrak: {len(features)} features")
        X = np.array([features])
        result = {'features_extracted': True}

        # ── Random Forest ──────────────────────────────────────
        try:
            X_rf     = self.rf_scaler.transform(X)
            rf_pred  = self.rf_model.predict(X_rf)[0]
            rf_proba = self.rf_model.predict_proba(X_rf)[0]
            result['rf_prediction']  = int(rf_pred)
            result['rf_attack_prob'] = float(rf_proba[1]) if len(rf_proba) > 1 else 0.0
            result['rf_confidence']  = float(max(rf_proba))
            logger.info(f"[RF] pred={rf_pred} attack_prob={result['rf_attack_prob']:.3f}")
        except Exception as e:
            logger.error(f"[RF] Error: {e}")
            result['rf_prediction']  = 0
            result['rf_attack_prob'] = 0.0
            result['rf_confidence']  = 0.0

        # ── Isolation Forest ───────────────────────────────────
        try:
            X_if     = self.if_scaler.transform(X)
            if_score = self.if_model.decision_function(X_if)[0]
            if_pred  = 1 if if_score < self.if_threshold else 0
            result['if_score']      = float(if_score)
            result['if_prediction'] = int(if_pred)
            result['if_threshold']  = float(self.if_threshold)
            logger.info(f"[IF] score={if_score:.4f} pred={if_pred}")
        except Exception as e:
            logger.error(f"[IF] Error: {e}")
            result['if_score']      = 0.0
            result['if_prediction'] = 0

        # ── Final Decision ─────────────────────────────────────
        if result['rf_prediction'] == 1:
            result['is_attack']   = True
            result['method']      = 'random_forest'
            result['severity']    = self._rf_severity(result['rf_attack_prob'])
            result['attack_type'] = 'ml_detected_attack'
            logger.warning(f"[ML] 🚨 ATTACK! prob={result['rf_attack_prob']:.3f} severity={result['severity']}")
        elif result['if_prediction'] == 1:
            result['is_attack']   = True
            result['method']      = 'isolation_forest'
            result['severity']    = 'medium'
            result['attack_type'] = 'ml_anomaly'
            logger.warning(f"[ML] ⚠️  ANOMALY! score={result['if_score']:.4f}")
        else:
            result['is_attack']   = False
            result['method']      = 'none'
            result['severity']    = None
            result['attack_type'] = None
            logger.info("[ML] ✅ Normal traffic")

        return result

    def _extract_features(self, log_entry: dict):
        """
        Ekstrak 25 fitur dari log entry.
        FIX: pakai dict.get dengan sentinel, bukan 'or', supaya nilai 0 tidak dianggap False.
        """
        _SENTINEL = object()

        # Gabungkan semua sumber data
        raw = {}
        raw.update(log_entry.get('raw', {}))
        raw.update(log_entry)

        # Buat lookup dengan semua variasi nama key
        lookup = {}
        for k, v in raw.items():
            if isinstance(k, str):
                lookup[k]                           = v
                lookup[k.strip()]                   = v
                lookup[k.lower()]                   = v
                lookup[k.lower().replace(' ', '_')] = v
                lookup[k.strip().lower()]           = v

        values  = []
        missing = []

        for feat in FEATURES:
            candidates = [
                feat,
                feat.strip(),
                feat.lower(),
                feat.lower().replace(' ', '_'),
                feat.strip().lower(),
            ]

            found = False
            for c in candidates:
                val = lookup.get(c, _SENTINEL)
                if val is _SENTINEL:
                    continue
                # val ditemukan — coba convert ke float
                try:
                    v = float(val)
                    if np.isinf(v) or np.isnan(v):
                        v = 0.0
                    values.append(v)
                    found = True
                    break
                except (ValueError, TypeError):
                    continue

            if not found:
                missing.append(feat)

        if missing:
            logger.debug(f"[ML] Missing {len(missing)} features: {missing[:5]}")
            return None

        return values

    def _rf_severity(self, prob: float) -> str:
        if prob >= 0.95:   return 'critical'
        elif prob >= 0.80: return 'high'
        elif prob >= 0.60: return 'medium'
        else:              return 'low'
