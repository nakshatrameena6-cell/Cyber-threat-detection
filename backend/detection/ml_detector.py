import numpy as np
from sklearn.ensemble import IsolationForest
from backend.models.events import NormalizedEvent

class MLAnomalyDetector:
    def __init__(self):
        # Initialize and fit a baseline IsolationForest model on normal telemetry patterns
        self.model = IsolationForest(contamination=0.15, random_state=42)
        self._train_synthetic_baseline()

    def _train_synthetic_baseline(self):
        """
        Trains IsolationForest on normal baseline telemetry vectors.
        Features: [payload_metric, event_code, hour_of_day]
        Normal baseline: payload <= 30 MB, normal event types (0, 1, 2), daytime hours (8-18).
        """
        np.random.seed(42)
        # 300 normal samples
        normal_payloads = np.random.uniform(0.1, 30.0, 300)
        normal_codes = np.random.choice([0, 1, 2], 300) # AUTH_SUCCESS, LOGIN_FAILED, SUSPICIOUS_LOGIN
        normal_hours = np.random.uniform(8.0, 18.0, 300)
        
        X_normal = np.column_stack((normal_payloads, normal_codes, normal_hours))
        
        # 50 anomaly samples
        anom_payloads = np.random.uniform(200.0, 1000.0, 50)
        anom_codes = np.random.choice([3, 4, 5, 6], 50) # SUDO_EXEC, C2_BEACON, PORT_SCAN, BYTES_OUT
        anom_hours = np.random.choice([1.0, 2.0, 3.0, 23.0], 50)
        
        X_anom = np.column_stack((anom_payloads, anom_codes, anom_hours))
        
        X_train = np.vstack((X_normal, X_anom))
        self.model.fit(X_train)

    def extract_features(self, event: NormalizedEvent) -> np.ndarray:
        event_code_map = {
            "AUTH_SUCCESS": 0,
            "LOGIN_FAILED": 1,
            "SUSPICIOUS_LOGIN": 2,
            "SUDO_EXEC": 3,
            "PORT_SCAN": 4,
            "C2_BEACON": 5,
            "BYTES_OUT": 6,
            "CUSTOM": 7
        }
        code = event_code_map.get(event.event_type.value, 7)
        hour = 12.0
        if "T" in event.timestamp and ":" in event.timestamp:
            try:
                time_part = event.timestamp.split("T")[1]
                hour = float(time_part.split(":")[0])
            except Exception:
                hour = 12.0

        return np.array([[event.payload_metric, code, hour]])

    def predict_anomaly_score(self, event: NormalizedEvent) -> float:
        """
        Returns anomaly score normalized between 0.0 (perfectly normal) and 1.0 (highly anomalous).
        IsolationForest decision_function > 0 indicates normal, < 0 indicates anomaly.
        """
        # Explicit domain overrides for known high-risk / low-risk patterns
        if event.payload_metric >= 500.0:
            return 0.95
        if event.event_type.value in ["C2_BEACON", "PORT_SCAN"]:
            return 0.90
        if event.event_type.value == "AUTH_SUCCESS" and event.payload_metric <= 10.0:
            return 0.10

        features = self.extract_features(event)
        decision = self.model.decision_function(features)[0]
        
        # Decision function mapping: positive decision = normal (low score), negative decision = anomaly (high score)
        # decision usually in range [-0.25, 0.25]
        score = 0.50 - (decision * 2.0)
        score = round(max(0.05, min(0.95, score)), 2)
        return float(score)
