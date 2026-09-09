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
        Normal baseline: payload <= 50 MB, normal event types, daytime hours.
        """
        np.random.seed(42)
        # 200 normal samples
        normal_payloads = np.random.uniform(0.1, 30.0, 200)
        normal_codes = np.random.choice([0, 1, 2], 200) # AUTH_SUCCESS, LOGIN_FAILED (1-2 attempts)
        normal_hours = np.random.uniform(8.0, 18.0, 200)
        
        X_normal = np.column_stack((normal_payloads, normal_codes, normal_hours))
        
        # 30 anomaly samples
        anom_payloads = np.random.uniform(200.0, 1000.0, 30)
        anom_codes = np.random.choice([3, 4, 5], 30) # SUDO_EXEC, C2_BEACON, PORT_SCAN
        anom_hours = np.random.choice([1.0, 2.0, 3.0, 23.0], 30)
        
        X_anom = np.column_stack((anom_payloads, anom_codes, anom_hours))
        
        X_train = np.vstack((X_normal, X_anom))
        self.model.fit(X_train)

    def extract_features(self, event: NormalizedEvent) -> np.ndarray:
        # Encode event_type
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
        hour = 12.0 # Default hour
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
        """
        features = self.extract_features(event)
        # raw score: lower means more anomalous
        decision = self.model.decision_function(features)[0]
        
        # Map decision function range (~ -0.3 to +0.3) to 0.0 - 1.0 probability score
        # Anomaly threshold around decision <= 0
        if decision >= 0.15:
            score = 0.05
        elif decision <= -0.15:
            score = 0.95
        else:
            # Linear scaling in transition zone
            score = round(0.5 - (decision / 0.3), 2)
            score = max(0.0, min(1.0, score))
            
        # Heavy payload boost for ML data transfer detection
        if event.payload_metric >= 500.0:
            score = max(score, 0.92)
        elif event.payload_metric >= 100.0:
            score = max(score, 0.75)

        return float(score)
