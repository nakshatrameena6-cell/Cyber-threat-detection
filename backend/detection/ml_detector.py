import numpy as np
from sklearn.ensemble import IsolationForest
from backend.models.events import NormalizedEvent
from backend.detection.behavioral_engine import BehavioralVector

class MLAnomalyDetector:
    def __init__(self):
        # IsolationForest model trained on 6D behavioral vectors
        self.model = IsolationForest(contamination=0.15, random_state=42)
        self._train_synthetic_baseline()

    def _train_synthetic_baseline(self):
        """
        Trains IsolationForest on 6D behavioral vectors:
        Features: [failed_logins, data_mb, unique_dests, conn_freq, off_hours, priv_changes]
        """
        np.random.seed(42)
        
        # 300 normal samples (standard user activity)
        norm_failed = np.random.uniform(0.0, 1.0, 300)
        norm_data = np.random.uniform(0.1, 20.0, 300)
        norm_dests = np.random.uniform(1.0, 3.0, 300)
        norm_conn = np.random.uniform(1.0, 4.0, 300)
        norm_off_hours = np.random.choice([0.0, 1.0], 300, p=[0.85, 0.15])
        norm_priv = np.zeros(300)
        
        X_normal = np.column_stack((norm_failed, norm_data, norm_dests, norm_conn, norm_off_hours, norm_priv))

        # 60 anomaly samples (various attack behavioral vectors)
        anom_failed = np.random.uniform(5.0, 20.0, 60)
        anom_data = np.random.uniform(300.0, 1000.0, 60)
        anom_dests = np.random.uniform(10.0, 50.0, 60)
        anom_conn = np.random.uniform(15.0, 60.0, 60)
        anom_off_hours = np.ones(60)
        anom_priv = np.random.uniform(1.0, 5.0, 60)

        X_anom = np.column_stack((anom_failed, anom_data, anom_dests, anom_conn, anom_off_hours, anom_priv))

        X_train = np.vstack((X_normal, X_anom))
        self.model.fit(X_train)

    def extract_features(self, event: NormalizedEvent, vector: BehavioralVector = None) -> np.ndarray:
        if vector is None:
            # Fallback construct basic vector from single event
            off_hours = 0.0
            ts_qual = getattr(event, "timestamp_quality", "TRUSTED")
            if str(ts_qual) not in ["FALLBACK_MALFORMED", "FALLBACK_MISSING", "FUTURE_TIMESTAMP"]:
                if "T" in event.timestamp and ":" in event.timestamp:
                    try:
                        h = int(event.timestamp.split("T")[1].split(":")[0])
                        if h < 8 or h >= 18:
                            off_hours = 1.0
                    except Exception:
                        pass

            return np.array([[
                event.payload_metric if event.event_type.value == "LOGIN_FAILED" else 0.0,
                event.payload_metric if event.event_type.value == "BYTES_OUT" else 0.0,
                1.0,
                event.payload_metric if event.event_type.value in ["C2_BEACON", "PORT_SCAN"] else 1.0,
                off_hours,
                1.0 if event.event_type.value == "SUDO_EXEC" else 0.0
            ]])

        return np.array([[
            vector.failed_login_count,
            vector.data_transfer_volume_mb,
            vector.unique_destinations_count,
            vector.connection_frequency,
            vector.off_hours_flag,
            vector.privilege_change_events
        ]])

    def predict_anomaly_score(self, event: NormalizedEvent, vector: BehavioralVector = None) -> float:
        """
        Returns continuous anomaly score between 0.05 (normal) and 0.95 (anomalous).
        """
        features = self.extract_features(event, vector)

        # Domain safety overrides for high-threat indicators
        if event.payload_metric >= 500.0:
            return 0.95
        if event.event_type.value == "C2_BEACON":
            return 0.90
        if event.event_type.value == "PORT_SCAN" and (event.payload_metric >= 5.0 or (vector and vector.cumulative_scan_targets >= 5.0)):
            return 0.90
        if event.event_type.value == "AUTH_SUCCESS" and (vector is None or vector.failed_login_count < 3.0):
            return 0.10

        decision = self.model.decision_function(features)[0]

        # Map decision function to anomaly score
        score = 0.50 - (decision * 2.5)
        score = round(max(0.05, min(0.95, score)), 2)
        return float(score)
