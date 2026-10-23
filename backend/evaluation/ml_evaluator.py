"""
Suraksha AI - IsolationForest ML Evaluation Engine (Workstream D)
Evaluates ML anomaly detection on independent holdout data without data leakage.
Compares Rules-alone, ML-alone, and Hybrid Detection.
"""
from typing import Dict, Any, List, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from backend.detection.ml_detector import MLAnomalyDetector
from backend.evaluation.metrics import (
    calculate_confusion_matrix,
    calculate_classification_metrics,
)


class MLEvaluator:
    """
    Evaluates ML anomaly detection without data leakage using independent holdout datasets.
    """
    def __init__(self, detector: MLAnomalyDetector = None):
        self.detector = detector or MLAnomalyDetector()

    @staticmethod
    def generate_independent_holdout_set(
        n_normal: int = 150,
        n_anomalous: int = 50,
        random_seed: int = 101
    ) -> Tuple[np.ndarray, List[bool]]:
        """
        Generates an independent, deterministic holdout dataset with a distinct random seed (101)
        to prevent train/test leakage with the training baseline (seed 42).
        Features: [failed_logins, data_mb, unique_dests, conn_freq, off_hours, priv_changes]
        """
        np.random.seed(random_seed)

        # 1. Normal holdout samples
        norm_failed = np.random.uniform(0.0, 1.0, n_normal)
        norm_data = np.random.uniform(0.1, 25.0, n_normal)
        norm_dests = np.random.uniform(1.0, 3.0, n_normal)
        norm_conn = np.random.uniform(1.0, 5.0, n_normal)
        norm_off_hours = np.random.choice([0.0, 1.0], n_normal, p=[0.88, 0.12])
        norm_priv = np.zeros(n_normal)

        X_normal = np.column_stack((
            norm_failed, norm_data, norm_dests, norm_conn, norm_off_hours, norm_priv
        ))
        y_normal = [False] * n_normal

        # 2. Anomalous holdout samples (attack profiles)
        anom_failed = np.random.uniform(5.0, 25.0, n_anomalous)
        anom_data = np.random.uniform(350.0, 1200.0, n_anomalous)
        anom_dests = np.random.uniform(12.0, 60.0, n_anomalous)
        anom_conn = np.random.uniform(15.0, 70.0, n_anomalous)
        anom_off_hours = np.ones(n_anomalous)
        anom_priv = np.random.uniform(1.0, 5.0, n_anomalous)

        X_anom = np.column_stack((
            anom_failed, anom_data, anom_dests, anom_conn, anom_off_hours, anom_priv
        ))
        y_anom = [True] * n_anomalous

        X_holdout = np.vstack((X_normal, X_anom))
        y_holdout = y_normal + y_anom

        return X_holdout, y_holdout

    def evaluate_holdout_performance(
        self,
        threshold: float = 0.50,
        random_seed: int = 101
    ) -> Dict[str, Any]:
        """
        Evaluates the IsolationForest model against the holdout behavioral vector set.
        """
        X_holdout, y_true = self.generate_independent_holdout_set(
            n_normal=150, n_anomalous=50, random_seed=random_seed
        )

        decisions = self.detector.model.decision_function(X_holdout)
        # Anomaly score mapping from MLAnomalyDetector: 0.50 - (decision * 2.5)
        anomaly_scores = [
            round(float(max(0.05, min(0.95, 0.50 - (d * 2.5)))), 2)
            for d in decisions
        ]

        y_pred = [score >= threshold for score in anomaly_scores]

        cm = calculate_confusion_matrix(y_true, y_pred)
        metrics = calculate_classification_metrics(cm["tp"], cm["fp"], cm["tn"], cm["fn"])

        return {
            "model_type": "IsolationForest (Scikit-Learn)",
            "contamination": self.detector.model.contamination,
            "training_seed": 42,
            "holdout_seed": random_seed,
            "total_holdout_samples": len(y_true),
            "normal_samples": 150,
            "anomalous_samples": 50,
            "threshold": threshold,
            "confusion_matrix": cm,
            "metrics": metrics,
            "safety_invariant": "ML anomaly score alone NEVER authorizes remediation; fails closed to Tier C Human Review."
        }
