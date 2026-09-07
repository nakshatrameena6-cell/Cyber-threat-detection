"""Risk Scoring Engine (REQ-SCO-001, REQ-SCO-002, REQ-SCO-003)."""
from models.schemas.incident import CorrelatedIncident


class RiskScoringEngine:
    """Computes composite multi-dimensional risk scores."""

    SEVERITY_WEIGHTS = {
        "LOW": 0.25,
        "MEDIUM": 0.50,
        "HIGH": 0.75,
        "CRITICAL": 1.00
    }

    def calculate_risk(self, incident: CorrelatedIncident, asset_criticality: float = 1.0) -> float:
        """
        RiskScore = Confidence * SeverityWeight * AssetCriticality
        Fallback to 1.0 (Maximum risk / human review) if input missing or invalid.
        """
        if not incident or incident.confidence is None or incident.max_severity is None:
            # Conservative fallback: REQ-SCO-003
            return 1.0

        confidence = max(0.0, min(1.0, incident.confidence))
        severity_weight = self.SEVERITY_WEIGHTS.get(incident.max_severity.upper(), 0.5)
        criticality = max(0.1, min(1.0, asset_criticality))

        risk_score = round(confidence * severity_weight * criticality, 4)
        incident.risk_score = risk_score
        return risk_score
