"""Base Connector Abstract Interface (REQ-CON-001, REQ-CON-002)."""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from models.schemas.telemetry import RawTelemetryEvent


class BaseConnector(ABC):
    """Abstract Connector Interface isolating vendor-specific logic."""

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Name of vendor (e.g. Splunk, Crowdstrike)."""
        pass

    @abstractmethod
    def ingest_payload(self, payload: Dict[str, Any]) -> List[RawTelemetryEvent]:
        """Convert vendor payload to RawTelemetryEvent list."""
        pass

    @abstractmethod
    def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute vendor API action (e.g., send alert, post ticket)."""
        pass
