"""Mock Vendor Connector Implementation (REQ-CON-001)."""
import json
from typing import Dict, Any, List
from datetime import datetime
from models.schemas.telemetry import RawTelemetryEvent
from ai_threat_detection.connectors.base import BaseConnector


class MockVendorConnector(BaseConnector):
    """Mock Connector for demonstration and testing."""

    @property
    def vendor_name(self) -> str:
        return "MockVendor"

    def ingest_payload(self, payload: Dict[str, Any]) -> List[RawTelemetryEvent]:
        events = []
        raw_items = payload.get("records", [payload])
        for item in raw_items:
            events.append(
                RawTelemetryEvent(
                    source_id="mock-source-01",
                    vendor=self.vendor_name,
                    raw_payload=json.dumps(item),
                    ingested_at=datetime.utcnow()
                )
            )
        return events

    def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "vendor": self.vendor_name,
            "action": action,
            "params": params,
            "timestamp": datetime.utcnow().isoformat()
        }
