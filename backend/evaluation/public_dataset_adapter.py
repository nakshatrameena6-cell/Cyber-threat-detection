"""
Suraksha AI - Public Dataset Ingestion Adapter (Phase 6 Optional Extension)
Implements schema and label mapping adapters for public intrusion detection benchmarks
(CIC-IDS2017 and UNSW-NB15) without hardcoding or fabricating results.
"""
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from backend.models.events import NormalizedEvent, EventType, AssetCriticality
from backend.models.incidents import ThreatCategory


class PublicDatasetType(str, Enum):
    CIC_IDS2017 = "CIC-IDS2017"
    UNSW_NB15 = "UNSW-NB15"


class DatasetAdapterMetadata(BaseModel):
    dataset_name: str
    license_type: str
    citation: str
    status: str = "PENDING_LOCAL_DOWNLOAD"
    notes: str = ""


# Documented Licensing & Attribution
DATASET_METADATA: Dict[PublicDatasetType, DatasetAdapterMetadata] = {
    PublicDatasetType.CIC_IDS2017: DatasetAdapterMetadata(
        dataset_name="CIC-IDS2017 (Canadian Institute for Cybersecurity)",
        license_type="Academic Research / Non-Commercial Evaluation License",
        citation="Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP.",
        status="PENDING_LOCAL_DOWNLOAD",
        notes="Dataset files must be obtained directly from UNB CIC portal. No synthetic data is fabricated."
    ),
    PublicDatasetType.UNSW_NB15: DatasetAdapterMetadata(
        dataset_name="UNSW-NB15 (Australian Centre for Cyber Security)",
        license_type="Academic & Educational Research License",
        citation="Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems. MilCIS.",
        status="PENDING_LOCAL_DOWNLOAD",
        notes="Dataset files must be obtained directly from UNSW Canberra Cyber portal. No synthetic data is fabricated."
    )
}

# Label Mappings: Public labels -> Suraksha AI ThreatCategory
CIC_IDS2017_LABEL_MAP: Dict[str, Tuple[ThreatCategory, EventType]] = {
    "BENIGN": (ThreatCategory.NONE, EventType.AUTH_SUCCESS),
    "PortScan": (ThreatCategory.LATERAL_MOVEMENT, EventType.PORT_SCAN),
    "SSH-Patator": (ThreatCategory.BRUTE_FORCE, EventType.LOGIN_FAILED),
    "FTP-Patator": (ThreatCategory.BRUTE_FORCE, EventType.LOGIN_FAILED),
    "Bot": (ThreatCategory.C2_ACTIVITY, EventType.C2_BEACON),
    "DDoS": (ThreatCategory.UNUSUAL_DATA_TRANSFER, EventType.BYTES_OUT),
    "DoS Hulk": (ThreatCategory.UNUSUAL_DATA_TRANSFER, EventType.BYTES_OUT),
    "DoS GoldenEye": (ThreatCategory.UNUSUAL_DATA_TRANSFER, EventType.BYTES_OUT),
}

UNSW_NB15_LABEL_MAP: Dict[str, Tuple[ThreatCategory, EventType]] = {
    "Normal": (ThreatCategory.NONE, EventType.AUTH_SUCCESS),
    "Reconnaissance": (ThreatCategory.LATERAL_MOVEMENT, EventType.PORT_SCAN),
    "Backdoor": (ThreatCategory.C2_ACTIVITY, EventType.C2_BEACON),
    "Exploits": (ThreatCategory.PRIVILEGE_ESCALATION, EventType.SUDO_EXEC),
    "Fuzzers": (ThreatCategory.BRUTE_FORCE, EventType.LOGIN_FAILED),
    "Generic": (ThreatCategory.SUSPICIOUS_LOGIN, EventType.SUSPICIOUS_LOGIN),
}


class PublicDatasetAdapter:
    """
    Translates raw feature records from CIC-IDS2017 or UNSW-NB15 CSV/JSON into
    Suraksha AI NormalizedEvent schema. Strictly decoupled from core production pipeline.
    """
    @staticmethod
    def get_metadata(dataset_type: PublicDatasetType) -> DatasetAdapterMetadata:
        return DATASET_METADATA[dataset_type]

    @classmethod
    def adapt_cic_ids2017_record(cls, record: Dict[str, Any], record_idx: int = 1) -> Tuple[NormalizedEvent, ThreatCategory]:
        """
        Adapts a CIC-IDS2017 flow record into NormalizedEvent.
        Expected raw fields (flexible keys): 'Source IP', 'Destination IP', 'Label', 'Flow Duration', etc.
        """
        raw_label = str(record.get("Label") or record.get("label") or "BENIGN").strip()
        threat_cat, event_type = CIC_IDS2017_LABEL_MAP.get(raw_label, (ThreatCategory.NONE, EventType.AUTH_SUCCESS))

        source_ip = str(record.get("Source IP") or record.get("src_ip") or "192.168.10.50").strip()
        dest_ip = str(record.get("Destination IP") or record.get("dst_ip") or "192.168.10.1").strip()
        payload_metric = float(record.get("Total Length of Fwd Packets") or record.get("payload_metric") or 1.0)

        norm_evt = NormalizedEvent(
            event_id=f"CIC-2017-{record_idx:06d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            destination_ip=dest_ip,
            user_id="cic_external_user",
            event_type=event_type,
            asset_id="cic-test-node",
            asset_criticality=AssetCriticality.MEDIUM,
            payload_metric=payload_metric,
            details=f"CIC-IDS2017 Flow Record: {raw_label}"
        )
        return norm_evt, threat_cat

    @classmethod
    def adapt_unsw_nb15_record(cls, record: Dict[str, Any], record_idx: int = 1) -> Tuple[NormalizedEvent, ThreatCategory]:
        """
        Adapts a UNSW-NB15 network flow record into NormalizedEvent.
        Expected raw fields: 'srcip', 'dstip', 'attack_cat', 'sbytes', etc.
        """
        attack_cat = str(record.get("attack_cat") or record.get("label_desc") or "Normal").strip()
        threat_cat, event_type = UNSW_NB15_LABEL_MAP.get(attack_cat, (ThreatCategory.NONE, EventType.AUTH_SUCCESS))

        source_ip = str(record.get("srcip") or record.get("src_ip") or "10.40.182.1").strip()
        dest_ip = str(record.get("dstip") or record.get("dst_ip") or "10.40.182.3").strip()
        sbytes = float(record.get("sbytes") or record.get("payload_metric") or 1.0)

        norm_evt = NormalizedEvent(
            event_id=f"UNSW-NB15-{record_idx:06d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            destination_ip=dest_ip,
            user_id="unsw_net_entity",
            event_type=event_type,
            asset_id="unsw-test-node",
            asset_criticality=AssetCriticality.LOW,
            payload_metric=sbytes / 1024.0, # convert to KB/MB
            details=f"UNSW-NB15 Flow Record: {attack_cat}"
        )
        return norm_evt, threat_cat
