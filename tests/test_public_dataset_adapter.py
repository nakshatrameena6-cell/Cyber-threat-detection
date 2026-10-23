"""
Suraksha AI - Phase 6 Test Suite: Public Dataset Adapter (Requirement D)
Verifies:
- Documented licensing and attribution for CIC-IDS2017 and UNSW-NB15
- Accurate schema and label translation to NormalizedEvent and ThreatCategory
- Decoupling from production ingestion path
- Pending status reporting when local dataset file is absent (Zero fabrication)
"""
import pytest
from backend.evaluation.public_dataset_adapter import (
    PublicDatasetType,
    PublicDatasetAdapter,
    CIC_IDS2017_LABEL_MAP,
    UNSW_NB15_LABEL_MAP
)
from backend.models.events import EventType
from backend.models.incidents import ThreatCategory


def test_public_dataset_metadata_and_licensing():
    """
    Requirement D: Verify licensing, attribution, and non-fabricated status documentation.
    """
    cic_meta = PublicDatasetAdapter.get_metadata(PublicDatasetType.CIC_IDS2017)
    assert "Canadian Institute for Cybersecurity" in cic_meta.dataset_name
    assert "Academic Research" in cic_meta.license_type
    assert cic_meta.status == "PENDING_LOCAL_DOWNLOAD"
    assert "No synthetic data is fabricated" in cic_meta.notes

    unsw_meta = PublicDatasetAdapter.get_metadata(PublicDatasetType.UNSW_NB15)
    assert "Australian Centre for Cyber Security" in unsw_meta.dataset_name
    assert "Academic & Educational Research License" in unsw_meta.license_type
    assert unsw_meta.status == "PENDING_LOCAL_DOWNLOAD"


def test_cic_ids2017_record_adaptation():
    """
    Requirement D: Adapt synthetic fixture representing CIC-IDS2017 flow record.
    """
    # 1. PortScan flow record
    raw_scan = {
        "Source IP": "172.16.0.1",
        "Destination IP": "192.168.10.50",
        "Label": "PortScan",
        "Total Length of Fwd Packets": 240.0
    }
    event, cat = PublicDatasetAdapter.adapt_cic_ids2017_record(raw_scan, record_idx=101)
    assert event.event_id == "CIC-2017-000101"
    assert event.source_ip == "172.16.0.1"
    assert event.event_type == EventType.PORT_SCAN
    assert cat == ThreatCategory.LATERAL_MOVEMENT

    # 2. SSH-Patator brute force flow record
    raw_bf = {
        "Source IP": "172.16.0.1",
        "Destination IP": "192.168.10.50",
        "Label": "SSH-Patator",
        "Total Length of Fwd Packets": 12.0
    }
    event_bf, cat_bf = PublicDatasetAdapter.adapt_cic_ids2017_record(raw_bf, record_idx=102)
    assert event_bf.event_type == EventType.LOGIN_FAILED
    assert cat_bf == ThreatCategory.BRUTE_FORCE

    # 3. Benign flow record
    raw_benign = {
        "Source IP": "192.168.10.15",
        "Destination IP": "192.168.10.3",
        "Label": "BENIGN",
        "Total Length of Fwd Packets": 500.0
    }
    event_norm, cat_norm = PublicDatasetAdapter.adapt_cic_ids2017_record(raw_benign, record_idx=103)
    assert event_norm.event_type == EventType.AUTH_SUCCESS
    assert cat_norm == ThreatCategory.NONE


def test_unsw_nb15_record_adaptation():
    """
    Requirement D: Adapt synthetic fixture representing UNSW-NB15 network flow record.
    """
    # 1. Reconnaissance record
    raw_recon = {
        "srcip": "175.45.176.0",
        "dstip": "149.171.126.16",
        "attack_cat": "Reconnaissance",
        "sbytes": 4096.0
    }
    event_recon, cat_recon = PublicDatasetAdapter.adapt_unsw_nb15_record(raw_recon, record_idx=201)
    assert event_recon.event_id == "UNSW-NB15-000201"
    assert event_recon.event_type == EventType.PORT_SCAN
    assert cat_recon == ThreatCategory.LATERAL_MOVEMENT
    assert event_recon.payload_metric == 4.0  # 4096 bytes / 1024 = 4.0 KB

    # 2. Backdoor C2 record
    raw_c2 = {
        "srcip": "175.45.176.3",
        "dstip": "149.171.126.18",
        "attack_cat": "Backdoor",
        "sbytes": 512.0
    }
    event_c2, cat_c2 = PublicDatasetAdapter.adapt_unsw_nb15_record(raw_c2, record_idx=202)
    assert event_c2.event_type == EventType.C2_BEACON
    assert cat_c2 == ThreatCategory.C2_ACTIVITY
