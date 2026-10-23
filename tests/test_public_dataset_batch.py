"""
Suraksha AI - Phase 7 Public Dataset Batch Processing & Generalization Tests (Requirement B)
Verifies PENDING_LOCAL_DATA status when files are absent, directory traversal protection,
CSV streaming/auditing, unknown label handling, and zero data leakage holdout evaluation.
"""
import os
import tempfile
import pytest
from backend.evaluation.public_dataset_adapter import (
    PublicDatasetType,
    PublicDatasetBatchEvaluator,
    PublicDatasetAdapter,
    DATASET_METADATA,
    DATASET_ACQUISITION_GUIDE
)


def test_public_dataset_pending_local_data_when_file_missing():
    """
    Verifies that when public dataset files are not present locally,
    the system reports explicit PENDING_LOCAL_DATA status with acquisition instructions
    and does NOT fabricate metrics or pretend evaluation occurred.
    """
    missing_path = "data/external/cic_ids2017/non_existent.csv"
    audit = PublicDatasetBatchEvaluator.audit_dataset(missing_path, PublicDatasetType.CIC_IDS2017)

    assert audit["status"] == "PENDING_LOCAL_DATA"
    assert audit["exists_locally"] is False
    assert "not present on local storage" in audit["message"]
    assert "No synthetic metrics fabricated" in audit["message"]
    assert "acquisition_guide" in audit
    assert audit["acquisition_guide"]["official_url"] == "https://www.unb.ca/cic/datasets/ids-2017.html"


def test_directory_traversal_protection():
    """Verifies that malicious directory traversal paths are rejected."""
    traversal_path = "../../etc/passwd"
    with pytest.raises(ValueError, match="Directory traversal detected"):
        PublicDatasetBatchEvaluator.validate_safe_path(traversal_path)

    traversal_path2 = "data/external/../../../windows/system32/cmd.exe"
    with pytest.raises(ValueError, match="Directory traversal detected"):
        PublicDatasetBatchEvaluator.validate_safe_path(traversal_path2)


def test_public_dataset_csv_audit_on_fixture():
    """Verifies schema audit, header extraction, and label distribution on synthetic CSV fixture."""
    csv_content = """Source IP,Destination IP,Label,Total Length of Fwd Packets
192.168.10.50,192.168.10.1,BENIGN,120
192.168.10.50,192.168.10.2,PortScan,500
192.168.10.50,192.168.10.3,PortScan,600
192.168.10.50,192.168.10.4,UNKNOWN_ZERO_DAY_EXPLOIT,999
"""
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", encoding="utf-8") as tmp:
        tmp.write(csv_content)
        tmp_path = tmp.name

    try:
        audit = PublicDatasetBatchEvaluator.audit_dataset(tmp_path, PublicDatasetType.CIC_IDS2017)
        assert audit["status"] == "READY_FOR_EVALUATION"
        assert audit["exists_locally"] is True
        assert audit["total_records_observed"] == 4
        assert audit["valid_records_count"] == 3
        assert audit["excluded_records_count"] == 1
        assert "UNKNOWN_ZERO_DAY_EXPLOIT" in audit["unsupported_labels"]
        assert audit["unsupported_labels"]["UNKNOWN_ZERO_DAY_EXPLOIT"] == 1
        assert audit["label_distribution"]["PortScan"] == 2
        assert audit["label_distribution"]["BENIGN"] == 1
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_leak_free_batch_evaluation_on_fixture():
    """
    Verifies that batch evaluation splits data deterministically into Train/Test partitions,
    fits IsolationForest strictly on the training partition, and produces validated metrics.
    """
    # Create synthetic dataset with 30 benign and 10 attack flows
    lines = ["Source IP,Destination IP,Label,Total Length of Fwd Packets\n"]
    for i in range(30):
        lines.append(f"192.168.10.50,192.168.10.{i+1},BENIGN,{100 + i}\n")
    for j in range(10):
        lines.append(f"192.168.10.50,192.168.10.{j+50},PortScan,{1500 + j*100}\n")

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", encoding="utf-8") as tmp:
        tmp.writelines(lines)
        tmp_path = tmp.name

    try:
        eval_result = PublicDatasetBatchEvaluator.evaluate_dataset(
            file_path=tmp_path,
            dataset_type=PublicDatasetType.CIC_IDS2017,
            train_ratio=0.75,
            random_seed=42
        )
        assert eval_result["status"] == "COMPLETED"
        assert eval_result["data_leakage_prevented"] is True
        assert eval_result["total_records_processed"] == 40
        assert eval_result["train_partition_size"] == 30
        assert eval_result["test_partition_size"] == 10
        assert "confusion_matrix" in eval_result
        assert "metrics" in eval_result

        cm = eval_result["confusion_matrix"]
        assert cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"] == 10 # Test partition size
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
