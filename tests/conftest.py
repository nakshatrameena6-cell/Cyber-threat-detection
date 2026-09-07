"""Pytest fixtures configuration."""
import os
import sys
import pytest

# Add src and root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

@pytest.fixture
def tmp_audit_log(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    return str(log_file)

@pytest.fixture
def tmp_kill_switch(tmp_path):
    ks_file = tmp_path / "test_kill_switch.yaml"
    return str(ks_file)
