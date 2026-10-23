import os
import tempfile
import pytest
import sqlite3
from backend.database import init_db, DatabaseManager
from backend.response.kill_switch import EmergencyKillSwitch

@pytest.fixture(autouse=True)
def clean_test_environment(tmp_path, monkeypatch):
    """
    Guarantees isolated SQLite test database for each test to prevent test state cross-contamination.
    """
    test_db = str(tmp_path / "test_suraksha.db")
    monkeypatch.setenv("SURAKSHA_DB_PATH", test_db)
    
    # Initialize schema in temporary database
    init_db(test_db)
    
    # Ensure kill switch is disabled for clean baseline
    EmergencyKillSwitch.disable()
    
    # Reset singletons if imported in main
    import backend.main as main_mod
    main_mod.db_manager = DatabaseManager(test_db)
    main_mod.incident_manager = main_mod.IncidentManager(db=main_mod.db_manager)
    main_mod.response_executor = main_mod.ResponseExecutor(db=main_mod.db_manager)
    main_mod.audit_logger = main_mod.AuditLogger(db=main_mod.db_manager)
    
    yield
    
    EmergencyKillSwitch.disable()
