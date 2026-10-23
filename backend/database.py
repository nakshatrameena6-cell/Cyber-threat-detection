import os
import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set, Tuple

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "suraksha.db"
)

def get_db_path() -> str:
    return os.environ.get("SURAKSHA_DB_PATH", DEFAULT_DB_PATH)

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or get_db_path()
    if path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Foreign keys enabled for referential checks
    conn.execute("PRAGMA foreign_keys = OFF;") # Keep flexible for standalone test isolation
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db(db_path: Optional[str] = None):
    """
    Initializes SQLite schema for Suraksha AI Phase 4 persistence.
    Covers telemetry, incidents, event relationships, timelines, evidence,
    responses, pre-states, simulated enforcements, and audit logs.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    # 1. Telemetry Events
    cur.execute("""
    CREATE TABLE IF NOT EXISTS telemetry_events (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        user_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        asset_criticality TEXT NOT NULL,
        payload_metric REAL NOT NULL DEFAULT 0.0,
        details TEXT DEFAULT '',
        normalized_at TEXT NOT NULL,
        raw_json TEXT DEFAULT '{}',
        is_duplicate INTEGER DEFAULT 0
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_source_ip ON telemetry_events(source_ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_user_id ON telemetry_events(user_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events(timestamp);")

    # 2. Incidents
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        threat_category TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score REAL NOT NULL,
        confidence_score REAL NOT NULL,
        source_ip TEXT NOT NULL,
        user_id TEXT NOT NULL,
        affected_user TEXT DEFAULT '',
        asset_id TEXT NOT NULL,
        affected_endpoint TEXT DEFAULT '',
        details TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'NEW',
        created_at TEXT NOT NULL,
        first_seen TEXT DEFAULT '',
        last_seen TEXT DEFAULT '',
        recommended_action TEXT NOT NULL,
        decision_tier TEXT NOT NULL,
        action_executed INTEGER DEFAULT 0,
        assigned_to TEXT,
        is_anomalous INTEGER DEFAULT 1,
        verification_status TEXT DEFAULT 'NOT_VERIFIED',
        rollback_status TEXT DEFAULT 'NOT_ROLLED_BACK',
        duplicate_events_count INTEGER DEFAULT 0,
        updated_at TEXT NOT NULL
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);")

    # Safe migration for existing DB files
    try:
        cur.execute("ALTER TABLE incidents ADD COLUMN duplicate_events_count INTEGER DEFAULT 0;")
    except Exception:
        pass

    # 3. Incident-to-Event Relationship
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        correlated_at TEXT NOT NULL,
        UNIQUE(incident_id, event_id)
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_inc_events_inc_id ON incident_events(incident_id);")

    # 4. Incident Timeline
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_timelines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        threat_category TEXT NOT NULL,
        risk_score REAL NOT NULL,
        is_duplicate INTEGER DEFAULT 0
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_timelines_inc_id ON incident_timelines(incident_id);")

    try:
        cur.execute("ALTER TABLE incident_timelines ADD COLUMN is_duplicate INTEGER DEFAULT 0;")
    except Exception:
        pass

    # 5. Incident Evidence & Why Explanations
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        evidence_type TEXT NOT NULL, -- 'BEHAVIORAL' or 'WHY'
        evidence_text TEXT NOT NULL,
        UNIQUE(incident_id, evidence_type, evidence_text)
    );
    """)

    # 6. Incident Threat Categories
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_threat_categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        threat_category TEXT NOT NULL,
        UNIQUE(incident_id, threat_category)
    );
    """)

    # 7. Response Records
    cur.execute("""
    CREATE TABLE IF NOT EXISTS response_records (
        action_id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target TEXT NOT NULL,
        tier TEXT NOT NULL,
        status TEXT NOT NULL,
        verification_status TEXT NOT NULL DEFAULT 'NOT_VERIFIED',
        executed_by TEXT NOT NULL,
        execution_time TEXT NOT NULL,
        verification_time TEXT,
        is_reversible INTEGER DEFAULT 1,
        rolled_back INTEGER DEFAULT 0,
        details TEXT DEFAULT '',
        success INTEGER DEFAULT 1,
        gate_message TEXT DEFAULT ''
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_response_inc_id ON response_records(incident_id);")

    # 8. Pre-State Capture for Rollback
    cur.execute("""
    CREATE TABLE IF NOT EXISTS response_pre_states (
        action_id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        action_type TEXT NOT NULL,
        was_blocked INTEGER NOT NULL DEFAULT 0,
        was_suspended INTEGER NOT NULL DEFAULT 0,
        was_isolated INTEGER NOT NULL DEFAULT 0,
        timestamp TEXT NOT NULL
    );
    """)

    # 9. Active Simulated Enforcements
    cur.execute("""
    CREATE TABLE IF NOT EXISTS simulated_security_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        state_type TEXT NOT NULL, -- 'BLOCKED_IP', 'SUSPENDED_USER', 'ISOLATED_HOST'
        target_value TEXT NOT NULL,
        created_at TEXT NOT NULL,
        action_id TEXT,
        UNIQUE(state_type, target_value)
    );
    """)

    # 10. Audit Logs (Append-Only)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        audit_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        role TEXT NOT NULL,
        action_category TEXT NOT NULL,
        description TEXT NOT NULL,
        target_resource TEXT NOT NULL,
        metadata_json TEXT DEFAULT '{}'
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_logs(action_category);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")

    conn.commit()
    conn.close()


class DatabaseManager:
    """
    Lightweight, maintainable SQLite Data Access Layer for Suraksha AI.
    Handles transactions safely with parameterized queries and provides audit persistence guarantees.
    """
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_db_path()
        init_db(self.db_path)

    def initialize_db(self):
        init_db(self.db_path)

    def get_conn(self) -> sqlite3.Connection:
        return get_db_connection(self.db_path)

    # --- Telemetry ---
    def save_telemetry_event(self, event_dict: dict, raw_json: str = "{}", is_dup: bool = False) -> bool:
        conn = self.get_conn()
        try:
            with conn:
                conn.execute("""
                INSERT OR REPLACE INTO telemetry_events 
                (event_id, timestamp, source_ip, user_id, event_type, asset_id, asset_criticality, payload_metric, details, normalized_at, raw_json, is_duplicate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_dict["event_id"],
                    event_dict["timestamp"],
                    event_dict["source_ip"],
                    event_dict["user_id"],
                    str(event_dict["event_type"]),
                    event_dict["asset_id"],
                    str(event_dict["asset_criticality"]),
                    float(event_dict.get("payload_metric", 0.0)),
                    event_dict.get("details", ""),
                    event_dict.get("normalized_at", datetime.now(timezone.utc).isoformat()),
                    raw_json,
                    1 if is_dup else 0
                ))
            return True
        finally:
            conn.close()

    def get_telemetry_event(self, event_id: str) -> Optional[dict]:
        conn = self.get_conn()
        try:
            row = conn.execute("SELECT * FROM telemetry_events WHERE event_id = ?", (event_id,)).fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def get_latest_telemetry_event(self) -> Optional[dict]:
        conn = self.get_conn()
        try:
            row = conn.execute("SELECT * FROM telemetry_events ORDER BY normalized_at DESC LIMIT 1").fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def get_telemetry_count(self) -> int:
        conn = self.get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) as cnt FROM telemetry_events").fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    def get_telemetry_stats(self) -> dict:
        conn = self.get_conn()
        try:
            total_raw = conn.execute("SELECT COUNT(*) as cnt FROM telemetry_events").fetchone()["cnt"]
            total_dups = conn.execute("SELECT COUNT(*) as cnt FROM telemetry_events WHERE is_duplicate = 1").fetchone()["cnt"]
            total_unique = total_raw - total_dups
            # Calculate total duplicate observations linked into incidents
            cur_dup_inc = conn.execute("SELECT SUM(duplicate_events_count) as cnt FROM incidents").fetchone()["cnt"]
            correlated_dups = cur_dup_inc if cur_dup_inc else 0
            return {
                "total_raw_events": total_raw,
                "total_unique_events": total_unique,
                "total_duplicates_suppressed": total_dups,
                "duplicates_attached_to_incidents": correlated_dups,
                "deduplication_rate_pct": round((total_dups / total_raw * 100.0) if total_raw > 0 else 0.0, 2)
            }
        finally:
            conn.close()

    # --- Incidents ---
    def save_incident(self, inc_dict: dict) -> bool:
        conn = self.get_conn()
        now_str = datetime.now(timezone.utc).isoformat()
        try:
            with conn:
                conn.execute("""
                INSERT OR REPLACE INTO incidents
                (incident_id, event_id, threat_category, severity, risk_score, confidence_score,
                 source_ip, user_id, affected_user, asset_id, affected_endpoint, details,
                 status, created_at, first_seen, last_seen, recommended_action, decision_tier,
                 action_executed, assigned_to, is_anomalous, verification_status, rollback_status,
                 duplicate_events_count, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    inc_dict["incident_id"],
                    inc_dict["event_id"],
                    getattr(inc_dict["threat_category"], "value", str(inc_dict["threat_category"])),
                    getattr(inc_dict["severity"], "value", str(inc_dict["severity"])),
                    float(inc_dict["risk_score"]),
                    float(inc_dict["confidence_score"]),
                    inc_dict["source_ip"],
                    inc_dict["user_id"],
                    inc_dict.get("affected_user", inc_dict["user_id"]),
                    inc_dict["asset_id"],
                    inc_dict.get("affected_endpoint", inc_dict["asset_id"]),
                    inc_dict.get("details", ""),
                    getattr(inc_dict.get("status", "NEW"), "value", str(inc_dict.get("status", "NEW"))),
                    inc_dict["created_at"],
                    inc_dict.get("first_seen", inc_dict["created_at"]),
                    inc_dict.get("last_seen", inc_dict["created_at"]),
                    str(getattr(inc_dict["recommended_action"], "value", inc_dict["recommended_action"])),
                    str(getattr(inc_dict["decision_tier"], "value", inc_dict["decision_tier"])),
                    1 if inc_dict.get("action_executed") else 0,
                    inc_dict.get("assigned_to"),
                    1 if inc_dict.get("is_anomalous", True) else 0,
                    inc_dict.get("verification_status", "NOT_VERIFIED"),
                    inc_dict.get("rollback_status", "NOT_ROLLED_BACK"),
                    int(inc_dict.get("duplicate_events_count", 0)),
                    now_str
                ))

                # Save related events
                for eid in inc_dict.get("related_events", [inc_dict["event_id"]]):
                    conn.execute("""
                    INSERT OR IGNORE INTO incident_events (incident_id, event_id, correlated_at)
                    VALUES (?, ?, ?)
                    """, (inc_dict["incident_id"], eid, now_str))

                # Save threat categories
                for tc in inc_dict.get("threat_categories", [inc_dict["threat_category"]]):
                    tc_val = getattr(tc, "value", str(tc))
                    conn.execute("""
                    INSERT OR IGNORE INTO incident_threat_categories (incident_id, threat_category)
                    VALUES (?, ?)
                    """, (inc_dict["incident_id"], tc_val))

                # Save evidence
                for ev in inc_dict.get("behavioral_evidence", []):
                    conn.execute("""
                    INSERT OR IGNORE INTO incident_evidence (incident_id, evidence_type, evidence_text)
                    VALUES (?, 'BEHAVIORAL', ?)
                    """, (inc_dict["incident_id"], str(ev)))

                for why in inc_dict.get("why_evidence", []):
                    conn.execute("""
                    INSERT OR IGNORE INTO incident_evidence (incident_id, evidence_type, evidence_text)
                    VALUES (?, 'WHY', ?)
                    """, (inc_dict["incident_id"], str(why)))

                # Save timeline entries
                for item in inc_dict.get("timeline", []):
                    chk = conn.execute("""
                    SELECT id FROM incident_timelines 
                    WHERE incident_id = ? AND timestamp = ? AND event_id = ?
                    """, (inc_dict["incident_id"], item["timestamp"], item["event_id"])).fetchone()
                    if not chk:
                        conn.execute("""
                        INSERT INTO incident_timelines (incident_id, timestamp, event_id, event_type, description, threat_category, risk_score, is_duplicate)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            inc_dict["incident_id"],
                            item["timestamp"],
                            item["event_id"],
                            item.get("event_type", "EVENT"),
                            item.get("description", ""),
                            item.get("threat_category", str(inc_dict["threat_category"])),
                            float(item.get("risk_score", inc_dict["risk_score"])),
                            1 if item.get("is_duplicate", False) else 0
                        ))
            return True
        finally:
            conn.close()

    def get_incident(self, incident_id: str) -> Optional[dict]:
        conn = self.get_conn()
        try:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if not row:
                return None
            inc = dict(row)
            inc["action_executed"] = bool(inc["action_executed"])
            inc["is_anomalous"] = bool(inc["is_anomalous"])
            inc["duplicate_events_count"] = int(inc.get("duplicate_events_count", 0))

            # Load related events
            evt_rows = conn.execute("SELECT event_id FROM incident_events WHERE incident_id = ?", (incident_id,)).fetchall()
            inc["related_events"] = [r["event_id"] for r in evt_rows]

            # Load threat categories
            tc_rows = conn.execute("SELECT threat_category FROM incident_threat_categories WHERE incident_id = ?", (incident_id,)).fetchall()
            inc["threat_categories"] = [r["threat_category"] for r in tc_rows]
            if not inc["threat_categories"]:
                inc["threat_categories"] = [inc["threat_category"]]

            # Load evidence
            bev_rows = conn.execute("SELECT evidence_text FROM incident_evidence WHERE incident_id = ? AND evidence_type = 'BEHAVIORAL'", (incident_id,)).fetchall()
            inc["behavioral_evidence"] = [r["evidence_text"] for r in bev_rows]

            why_rows = conn.execute("SELECT evidence_text FROM incident_evidence WHERE incident_id = ? AND evidence_type = 'WHY'", (incident_id,)).fetchall()
            inc["why_evidence"] = [r["evidence_text"] for r in why_rows]

            # Load timeline
            tl_rows = conn.execute("SELECT * FROM incident_timelines WHERE incident_id = ? ORDER BY timestamp ASC, id ASC", (incident_id,)).fetchall()
            inc["timeline"] = [
                {
                    "timestamp": r["timestamp"],
                    "event_id": r["event_id"],
                    "event_type": r["event_type"],
                    "description": r["description"],
                    "threat_category": r["threat_category"],
                    "risk_score": r["risk_score"],
                    "is_duplicate": bool(r["is_duplicate"]) if "is_duplicate" in r.keys() else False
                }
                for r in tl_rows
            ]
            inc["suppressed_duplicates"] = [
                r["event_id"] for r in inc["timeline"] if r.get("is_duplicate") or r.get("event_type") == "DUPLICATE_OBSERVATION"
            ]

            return inc
        finally:
            conn.close()

    def list_incidents(self, status: Optional[str] = None) -> List[dict]:
        conn = self.get_conn()
        try:
            if status:
                rows = conn.execute("SELECT incident_id FROM incidents WHERE status = ? ORDER BY created_at DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT incident_id FROM incidents ORDER BY created_at DESC").fetchall()
            return [self.get_incident(r["incident_id"]) for r in rows if r["incident_id"]]
        finally:
            conn.close()

    def update_incident_status(self, incident_id: str, new_status: str, assigned_to: Optional[str] = None, timeline_item: Optional[dict] = None) -> bool:
        conn = self.get_conn()
        now_str = datetime.now(timezone.utc).isoformat()
        try:
            with conn:
                conn.execute("""
                UPDATE incidents 
                SET status = ?, assigned_to = COALESCE(?, assigned_to), updated_at = ?
                WHERE incident_id = ?
                """, (new_status, assigned_to, now_str, incident_id))

                if timeline_item:
                    conn.execute("""
                    INSERT INTO incident_timelines (incident_id, timestamp, event_id, event_type, description, threat_category, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        incident_id,
                        timeline_item.get("timestamp", now_str),
                        timeline_item.get("event_id", "SYS-UPDATE"),
                        timeline_item.get("event_type", "STATUS_CHANGE"),
                        timeline_item.get("description", f"Status changed to {new_status}"),
                        timeline_item.get("threat_category", "SYSTEM"),
                        float(timeline_item.get("risk_score", 0.0))
                    ))
            return True
        finally:
            conn.close()

    def mark_incident_action_executed(self, incident_id: str, new_status: str = "MITIGATED") -> bool:
        conn = self.get_conn()
        now_str = datetime.now(timezone.utc).isoformat()
        try:
            with conn:
                conn.execute("""
                UPDATE incidents 
                SET action_executed = 1, status = ?, updated_at = ?
                WHERE incident_id = ?
                """, (new_status, now_str, incident_id))
            return True
        finally:
            conn.close()

    # --- Response Records & Pre-States ---
    def save_response_record(self, record_dict: dict) -> bool:
        conn = self.get_conn()
        try:
            with conn:
                conn.execute("""
                INSERT OR REPLACE INTO response_records
                (action_id, incident_id, action_type, target, tier, status, verification_status,
                 executed_by, execution_time, verification_time, is_reversible, rolled_back, details, success, gate_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record_dict["action_id"],
                    record_dict["incident_id"],
                    getattr(record_dict["action_type"], "value", str(record_dict["action_type"])),
                    record_dict["target"],
                    getattr(record_dict["tier"], "value", str(record_dict["tier"])),
                    getattr(record_dict["status"], "value", str(record_dict["status"])),
                    getattr(record_dict.get("verification_status", "NOT_VERIFIED"), "value", str(record_dict.get("verification_status", "NOT_VERIFIED"))),
                    record_dict["executed_by"],
                    record_dict["execution_time"],
                    record_dict.get("verification_time"),
                    1 if record_dict.get("is_reversible", True) else 0,
                    1 if record_dict.get("rolled_back", False) else 0,
                    record_dict.get("details", ""),
                    1 if record_dict.get("success", True) else 0,
                    record_dict.get("gate_message", "")
                ))
            return True
        finally:
            conn.close()

    def get_response_record(self, action_id: str) -> Optional[dict]:
        conn = self.get_conn()
        try:
            row = conn.execute("SELECT * FROM response_records WHERE action_id = ?", (action_id,)).fetchone()
            if not row:
                return None
            rec = dict(row)
            rec["is_reversible"] = bool(rec["is_reversible"])
            rec["rolled_back"] = bool(rec["rolled_back"])
            rec["success"] = bool(rec["success"])
            return rec
        finally:
            conn.close()

    def list_response_records(self) -> List[dict]:
        conn = self.get_conn()
        try:
            rows = conn.execute("SELECT * FROM response_records ORDER BY execution_time DESC").fetchall()
            records = []
            for r in rows:
                rec = dict(r)
                rec["is_reversible"] = bool(rec["is_reversible"])
                rec["rolled_back"] = bool(rec["rolled_back"])
                rec["success"] = bool(rec["success"])
                records.append(rec)
            return records
        finally:
            conn.close()

    def save_pre_state(self, action_id: str, target: str, action_type: str, was_blocked: bool, was_suspended: bool, was_isolated: bool, timestamp: str) -> bool:
        conn = self.get_conn()
        try:
            with conn:
                conn.execute("""
                INSERT OR REPLACE INTO response_pre_states
                (action_id, target, action_type, was_blocked, was_suspended, was_isolated, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    action_id, target, action_type,
                    1 if was_blocked else 0,
                    1 if was_suspended else 0,
                    1 if was_isolated else 0,
                    timestamp
                ))
            return True
        finally:
            conn.close()

    def get_pre_state(self, action_id: str) -> Optional[dict]:
        conn = self.get_conn()
        try:
            row = conn.execute("SELECT * FROM response_pre_states WHERE action_id = ?", (action_id,)).fetchone()
            if not row:
                return None
            ps = dict(row)
            ps["was_blocked"] = bool(ps["was_blocked"])
            ps["was_suspended"] = bool(ps["was_suspended"])
            ps["was_isolated"] = bool(ps["was_isolated"])
            return ps
        finally:
            conn.close()

    # --- Simulated Security State ---
    def save_security_state(self, state_type: str, target_value: str, action_id: Optional[str] = None) -> bool:
        conn = self.get_conn()
        now_str = datetime.now(timezone.utc).isoformat()
        try:
            with conn:
                conn.execute("""
                INSERT OR IGNORE INTO simulated_security_state (state_type, target_value, created_at, action_id)
                VALUES (?, ?, ?, ?)
                """, (state_type, target_value, now_str, action_id))
            return True
        finally:
            conn.close()

    def remove_security_state(self, state_type: str, target_value: str) -> bool:
        conn = self.get_conn()
        try:
            with conn:
                conn.execute("""
                DELETE FROM simulated_security_state WHERE state_type = ? AND target_value = ?
                """, (state_type, target_value))
            return True
        finally:
            conn.close()

    def get_active_security_states(self) -> Dict[str, Set[str]]:
        conn = self.get_conn()
        try:
            rows = conn.execute("SELECT state_type, target_value FROM simulated_security_state").fetchall()
            states = {
                "blocked_ips": set(),
                "suspended_users": set(),
                "isolated_hosts": set()
            }
            for r in rows:
                st = r["state_type"]
                tv = r["target_value"]
                if st == "BLOCKED_IP":
                    states["blocked_ips"].add(tv)
                elif st == "SUSPENDED_USER":
                    states["suspended_users"].add(tv)
                elif st == "ISOLATED_HOST":
                    states["isolated_hosts"].add(tv)
            return states
        finally:
            conn.close()

    # --- Audit Logs (Append-Only) ---
    def save_audit_log(self, audit_dict: dict) -> bool:
        conn = self.get_conn()
        try:
            with conn:
                conn.execute("""
                INSERT INTO audit_logs
                (audit_id, timestamp, actor, role, action_category, description, target_resource, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    audit_dict["audit_id"],
                    audit_dict["timestamp"],
                    audit_dict["actor"],
                    audit_dict["role"],
                    audit_dict["action_category"],
                    audit_dict["description"],
                    audit_dict["target_resource"],
                    json.dumps(audit_dict.get("metadata", {}))
                ))
            return True
        finally:
            conn.close()

    def list_audit_logs(self, category: Optional[str] = None, actor: Optional[str] = None, limit: int = 100) -> List[dict]:
        conn = self.get_conn()
        try:
            query = "SELECT * FROM audit_logs"
            params = []
            conditions = []
            if category:
                conditions.append("UPPER(action_category) = ?")
                params.append(category.upper())
            if actor:
                conditions.append("LOWER(actor) = ?")
                params.append(actor.lower())

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, tuple(params)).fetchall()
            logs = []
            for r in rows:
                entry = dict(r)
                try:
                    entry["metadata"] = json.loads(entry["metadata_json"])
                except Exception:
                    entry["metadata"] = {}
                logs.append(entry)
            return logs
        finally:
            conn.close()

    def test_audit_persistence_available(self) -> bool:
        """
        Safety Gate 6: Verifies database connectivity and audit persistence readiness.
        """
        try:
            conn = self.get_conn()
            conn.execute("SELECT 1 FROM audit_logs LIMIT 1")
            conn.close()
            return True
        except Exception:
            return False
