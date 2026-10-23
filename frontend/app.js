const API_BASE = ""; // Relative path to FastAPI server

let incidentsCache = [];

document.addEventListener("DOMContentLoaded", () => {
    startClock();
    loadDashboardState();
    loadIncidents();
    loadResponses();
    loadAuditLogs();
    
    // Auto refresh every 4 seconds
    setInterval(loadDashboardState, 4000);
    setInterval(loadIncidents, 4000);
});

function startClock() {
    setInterval(() => {
        const now = new Date();
        document.getElementById("clock").innerText = now.toUTCString().split(" ")[4] + " UTC";
    }, 1000);
}

// Visual Pipeline Node Animation
function triggerPipelineGlow() {
    for (let i = 1; i <= 9; i++) {
        setTimeout(() => {
            const node = document.getElementById(`node-${i}`);
            if (node) {
                node.classList.add("glow");
                setTimeout(() => node.classList.remove("glow"), 500);
            }
        }, i * 150);
    }
}

// Tab Switching
function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));
    
    event.currentTarget.classList.add("active");
    document.getElementById(tabId).classList.add("active");

    if (tabId === "auditTab") loadAuditLogs();
    if (tabId === "responseTab") loadResponses();
    if (tabId === "evalTab") loadEvaluationReport();
}

// Load System State & Metrics
// Load System State, SQLite Persistence Metrics & Live Telemetry Stats
async function loadDashboardState() {
    try {
        const res = await fetch(`${API_BASE}/api/system/state`);
        const data = await res.json();

        document.getElementById("metricIncidents").innerText = data.total_incidents || 0;
        document.getElementById("metricBlockedIPs").innerText = (data.blocked_ips || []).length;
        document.getElementById("metricSuspendedUsers").innerText = (data.suspended_users || []).length;
        document.getElementById("metricIsolatedHosts").innerText = (data.isolated_hosts || []).length;
        if (document.getElementById("metricPersistedEvents")) {
            document.getElementById("metricPersistedEvents").innerText = data.total_telemetry_events || 0;
        }

        if (document.getElementById("dbPathDisplay") && data.database_path) {
            document.getElementById("dbPathDisplay").innerText = data.database_path;
        }

        if (document.getElementById("syslogStatus") && data.syslog_listener) {
            document.getElementById("syslogStatus").innerText = data.syslog_listener.enabled
                ? `Active (${data.syslog_listener.host}:${data.syslog_listener.port})`
                : "Disabled (Default)";
        }

        // Render Enforcements
        const stateList = document.getElementById("activeEnforcementsList");
        let html = "";

        data.blocked_ips.forEach(ip => {
            html += `<div class="state-tag"><i class="fa-solid fa-ban text-red"></i> Blocked IP: ${ip}</div>`;
        });
        data.suspended_users.forEach(u => {
            html += `<div class="state-tag"><i class="fa-solid fa-user-slash text-amber"></i> Suspended User: ${u}</div>`;
        });
        data.isolated_hosts.forEach(h => {
            html += `<div class="state-tag"><i class="fa-solid fa-network-wired text-cyan"></i> Isolated Endpoint: ${h}</div>`;
        });

        if (!html) html = '<span class="empty-text">No active blocks or isolations.</span>';
        stateList.innerHTML = html;

        // Kill Switch status update
        updateKillSwitchUI(data.kill_switch.is_active);

        // Fetch Telemetry stats for latest timestamp
        loadTelemetryStats();
    } catch (e) {
        console.error("Error loading dashboard state:", e);
    }
}

async function loadTelemetryStats() {
    try {
        const res = await fetch(`${API_BASE}/api/telemetry/stats`);
        if (res.ok) {
            const stats = await res.json();
            const rawEl = document.getElementById("metricRawEvents");
            if (rawEl) {
                rawEl.innerText = stats.total_raw_events ?? stats.total_persisted_events ?? 0;
            }
            const dupEl = document.getElementById("metricDupsSuppressed");
            if (dupEl) {
                dupEl.innerText = stats.total_duplicates_suppressed ?? 0;
            }
            const timeEl = document.getElementById("lastIngestTime");
            if (timeEl) {
                if (stats.latest_event && stats.latest_event.timestamp) {
                    timeEl.innerText = stats.latest_event.timestamp;
                } else if (stats.total_raw_events > 0) {
                    timeEl.innerText = `${stats.total_raw_events} raw events (${stats.total_duplicates_suppressed} dups)`;
                }
            }
        }
    } catch (e) {
        // Silently ignore stats fetch failure
    }
}

// Single Event API Demonstration Trigger
async function injectSingleEventDemo() {
    triggerPipelineGlow();
    const sampleEvent = {
        raw_id: "RT-" + Math.random().toString(36).substring(2, 8).toUpperCase(),
        timestamp: new Date().toISOString(),
        source_ip: "198.51.100." + Math.floor(Math.random() * 200 + 10),
        user_id: "field_agent_" + Math.floor(Math.random() * 50 + 1),
        event_type: "LOGIN_FAILED",
        asset_id: "cloud-portal-auth",
        asset_criticality: "HIGH",
        payload_metric: 6.0,
        details: "Real-time single telemetry event via POST /api/telemetry/event"
    };

    try {
        const res = await fetch(`${API_BASE}/api/telemetry/event`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(sampleEvent)
        });
        const data = await res.json();
        alert(`Single Event Ingested! Event ID: ${data.normalized_event.event_id}\nThreat: ${data.threat_detected ? (data.incident ? data.incident.incident_id : 'Detected') : 'Normal'}\nPersisted to SQLite.`);
        loadDashboardState();
        loadIncidents();
    } catch (e) {
        alert("Error in single event ingestion: " + e);
    }
}

// Webhook API Demonstration Trigger
async function injectWebhookDemo() {
    triggerPipelineGlow();
    const webhookPayload = {
        src_ip: "10.0.8." + Math.floor(Math.random() * 100 + 1),
        user: "svc_database_sync",
        action: "BYTES_OUT",
        host: "central-sql-01",
        asset_criticality: "HIGH",
        bytes: 850.0,
        description: "External generic JSON webhook telemetry from edge sensor"
    };

    try {
        const res = await fetch(`${API_BASE}/api/telemetry/webhook`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(webhookPayload)
        });
        const data = await res.json();
        alert(`Webhook Ingested! Status: ${res.status}\nTarget: ${data.normalized_event.source_ip}\nIncident: ${data.incident ? data.incident.incident_id : 'None'}`);
        loadDashboardState();
        loadIncidents();
    } catch (e) {
        alert("Error in webhook ingestion: " + e);
    }
}

// Toggle Emergency Kill Switch
async function toggleKillSwitch() {
    try {
        const statusRes = await fetch(`${API_BASE}/api/kill-switch/status`);
        const currentState = await statusRes.json();

        const newActiveState = !currentState.is_active;

        const res = await fetch(`${API_BASE}/api/kill-switch/toggle`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-User-Role": "ADMIN",
                "X-User-Id": "admin_dash"
            },
            body: JSON.stringify({ enable: newActiveState })
        });
        const data = await res.json();
        updateKillSwitchUI(data.status === "ACTIVE");
        loadDashboardState();
        loadIncidents();
    } catch (e) {
        alert("Error toggling Kill Switch: " + e);
    }
}

function updateKillSwitchUI(isActive) {
    const box = document.getElementById("killSwitchBox");
    const badge = document.getElementById("ksStatusBadge");
    const btnText = document.getElementById("ksBtnText");

    if (isActive) {
        box.classList.add("active-ks");
        badge.innerText = "ACTIVE (AUTOMATED ACTIONS HALTED)";
        btnText.innerText = "DISENGAGE KILL SWITCH";
    } else {
        box.classList.remove("active-ks");
        badge.innerText = "INACTIVE";
        btnText.innerText = "ENGAGE KILL SWITCH";
    }
}

// Inject Batch Telemetry Stream File
async function injectTelemetryStream() {
    triggerPipelineGlow();
    try {
        const res = await fetch(`${API_BASE}/api/simulator/inject-stream`, { method: "POST" });
        const data = await res.json();
        alert(`Successfully ingested ${data.total_stream_events} stream events through deduplication, correlation & policy pipeline!`);
        setTimeout(() => {
            loadDashboardState();
            loadIncidents();
            loadResponses();
        }, 600);
    } catch (e) {
        alert("Error ingesting telemetry stream: " + e);
    }
}

// Inject Attack Simulation
async function injectAttack(attackType) {
    triggerPipelineGlow();
    try {
        const res = await fetch(`${API_BASE}/api/simulator/inject-attack?attack_type=${attackType}`, {
            method: "POST"
        });
        const data = await res.json();
        
        setTimeout(() => {
            loadDashboardState();
            loadIncidents();
            loadResponses();
        }, 600);
    } catch (e) {
        alert("Error injecting attack: " + e);
    }
}

// Load Incidents Table
async function loadIncidents() {
    try {
        const res = await fetch(`${API_BASE}/api/incidents`);
        const incidents = await res.json();
        incidentsCache = incidents;
        
        document.getElementById("incCount").innerText = incidents.length;
        const tbody = document.getElementById("incidentsTableBody");

        if (incidents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-td">No incidents recorded. Ingest stream or inject attack!</td></tr>';
            return;
        }

        let html = "";
        incidents.forEach(inc => {
            let actionBtn = "";
            if (inc.action_executed) {
                actionBtn = `<span class="badge badge-LOW"><i class="fa-solid fa-check"></i> Executed</span>`;
            } else if (inc.status === "FALSE_POSITIVE") {
                actionBtn = `<span class="badge badge-MEDIUM"><i class="fa-solid fa-xmark"></i> Denied</span>`;
            } else {
                actionBtn = `
                    <button class="action-btn-approve" onclick="approveIncident('${inc.incident_id}', true)"><i class="fa-solid fa-check"></i> Approve</button>
                    <button class="action-btn-deny" onclick="approveIncident('${inc.incident_id}', false)"><i class="fa-solid fa-xmark"></i></button>
                `;
            }

            const behaviorBadge = inc.is_anomalous
                ? `<span class="badge badge-abnormal"><i class="fa-solid fa-triangle-exclamation"></i> ABNORMAL</span>`
                : `<span class="badge badge-normal"><i class="fa-solid fa-circle-check"></i> NORMAL</span>`;

            let categoriesStr = inc.threat_category;
            if (inc.threat_categories && inc.threat_categories.length > 1) {
                categoriesStr = inc.threat_categories.join(", ");
            }

            const statusBadge = `<span class="tier-badge tier-${inc.status === 'NEW' ? 'TIER_C' : 'TIER_A'}">${inc.status}</span>`;

            html += `
                <tr>
                    <td><strong>${inc.incident_id}</strong></td>
                    <td>${behaviorBadge}</td>
                    <td><span class="badge badge-${inc.severity}">${categoriesStr}</span></td>
                    <td><code>${inc.source_ip}</code></td>
                    <td><span class="risk-pill">${inc.risk_score} <small>(${Math.round(inc.confidence_score*100)}%)</small></span></td>
                    <td><span class="tier-badge tier-${inc.decision_tier}">${inc.decision_tier}</span></td>
                    <td>${statusBadge}</td>
                    <td>
                        <button class="evidence-btn" onclick="showEvidenceModal('${inc.incident_id}')"><i class="fa-solid fa-clock-rotate-left"></i> Timeline</button>
                        ${inc.status === 'NEW' ? `<button class="investigate-btn" onclick="investigateIncident('${inc.incident_id}')"><i class="fa-solid fa-magnifying-glass"></i></button>` : ''}
                        ${actionBtn}
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (e) {
        console.error("Error loading incidents:", e);
    }
}

// Mark Incident Under Investigation
async function investigateIncident(incidentId) {
    try {
        const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/investigate`, {
            method: "POST",
            headers: { "X-User-Role": "ANALYST", "X-User-Id": "analyst_ui" }
        });
        const data = await res.json();
        loadIncidents();
    } catch (e) {
        alert("Error investigating incident: " + e);
    }
}

// Show Evidence & Timeline Modal
function showEvidenceModal(incidentId) {
    const inc = incidentsCache.find(i => i.incident_id === incidentId);
    if (!inc) return;

    const modalContent = document.getElementById("modalEvidenceContent");
    
    let whyHtml = "";
    if (inc.why_evidence && inc.why_evidence.length > 0) {
        inc.why_evidence.forEach(bullet => {
            whyHtml += `<div class="why-bullet-item"><i class="fa-solid fa-circle-info text-amber"></i> ${bullet}</div>`;
        });
    } else {
        whyHtml = `<p class="text-muted">No explicit risk drivers.</p>`;
    }

    let timelineHtml = "";
    if (inc.timeline && inc.timeline.length > 0) {
        inc.timeline.forEach(step => {
            const timeStr = step.timestamp ? step.timestamp.split("T")[1].substring(0, 8) : "";
            timelineHtml += `
                <div class="timeline-item">
                    <div class="timeline-time">${timeStr} UTC</div>
                    <div><strong>${step.event_type}</strong> - ${step.description}</div>
                </div>
            `;
        });
    } else {
        timelineHtml = `<p class="text-muted">No timeline recorded.</p>`;
    }

    let evidenceHtml = `
        <p style="margin-bottom: 8px;"><strong>Incident ID:</strong> ${inc.incident_id} (<strong>${inc.threat_category}</strong>)</p>
        <p style="margin-bottom: 8px;"><strong>Correlated Events Count:</strong> ${inc.related_events ? inc.related_events.length : 1} | <strong>Status:</strong> ${inc.status}</p>
        <p style="margin-bottom: 12px;"><strong>Risk Score:</strong> ${inc.risk_score} / 100 | <strong>Confidence:</strong> ${Math.round(inc.confidence_score*100)}%</p>
        
        <h4 style="color: var(--accent-amber); margin-top: 14px; margin-bottom: 8px;"><i class="fa-solid fa-list-check"></i> "Why" Risk Evidence Explanation:</h4>
        ${whyHtml}

        <h4 style="color: var(--primary-cyan); margin-top: 16px; margin-bottom: 8px;"><i class="fa-solid fa-clock-rotate-left"></i> Correlated Event Timeline:</h4>
        ${timelineHtml}
    `;

    modalContent.innerHTML = evidenceHtml;
    document.getElementById("evidenceModal").classList.add("active");
}

function closeModal() {
    document.getElementById("evidenceModal").classList.remove("active");
}

function closeEvidenceModal(e) {
    if (e.target.id === "evidenceModal") closeModal();
}

// Approve / Deny Incident Response Action
async function approveIncident(incidentId, approved) {
    try {
        const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/approve`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-User-Role": "ANALYST",
                "X-User-Id": "analyst_ui"
            },
            body: JSON.stringify({ approved: approved, reason: "Suraksha AI Analyst manual review" })
        });
        const data = await res.json();
        loadDashboardState();
        loadIncidents();
        loadResponses();
    } catch (e) {
        alert("Error handling approval: " + e);
    }
}

// Load Response Records Table
async function loadResponses() {
    try {
        const res = await fetch(`${API_BASE}/api/response/records`);
        const records = await res.json();

        document.getElementById("actCount").innerText = records.length;
        const tbody = document.getElementById("responsesTableBody");

        if (records.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-td">No response actions executed yet.</td></tr>';
            return;
        }

        let html = "";
        records.forEach(rec => {
            let rollbackBtn = "-";
            if (rec.is_reversible && !rec.rolled_back) {
                rollbackBtn = `<button class="action-btn-rollback" onclick="rollbackAction('${rec.action_id}')"><i class="fa-solid fa-rotate-left"></i> Rollback</button>`;
            } else if (rec.rolled_back) {
                rollbackBtn = `<span class="badge badge-MEDIUM">Rolled Back</span>`;
            }

            html += `
                <tr>
                    <td><strong>${rec.action_id}</strong></td>
                    <td><code>${rec.action_type}</code></td>
                    <td><code>${rec.target}</code></td>
                    <td>${rec.executed_by}</td>
                    <td><span class="badge badge-${rec.verification_status === 'PASSED' ? 'LOW' : 'HIGH'}">${rec.verification_status}</span></td>
                    <td><code>${rec.status}</code></td>
                    <td>${rollbackBtn}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (e) {
        console.error("Error loading responses:", e);
    }
}

// Rollback Response Action
async function rollbackAction(actionId) {
    if (!confirm(`Are you sure you want to rollback action ${actionId}?`)) return;

    try {
        const res = await fetch(`${API_BASE}/api/response/${actionId}/rollback`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-User-Role": "ADMIN",
                "X-User-Id": "admin_ui"
            },
            body: JSON.stringify({ reason: "Dashboard manual rollback" })
        });
        const data = await res.json();
        alert(data.message);
        loadDashboardState();
        loadIncidents();
        loadResponses();
    } catch (e) {
        alert("Error performing rollback: " + e);
    }
}

// Load Audit Logs Table
async function loadAuditLogs() {
    try {
        const cat = document.getElementById("auditCategoryFilter").value;
        const res = await fetch(`${API_BASE}/api/audit?category=${cat}`);
        const logs = await res.json();

        const tbody = document.getElementById("auditTableBody");
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-td">No audit entries found.</td></tr>';
            return;
        }

        let html = "";
        logs.forEach(log => {
            const timeStr = log.timestamp.split("T")[1].substring(0, 8);
            html += `
                <tr>
                    <td><code>${timeStr}</code></td>
                    <td>${log.actor}</td>
                    <td><span class="tier-badge tier-TIER_A">${log.role}</span></td>
                    <td><strong>${log.action_category}</strong></td>
                    <td>${log.description}</td>
                    <td><code>${log.target_resource}</code></td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (e) {
        console.error("Error loading audit logs:", e);
    }
}

// --- Phase 5: Detection Quality Evaluation UI Functions ---

async function loadEvaluationReport() {
    try {
        const res = await fetch(`${API_BASE}/api/evaluation/latest`);
        if (!res.ok) return;
        const report = await res.json();
        renderEvaluationReport(report);
    } catch (e) {
        console.error("Error loading evaluation report:", e);
    }
}

async function triggerEvaluationBenchmark() {
    const btn = document.getElementById("runEvalBtn");
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running Benchmark...';
    try {
        const res = await fetch(`${API_BASE}/api/evaluation/run`, {
            method: "POST",
            headers: {
                "X-Role": "ADMIN",
                "X-User-Id": "admin_eval"
            }
        });
        const report = await res.json();
        renderEvaluationReport(report);
        alert("Detection Benchmark Complete! Report updated.");
    } catch (e) {
        alert("Error running benchmark: " + e);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-play"></i> Run Detection Benchmark';
    }
}

function renderEvaluationReport(report) {
    if (!report || !report.overall_hybrid_metrics) return;
    const hybridM = report.overall_hybrid_metrics.metrics;
    const corr = report.incident_correlation_evaluation;

    // Metadata & Status
    if (report.evaluation_metadata) {
        const timeEl = document.getElementById("evalTimestamp");
        if (timeEl && report.evaluation_metadata.timestamp) {
            timeEl.innerText = new Date(report.evaluation_metadata.timestamp).toUTCString();
        }
    }

    // Stream Deduplication Metrics (Requirement B, C & E)
    if (report.raw_stream_deduplication_metrics) {
        const sm = report.raw_stream_deduplication_metrics;
        const rawEl = document.getElementById("evalStreamRaw");
        if (rawEl) rawEl.innerText = sm.raw_events_received ?? "--";
        const unqEl = document.getElementById("evalStreamUnique");
        if (unqEl) unqEl.innerText = sm.unique_events_analyzed ?? "--";
        const dupEl = document.getElementById("evalStreamDups");
        if (dupEl) dupEl.innerText = sm.duplicates_suppressed ?? "--";
        const rateEl = document.getElementById("evalStreamDedupRate");
        if (rateEl) rateEl.innerText = (sm.deduplication_rate_pct ?? 0).toFixed(1) + "%";
    }

    document.getElementById("evalPrecision").innerText = (hybridM.precision * 100).toFixed(1) + "%";
    document.getElementById("evalRecall").innerText = (hybridM.recall * 100).toFixed(1) + "%";
    document.getElementById("evalF1").innerText = hybridM.f1_score.toFixed(4);
    document.getElementById("evalCorrelationAcc").innerText = (corr.grouping_accuracy * 100).toFixed(1) + "%";

    // Pipeline Comparison Table
    const pipe = report.pipeline_comparison;
    const compTbody = document.getElementById("pipelineComparisonTbody");
    compTbody.innerHTML = `
        <tr>
            <td><strong>Deterministic Rules Only</strong></td>
            <td>${(pipe.rules_only.metrics.precision * 100).toFixed(1)}%</td>
            <td>${(pipe.rules_only.metrics.recall * 100).toFixed(1)}%</td>
            <td>${pipe.rules_only.metrics.f1_score.toFixed(4)}</td>
            <td>${(pipe.rules_only.metrics.false_positive_rate * 100).toFixed(1)}%</td>
            <td>${(pipe.rules_only.metrics.accuracy * 100).toFixed(1)}%</td>
        </tr>
        <tr>
            <td><strong>ML IsolationForest Only</strong></td>
            <td>${(pipe.ml_only.metrics.precision * 100).toFixed(1)}%</td>
            <td>${(pipe.ml_only.metrics.recall * 100).toFixed(1)}%</td>
            <td>${pipe.ml_only.metrics.f1_score.toFixed(4)}</td>
            <td>${(pipe.ml_only.metrics.false_positive_rate * 100).toFixed(1)}%</td>
            <td>${(pipe.ml_only.metrics.accuracy * 100).toFixed(1)}%</td>
        </tr>
        <tr style="background: rgba(0, 242, 254, 0.08); font-weight: bold;">
            <td><i class="fa-solid fa-star text-cyan"></i> <strong>Hybrid Pipeline (Suraksha AI)</strong></td>
            <td class="text-cyan">${(hybridM.precision * 100).toFixed(1)}%</td>
            <td class="text-emerald">${(hybridM.recall * 100).toFixed(1)}%</td>
            <td class="text-purple">${hybridM.f1_score.toFixed(4)}</td>
            <td>${(hybridM.false_positive_rate * 100).toFixed(1)}%</td>
            <td>${(hybridM.accuracy * 100).toFixed(1)}%</td>
        </tr>
    `;

    // Per-Category Breakdown
    const perCat = report.per_category_metrics;
    const perCatTbody = document.getElementById("perCategoryTbody");
    let perCatHtml = "";
    for (const [catName, catData] of Object.entries(perCat)) {
        const cm = catData.confusion_matrix;
        const m = catData.metrics;
        perCatHtml += `
            <tr>
                <td><strong>${catName}</strong></td>
                <td>${catData.support}</td>
                <td><span class="text-emerald">${cm.tp}</span></td>
                <td><span class="text-amber">${cm.fp}</span></td>
                <td><span class="text-red">${cm.fn}</span></td>
                <td>${(m.precision * 100).toFixed(1)}%</td>
                <td>${(m.recall * 100).toFixed(1)}%</td>
                <td>${m.f1_score.toFixed(4)}</td>
            </tr>
        `;
    }
    perCatTbody.innerHTML = perCatHtml;
}
