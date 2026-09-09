const API_BASE = ""; // Relative path to FastAPI server

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
}

// Load System State & Metrics
async function loadDashboardState() {
    try {
        const res = await fetch(`${API_BASE}/api/system/state`);
        const data = await res.json();

        document.getElementById("metricIncidents").innerText = data.total_incidents || 0;
        document.getElementById("metricBlockedIPs").innerText = (data.blocked_ips || []).length;
        document.getElementById("metricSuspendedUsers").innerText = (data.suspended_users || []).length;
        document.getElementById("metricIsolatedHosts").innerText = (data.isolated_hosts || []).length;

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
    } catch (e) {
        console.error("Error loading dashboard state:", e);
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
        }, 800);
    } catch (e) {
        alert("Error injecting attack: " + e);
    }
}

// Load Incidents Table
async function loadIncidents() {
    try {
        const res = await fetch(`${API_BASE}/api/incidents`);
        const incidents = await res.json();
        
        document.getElementById("incCount").innerText = incidents.length;
        const tbody = document.getElementById("incidentsTableBody");

        if (incidents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-td">No incidents recorded. Inject an attack above!</td></tr>';
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

            html += `
                <tr>
                    <td><strong>${inc.incident_id}</strong></td>
                    <td><span class="badge badge-${inc.severity}">${inc.threat_category}</span></td>
                    <td><code>${inc.source_ip}</code></td>
                    <td><span class="risk-pill">${inc.risk_score} <small>(${Math.round(inc.confidence_score*100)}%)</small></span></td>
                    <td><span class="tier-badge tier-${inc.decision_tier}">${inc.decision_tier}</span></td>
                    <td><code>${inc.status}</code></td>
                    <td>${actionBtn}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (e) {
        console.error("Error loading incidents:", e);
    }
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
            body: JSON.stringify({ approved: approved, reason: "Analyst dashboard manual action" })
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
