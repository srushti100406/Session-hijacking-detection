/**
 * demo.js — Frontend controller for the 4-stage demo.
 *
 * All stage results are fetched from the real backend.
 * No hardcoded success states or fake responses.
 */

"use strict";

// ── Global demo state ──
const state = {
  sessionFingerprint: null,
  testSessionId: null,
  stage1Done: false,
  stage2Done: false,
  stage3Done: false,
  stage4Done: false,
  securityAlertSignature: null,
  backendStatusSignature: null,
};

// ── Helpers ──

function el(id) { return document.getElementById(id); }

function setLoading(btnId, loading) {
  const btn = el(btnId);
  if (!btn) return;
  if (loading) {
    btn.disabled = true;
    btn._origText = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Processing…`;
  } else {
    btn.disabled = false;
    if (btn._origText) btn.innerHTML = btn._origText;
  }
}

function showResult(boxId, html, type = "info") {
  const box = el(boxId);
  if (!box) return;
  box.innerHTML = html;
  box.className = `result-box ${type}`;
}

function markStageDone(n) {
  const dot = el(`dot${n}`);
  if (dot) { dot.classList.remove("active"); dot.classList.add("done"); }
  const nextDot = el(`dot${n + 1}`);
  if (nextDot) nextDot.classList.add("active");
}

function activatePanel(panelId) {
  const p = el(panelId);
  if (p) p.style.display = "block";
}

function enableStage2() {
  const s2 = el("stage2");
  if (s2) { s2.style.opacity = "1"; s2.style.pointerEvents = "auto"; }
}

function formatTime(isoStr) {
  if (!isoStr) return "—";
  const d = new Date(isoStr);
  return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatTimestamp(isoStr) {
  if (!isoStr) return "—";
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return isoStr;
  return d.toLocaleString([], { hour12: false });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function httpBadge(code) {
  if (!code) return `<span style="color:var(--text-dim)">—</span>`;
  const cls = code === 200 ? "success-text" : "danger-text";
  return `<span class="${cls}" style="font-family:var(--mono);font-weight:700">HTTP ${code}</span>`;
}

// ── Stage 1 — Legitimate Login ──

async function runStage1() {
  setLoading("btnLogin", true);
  try {
    const resp = await fetch("/demo/stage1-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: el("loginUsername").value,
        password: el("loginPassword").value,
      }),
    });
    const data = await resp.json();

    if (!resp.ok || !data.success) {
      showResult("stage1Result", `<strong>Error:</strong> ${data.error || "Login failed."}`, "error");
      return;
    }

    el("loginPassword").value = "";
    state.sessionFingerprint = data.session_fingerprint;
    state.testSessionId = data.test_session_id;
    state.stage1Done = true;

    // Update UI
    el("sessionUser").textContent = data.username;
    el("sessionFp").textContent = data.session_fingerprint;
    el("sessionCard").style.display = "block";
    el("protectedSection").style.display = "block";
    el("attackerFp").textContent = data.session_fingerprint + " (session ID fingerprint)";
    // Keep the attacker handoff field for pasted cross-device input. The laptop
    // retains the legitimate ID separately in state for copying.
    el("attackerSessionId").value = "";
    el("explainer1").style.display = "block";

    showResult("stage1Result",
      `✅ Authenticated as <strong>${data.username}</strong> (${data.role})<br>
       Session status: <span class="success-text">${data.session_status}</span><br>
       Auth status: <span class="success-text">${data.auth_status}</span><br>
       Session fingerprint: <code>${data.session_fingerprint}</code><br>
       <small>${data.explanation}</small>`,
      "success"
    );

    markStageDone(1);
    enableStage2();
    el("btnLogin").disabled = true;

    await refreshEvents();

  } catch (err) {
    showResult("stage1Result", `<strong>Network error:</strong> ${err.message}`, "error");
  } finally {
    setLoading("btnLogin", false);
    if (state.stage1Done) el("btnLogin").disabled = true;
  }
}

async function copyTestSessionId() {
  const sessionId = state.testSessionId;
  if (!sessionId) {
    showResult("stage2Result", "No legitimate test session exists. Create one on Laptop A first.", "error");
    return;
  }
  try {
    await navigator.clipboard.writeText(sessionId);
    el("stage2Result").className = "result-box hidden";
  } catch (err) {
    showResult("stage2Result", `Clipboard unavailable: ${err.message}. Select and copy the ID manually.`, "error");
  }
}

// ── Access Protected Resource (Stage 1 demo) ──

async function accessProtectedResource() {
  setLoading("btnAccess", true);
  try {
    const resp = await fetch("/api/protected-resource");
    const data = await resp.json();

    if (resp.ok && data.success) {
      showResult("protectedResult",
        `${httpBadge(200)} <strong>${data.status}</strong><br>
         ${data.message}<br>
         <small>Document: <em>${data.resource_data?.document}</em></small>`,
        "success"
      );
    } else {
      showResult("protectedResult",
        `${httpBadge(resp.status)} Access denied: ${data.reason || data.message}`,
        "error"
      );
    }
    await refreshEvents();
  } catch (err) {
    showResult("protectedResult", `Network error: ${err.message}`, "error");
  } finally {
    setLoading("btnAccess", false);
  }
}

// ── Stage 2 — Replay Attack ──

async function runStage2() {
  const sessionId = el("attackerSessionId").value.trim();
  if (!sessionId) {
    showResult("stage2Result", "Paste the test session ID copied from Laptop A.", "error");
    return;
  }
  state.testSessionId = sessionId;
  setLoading("btnAttack", true);
  try {
    const resp = await fetch("/demo/stage2-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test_session_id: sessionId }),
    });
    const data = await resp.json();

    const detected = resp.ok && data.success === true
      && data.detected === true && data.session_revoked === true;
    const code = data.server_response_code;
    const serverResp = data.server_response || {};

    if (!detected) {
      showResult("stage2Result",
        `${httpBadge(code || resp.status)} <strong>Backend did not confirm detection and revocation.</strong><br>
         ${serverResp.reason || data.error || "No confirmed replay result was returned."}`,
        "error"
      );
      await refreshEvents();
      return;
    }

    state.stage2Done = true;
    state.sessionFingerprint = data.session_fingerprint;

    showResult("stage2Result",
      `${httpBadge(code)} <strong>${detected ? "ATTACK BLOCKED" : "NOT DETECTED ⚠️"}</strong><br>
       <strong>Attack type:</strong> ${data.attack_type}<br>
       <strong>Cookies sent:</strong> ${(data.cookies_sent || []).join(", ")}<br>
       <strong>Server response:</strong> ${serverResp.detection || serverResp.reason || serverResp.message || "—"}<br>
       ${serverResp.reason ? `<strong>Reason:</strong> ${serverResp.reason}<br>` : ""}
       <small style="color:var(--text-muted)">${data.description}</small>`,
      detected ? "warning" : "error"
    );

    markStageDone(2);

    if (detected) {
      activatePanel("panelDetection");
      animateDetectionSteps(data, serverResp);
    }

    el("btnStage3").style.display = "inline-flex";

    el("sessionStatus").textContent = data.session_revoked ? "REVOKED" : "ACTIVE";
    el("sessionStatus").className = `status-value ${data.session_revoked ? "danger-text" : "success-text"}`;

    await refreshEvents();

  } catch (err) {
    showResult("stage2Result", `<strong>Network error:</strong> ${err.message}`, "error");
  } finally {
    setLoading("btnAttack", false);
  }
}

// ── Detection steps animation ──

function animateDetectionSteps(data, serverResp) {
  const steps = ["dstep1", "dstep2", "dstep3", "dstep4", "dstep5", "dstep6"];
  steps.forEach((id, i) => {
    setTimeout(() => {
      const el_s = el(id);
      if (el_s) {
        el_s.classList.add(i < 3 ? "lit" : "done");
      }
    }, i * 350);
  });

  setTimeout(() => {
    const det = el("detectionDetails");
    if (det) {
      det.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem">
          <div>
            <div style="font-size:0.72rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;margin-bottom:0.4rem">Detection Reason</div>
            <div style="color:var(--amber-text);font-weight:600">${serverResp.reason || "proof_token_invalid_or_missing"}</div>
          </div>
          <div>
            <div style="font-size:0.72rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;margin-bottom:0.4rem">HTTP Response</div>
            <div>${httpBadge(data.server_response_code)}</div>
          </div>
          <div>
            <div style="font-size:0.72rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;margin-bottom:0.4rem">Action Taken</div>
            <div style="color:var(--red-text);font-weight:600">${serverResp.action || "Request rejected. Session revoked."}</div>
          </div>
          <div>
            <div style="font-size:0.72rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;margin-bottom:0.4rem">Detection Signal</div>
            <div style="color:var(--amber-text);font-weight:600">Missing proof token</div>
          </div>
        </div>
        <div style="margin-top:0.75rem;font-size:0.82rem;color:var(--text-muted)">
          ${data.explanation || ""}
        </div>`;
    }
  }, steps.length * 350 + 100);
}

// ── Stage 3 — Confirm Detection ──

async function runStage3() {
  const sessionId = el("attackerSessionId").value.trim();
  if (!sessionId) return;
  setLoading("btnStage3", true);
  try {
    const resp = await fetch("/demo/stage3-detection", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test_session_id: sessionId }),
    });
    const data = await resp.json();

    if (!resp.ok || data.success !== true) {
      showResult("stage3Result",
        `<strong>Backend confirmation failed:</strong> ${data.error || data.explanation || resp.status}`,
        "error"
      );
      await refreshEvents();
      return;
    }
    state.stage3Done = true;

    showResult("stage3Result",
      `<strong>Detection status:</strong> <span class="warning-text">${data.detection_status}</span><br>
       <strong>Session revoked:</strong> <span class="${data.session_revoked ? "danger-text" : "warning-text"}">${data.session_revoked ? "YES" : "NO"}</span><br>
       ${data.revoke_reason ? `<strong>Revoke reason:</strong> ${data.revoke_reason}<br>` : ""}
       <small>${data.explanation}</small>`,
      data.session_revoked ? "error" : "warning"
    );

    markStageDone(3);
    activatePanel("panelVerify");
    el("btnStage3").style.display = "none";

    await refreshEvents();

  } catch (err) {
    showResult("stage3Result", `Network error: ${err.message}`, "error");
  } finally {
    setLoading("btnStage3", false);
  }
}

// ── Stage 4 — Post-Revocation Verification ──

async function runStage4() {
  const sessionId = el("attackerSessionId").value.trim();
  if (!sessionId) return;
  setLoading("btnStage4", true);
  try {
    const resp = await fetch("/demo/stage4-verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test_session_id: sessionId }),
    });
    const data = await resp.json();

    if (!resp.ok || data.success !== true) {
      showResult("stage4Result",
        `<strong>Backend verification failed:</strong> ${data.error || data.conclusion || resp.status}`,
        "error"
      );
      await refreshEvents();
      return;
    }
    state.stage4Done = true;

    const summary = data.demo_summary || {};
    const overall = summary.overall_result;

    showResult("stage4Result",
      `${httpBadge(data.post_revocation_response_code)}: 
       <span class="${data.post_revocation_access_denied ? "danger-text" : "warning-text"}">
         ${data.post_revocation_access_denied ? "ACCESS DENIED ✓" : "REVOCATION NOT VERIFIED ⚠️"}
       </span><br>
       <strong>Session revoked before check:</strong> ${data.session_revoked_before_attempt ? "YES" : "NO"}<br>
       <strong>Server reason:</strong> ${data.post_revocation_reason || "—"}<br>
       <small>${data.conclusion}</small>`,
      data.post_revocation_access_denied ? "error" : "warning"
    );

    markStageDone(4);
    buildFinalResult(summary, data.conclusion);
    activatePanel("panelResult");

    await refreshEvents();

  } catch (err) {
    showResult("stage4Result", `Network error: ${err.message}`, "error");
  } finally {
    setLoading("btnStage4", false);
  }
}

// ── Final Result Panel ──

function buildFinalResult(summary, conclusion) {
  const overall = summary.overall_result;
  const isPassed = overall === "PASS";

  const header = el("resultHeader");
  header.className = `panel-header ${isPassed ? "pass-header success-header" : "fail-header danger-header"}`;
  header.innerHTML = `
    <span class="panel-icon">${isPassed ? "🏆" : "⚠️"}</span>
    <h2>Demo Result: <span style="color:${isPassed ? "var(--green-text)" : "var(--red-text)"}">${overall}</span></h2>`;

  const checks = [
    ["stage1_legitimate_access", "Legitimate user accessed protected resource"],
    ["stage2_replay_detected", "Replay attack was detected"],
    ["stage3_session_revoked", "Session was revoked"],
    ["stage4_revocation_enforced", "Post-revocation access denied"],
  ];

  el("resultSummary").innerHTML = checks.map(([key, label]) => {
    const passed = summary[key];
    return `<div class="summary-item ${passed ? "pass" : "fail"}">
      ${passed ? "✅" : "❌"} ${label}
    </div>`;
  }).join("");

  el("resultConclusion").innerHTML = `<strong>Conclusion:</strong> ${conclusion}`;

  el("panelResult").style.display = "block";
}

// ── Reset ──

async function resetDemo() {
  setLoading("btnStage4", true);
  try {
    const sessionId = el("attackerSessionId").value.trim();
    const resp = await fetch("/demo/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test_session_id: sessionId }),
    });
    const data = await resp.json();
    if (!resp.ok || data.success !== true) {
      showResult("stage4Result", `<strong>Reset failed:</strong> ${data.error || resp.status}`, "error");
      return;
    }

    // Reset state
    state.sessionFingerprint = null;
    state.testSessionId = null;
    state.stage1Done = state.stage2Done = state.stage3Done = state.stage4Done = false;

    // Reset stage dots
    ["dot1","dot2","dot3","dot4"].forEach((id, i) => {
      const d = el(id);
      if (d) { d.classList.remove("active","done"); if (i===0) d.classList.add("active"); }
    });

    // Reset result boxes
    ["stage1Result","stage2Result","stage3Result","stage4Result","protectedResult"].forEach(id => {
      const b = el(id);
      if (b) { b.innerHTML = ""; b.className = "result-box hidden"; }
    });

    // Reset panels
    el("panelDetection").style.display = "none";
    el("panelVerify").style.display = "none";
    el("panelResult").style.display = "none";
    el("sessionCard").style.display = "none";
    el("protectedSection").style.display = "none";
    el("explainer1").style.display = "none";
    el("btnStage3").style.display = "none";

    // Reset detection steps
    ["dstep1","dstep2","dstep3","dstep4","dstep5","dstep6"].forEach(id => {
      const d = el(id);
      if (d) d.classList.remove("lit","done");
    });

    // Re-enable login button
    const btnLogin = el("btnLogin");
    if (btnLogin) {
      btnLogin.disabled = false;
      btnLogin.innerHTML = "🔐 Create Legitimate Session";
    }

    // Reset session status
    el("sessionStatus").textContent = "ACTIVE";
    el("sessionStatus").className = "status-value success-text";
    el("sessionUser").textContent = "—";
    el("sessionFp").textContent = "—";
    el("attackerFp").textContent = "—";
    el("attackerSessionId").value = "";
    state.securityAlertSignature = null;
    state.backendStatusSignature = null;
    if (el("sessionHijackAlert")) el("sessionHijackAlert").style.display = "none";

    el("detectionDetails").innerHTML = "";

    await refreshEvents();

  } catch (err) {
    console.error("Reset error:", err);
  } finally {
    setLoading("btnStage4", false);
  }
}

// ── Event Log and backend session status ──

async function refreshBackendSession(events = []) {
  try {
    const resp = await fetch("/api/session-status", { cache: "no-store" });
    if (!resp.ok) throw new Error(`Session status returned HTTP ${resp.status}`);
    const status = await resp.json();
    if (!status.has_session) return;

    const targetFingerprint = state.sessionFingerprint || status.fingerprint;
    if (status.fingerprint !== targetFingerprint) return;

    if (!status.revoked) {
      const activeSignature = `${status.fingerprint}:active`;
      if (state.backendStatusSignature !== activeSignature) {
        el("sessionStatus").textContent = "ACTIVE";
        el("sessionStatus").className = "status-value success-text";
        state.backendStatusSignature = activeSignature;
      }
      return;
    }

    const revokedSignature = `${status.fingerprint}:revoked`;
    if (state.backendStatusSignature !== revokedSignature) {
      el("sessionStatus").textContent = "REVOKED";
      el("sessionStatus").className = "status-value danger-text";
      state.backendStatusSignature = revokedSignature;
    }

    const matchingEvents = events.filter(ev => ev.session_fingerprint === targetFingerprint);
    const detection = matchingEvents.find(ev => ev.event_type === "DETECTION_TRIGGERED");
    const revocation = matchingEvents.find(ev => ev.event_type === "SESSION_REVOKED");
    if (!detection) return;

    activatePanel("panelDetection");
    ["dstep1", "dstep2", "dstep3", "dstep4", "dstep5", "dstep6"].forEach(id => {
      const step = el(id);
      if (step && !step.classList.contains("done")) step.classList.add("done");
    });

    const httpEvent = revocation || detection;
    const httpMatch = httpEvent.extra_info?.match(/http_status=(\d+)/i);
    const httpResponse = httpMatch ? `HTTP ${httpMatch[1]} Access Denied` : "Backend response unavailable";
    const alertSignature = `${detection.id}:${revocation?.id || ""}:${status.revoked_at || ""}`;
    if (state.securityAlertSignature !== alertSignature) {
      const alert = el("sessionHijackAlert");
      const alertDetails = el("sessionHijackAlertDetails");
      if (alert && alertDetails) {
        alertDetails.innerHTML = `
          <div><span>Target user</span><strong>${escapeHtml(detection.username || "—")}</strong></div>
          <div><span>Attack type</span><strong>Session hijacking / replay</strong></div>
          <div><span>Detection reason</span><strong>${escapeHtml(detection.reason || "—")}</strong></div>
          <div><span>HTTP response</span><strong>${escapeHtml(httpResponse)}</strong></div>
          <div><span>Session revocation</span><strong class="danger-text">REVOKED</strong></div>
          <div><span>Timestamp</span><strong>${escapeHtml(formatTimestamp(revocation?.timestamp || status.revoked_at))}</strong></div>`;
        alert.style.display = "block";
      }
      state.securityAlertSignature = alertSignature;
    }
  } catch (err) {
    console.error("Failed to refresh backend session status:", err);
  }
}

async function refreshEvents() {
  if (refreshEvents._inProgress) return;
  refreshEvents._inProgress = true;
  try {
    const resp = await fetch("/api/security-events", { cache: "no-store" });
    if (!resp.ok) throw new Error(`Security events returned HTTP ${resp.status}`);
    const data = await resp.json();
    const events = data.events || [];

    await refreshBackendSession(events);
    const container = el("eventLog");
    if (!container) return;

    if (events.length === 0) {
      container.innerHTML = `<p class="log-empty">No events yet. Run the demo to see security events.</p>`;
      return;
    }

    container.innerHTML = events.map(ev => {
      const evClass = `ev-${ev.event_type}`;
      const time = formatTime(ev.timestamp);
      const outcome = ev.outcome
        ? `<span class="event-outcome" style="color:${ev.outcome==='success'?'var(--green-text)':ev.outcome==='failure'||ev.outcome==='blocked'?'var(--red-text)':'var(--amber-text)'}">${ev.outcome.toUpperCase()}</span>`
        : "";
      return `
        <div class="event-entry ${evClass}">
          <span class="event-type">${ev.event_type}</span>
          <span class="event-reason">
            ${ev.reason ? `<span style="color:var(--text-muted)">${ev.reason}</span>` : ""}
            ${ev.session_fingerprint ? ` · <code>${ev.session_fingerprint}</code>` : ""}
            ${ev.username ? ` · <strong>${ev.username}</strong>` : ""}
            ${ev.action_taken ? ` · ${ev.action_taken}` : ""}
          </span>
          <div style="text-align:right">
            <div class="event-time">${time}</div>
            ${outcome}
          </div>
        </div>`;
    }).join("");

  } catch (err) {
    console.error("Failed to refresh events:", err);
  } finally {
    refreshEvents._inProgress = false;
  }
}

// ── Init ──
document.addEventListener("DOMContentLoaded", () => {
  refreshEvents();
  setInterval(refreshEvents, 2000);
});
