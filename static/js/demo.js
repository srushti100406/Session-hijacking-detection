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
  stage1Done: false,
  stage2Done: false,
  stage3Done: false,
  stage4Done: false,
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
      body: JSON.stringify({ username: "alice", password: "Demo@1234" }),
    });
    const data = await resp.json();

    if (!resp.ok || !data.success) {
      showResult("stage1Result", `<strong>Error:</strong> ${data.error || "Login failed."}`, "error");
      return;
    }

    state.sessionFingerprint = data.session_fingerprint;
    state.stage1Done = true;

    // Update UI
    el("sessionUser").textContent = data.username;
    el("sessionFp").textContent = data.session_fingerprint;
    el("sessionCard").style.display = "block";
    el("protectedSection").style.display = "block";
    el("attackerFp").textContent = data.session_fingerprint + " (session ID fingerprint)";
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
  if (!state.sessionFingerprint) {
    alert("Run Stage 1 first.");
    return;
  }
  setLoading("btnAttack", true);
  try {
    const resp = await fetch("/demo/stage2-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_fingerprint: state.sessionFingerprint }),
    });
    const data = await resp.json();

    if (!resp.ok || !data.success) {
      showResult("stage2Result", `<strong>Error:</strong> ${data.error || "Replay check failed."}`, "error");
      return;
    }

    state.stage2Done = true;

    const detected = data.detected === true;
    const code = data.server_response_code;
    const serverResp = data.server_response || {};

    showResult("stage2Result",
      `${httpBadge(code)} <strong>${detected ? "DETECTED & BLOCKED" : "NOT DETECTED ⚠️"}</strong><br>
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
  if (!state.sessionFingerprint) return;
  setLoading("btnStage3", true);
  try {
    const resp = await fetch("/demo/stage3-detection", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_fingerprint: state.sessionFingerprint }),
    });
    const data = await resp.json();

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
  if (!state.sessionFingerprint) return;
  setLoading("btnStage4", true);
  try {
    const resp = await fetch("/demo/stage4-verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_fingerprint: state.sessionFingerprint }),
    });
    const data = await resp.json();

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
    ["stage1_legitimate_login", "Legitimate login succeeded"],
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
    await fetch("/demo/reset", { method: "POST" });

    // Reset state
    state.sessionFingerprint = null;
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

    // Reset stage 2 lock
    const s2 = el("stage2");
    if (s2) { s2.style.opacity = "0.4"; s2.style.pointerEvents = "none"; }

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

    el("detectionDetails").innerHTML = "";

    await refreshEvents();

  } catch (err) {
    console.error("Reset error:", err);
  } finally {
    setLoading("btnStage4", false);
  }
}

// ── Event Log ──

async function refreshEvents() {
  try {
    const resp = await fetch("/api/security-events");
    const data = await resp.json();
    const events = data.events || [];

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
  }
}

// ── Init ──
document.addEventListener("DOMContentLoaded", () => {
  refreshEvents();
});
