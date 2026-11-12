"use strict";

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString() : "—");
const badge = (s) => `<span class="badge s-${esc(s)}">${esc(s)}</span>`;
const PAGE = 50;
let logOffset = 0;
let editingKeyId = null;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
  });
  if (res.status === 401 && !path.endsWith("/login")) { showLogin(); throw new Error("Not logged in"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) {
    let msg = data?.detail ?? res.statusText;
    if (Array.isArray(msg)) msg = msg.map((d) => `${d.loc?.slice(1).join(".")}: ${d.msg}`).join("; ");
    throw new Error(msg);
  }
  return data;
}

// ---------------------------------------------------------------- auth
function showLogin() { $("#app-view").classList.add("hidden"); $("#login-view").classList.remove("hidden"); $("#login-password").focus(); }
function showApp() { $("#login-view").classList.add("hidden"); $("#app-view").classList.remove("hidden"); switchTab("overview"); }

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    await api("/admin/api/login", { method: "POST", body: { password: $("#login-password").value } });
    $("#login-password").value = "";
    showApp();
  } catch (err) { $("#login-error").textContent = err.message; }
});
$("#logout").addEventListener("click", async () => { await api("/admin/api/logout", { method: "POST" }); showLogin(); });

// ---------------------------------------------------------------- tabs
function switchTab(name) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("hidden", p.id !== `tab-${name}`));
  ({ overview: loadOverview, keys: loadKeys, logs: loadLogs })[name]();
}
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));

// ---------------------------------------------------------------- overview
async function loadOverview() {
  if (typeof window.loadCharts === "function") window.loadCharts(); // usage charts at the bottom of this page
  const [stats, cfg] = await Promise.all([api("/admin/api/stats"), api("/admin/api/config")]);
  $("#test-banner").classList.toggle("hidden", cfg.mail_backend !== "console");
  const d = stats.by_status["24h"] || {}, w = stats.by_status["7d"] || {};
  const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);
  const tiles = [
    ["Sent (24h)", d.sent || 0], ["Partial (24h)", d.partial || 0], ["Failed (24h)", d.failed || 0], ["Rejected (24h)", d.rejected || 0],
    ["Pending now", stats.pending], ["Total (7d)", sum(w)],
  ];
  $("#stats").innerHTML = tiles.map(([l, n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`).join("");
  $("#per-app").innerHTML = stats.per_app_24h.length
    ? stats.per_app_24h.map((r) => `<tr><td>${esc(r.app_name)}</td><td>${r.sent}</td><td>${r.failed}</td><td>${r.total}</td></tr>`).join("")
    : `<tr><td colspan="4" class="muted">No messages in the last 24h</td></tr>`;
  const rows = [
    ["Backend", cfg.backend], ["Default from", cfg.mail_from_name ? `${cfg.mail_from_name} <${cfg.mail_from}>` : cfg.mail_from],
    ["Allowed from", cfg.mail_allowed_from.join(", ")], ["Max attempts", cfg.max_attempts],
    ["Retry delays (s)", cfg.retry_schedule_seconds.join(", ")], ["Max recipients", cfg.max_recipients],
    ["SMTP submission", cfg.submission.enabled
      ? `${cfg.submission.running ? "running" : "NOT running"} — ports ${[cfg.submission.starttls_port, cfg.submission.tls_port].filter(Boolean).join(", ")}`
      : "disabled"],
    ["Submission cert", !cfg.submission.certificate ? "—" : cfg.submission.certificate.error
      ? cfg.submission.certificate.error
      : `${cfg.submission.certificate.self_signed ? "SELF-SIGNED" : cfg.submission.certificate.issuer}; ${(cfg.submission.certificate.names || []).join(", ")}; expires ${new Date(cfg.submission.certificate.not_after * 1000).toLocaleDateString()}`],
    ["Max attachments", `${(cfg.max_attachment_bytes / 1048576).toFixed(1)} MB`], ["Log retention", cfg.log_retention_days > 0 ? `${cfg.log_retention_days} days` : "unlimited"],
  ];
  $("#config").innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
}

$("#test-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const r = await api("/admin/api/test-send", { method: "POST", body: { to: $("#test-to").value } });
    $("#test-result").innerHTML = `Queued as <code>${esc(r.id)}</code> — check the Send log for the result.`;
    setTimeout(loadOverview, 2000);
  } catch (err) { $("#test-result").textContent = err.message; }
});

// ---------------------------------------------------------------- connection details
let connectInfo = null;
async function getConnectInfo() { return (connectInfo ??= await api("/admin/api/connect-info")); }

function codeBox(text) {
  return `<div class="codebox"><pre>${esc(text)}</pre><button class="secondary small" data-copy="${esc(text)}">Copy</button></div>`;
}

function renderConnect(info, key, secret) {
  const pw = secret || "<the key shown when this app was created>";
  const allowed = key.allowed_from?.length ? key.allowed_from : info.allowed_from;
  const fromList = allowed.join(", ");
  const limits = [key.rate_per_minute && `${key.rate_per_minute} per minute`, key.rate_per_day && `${key.rate_per_day} per 24h`]
    .filter(Boolean).join(", ") || "none";
  const smtp = info.smtp;
  let smtpHtml = `<p class="muted">SMTP submission is disabled (SUBMISSION_ENABLED=false).</p>`;
  if (smtp.enabled) {
    const ports = [smtp.starttls_port && `${smtp.starttls_port} — STARTTLS (recommended)`, smtp.tls_port && `${smtp.tls_port} — SSL/TLS (implicit)`].filter(Boolean);
    const cert = smtp.certificate || {};
    const certNote = cert.self_signed
      ? `<div class="note">The relay is using a <strong>self-signed certificate</strong> for SMTP. Configure TLS_CERT/TLS_KEY
         (e.g. a Let's Encrypt cert for ${esc(info.smtp.host)}) so apps can verify it, or trust the relay's CA in the app.</div>`
      : cert.error ? `<div class="note">Certificate problem: ${esc(cert.error)}</div>` : "";
    smtpHtml = `<dl>
        <dt>Host</dt><dd><code>${esc(smtp.host)}</code></dd>
        <dt>Port / security</dt><dd>${ports.map(esc).join("<br>")}</dd>
        <dt>Authentication</dt><dd>Required — PLAIN or LOGIN</dd>
        <dt>Username</dt><dd><code>${esc(key.username)}</code> <span class="muted">(lowercase, plain characters; the password identifies the app)</span></dd>
        <dt>Password</dt><dd><code>${esc(pw)}</code></dd>
        <dt>From address</dt><dd>${esc(fromList)}</dd>
      </dl>${certNote}`;
  }
  const curl = `curl -X POST ${info.api.send_url} \\
  -H "Authorization: Bearer ${pw}" \\
  -H "Content-Type: application/json" \\
  -d '{"to": ["someone@example.com"], "subject": "Hello", "text": "Plain body", "html": "<p>HTML body</p>"}'`;
  const py = `import requests

requests.post(
    "${info.api.send_url}",
    headers={"Authorization": "Bearer ${pw}"},
    json={"to": ["someone@example.com"], "subject": "Hello", "text": "Plain body"},
    timeout=30,
).raise_for_status()`;
  return `<div class="connect">
    <h3>Option A — SMTP (for apps with "SMTP settings": Gitea, Grafana, Vaultwarden, …)</h3>${smtpHtml}
    <h3>Option B — HTTP API</h3>
    <dl>
      <dt>Endpoint</dt><dd><code>POST ${esc(info.api.send_url)}</code></dd>
      <dt>Auth header</dt><dd><code>Authorization: Bearer ${esc(pw)}</code> or <code>X-API-Key</code></dd>
      <dt>Delivery status</dt><dd><code>GET ${esc(info.api.status_url)}</code></dd>
      <dt>Docs</dt><dd><code>${esc(info.api.docs_url)}</code></dd>
    </dl>
    ${codeBox(curl)}${codeBox(py)}
    <h3>Limits for this app</h3>
    <dl>
      <dt>Rate limit</dt><dd>${esc(limits)}</dd>
      <dt>Allowed From</dt><dd>${esc(fromList)} <span class="muted">(default: ${esc(info.default_from)})</span></dd>
      <dt>Max recipients</dt><dd>${info.max_recipients} per message</dd>
      <dt>Max size</dt><dd>${(info.max_attachment_bytes / 1048576).toFixed(1)} MB of attachments</dd>
    </dl></div>`;
}

document.addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-copy]");
  if (!b) return;
  await navigator.clipboard.writeText(b.dataset.copy);
  b.textContent = "Copied";
  setTimeout(() => (b.textContent = "Copy"), 1500);
});
$("#connect-close").addEventListener("click", () => $("#connect-dialog").close());

// ---------------------------------------------------------------- keys
async function loadKeys() {
  const keys = await api("/admin/api/keys");
  window._keys = keys;
  $("#keys-body").innerHTML = keys.length ? keys.map((k) => {
    const limits = [k.rate_per_minute && `${k.rate_per_minute}/min`, k.rate_per_day && `${k.rate_per_day}/day`].filter(Boolean).join(", ") || "—";
    const revoked = !!k.revoked_at;
    return `<tr class="${revoked ? "revoked" : ""}">
      <td><strong>${esc(k.name)}</strong><div class="muted">username: <code>${esc(k.username)}</code></div>${k.notes ? `<div class="muted">${esc(k.notes)}</div>` : ""}</td>
      <td><code>${esc(k.key_prefix)}…</code></td>
      <td>${esc(limits)}</td>
      <td>${esc(k.allowed_from.join(", ") || "default")}</td>
      <td>${k.sent_24h}</td><td>${k.failed_24h}</td>
      <td>${fmtTime(k.last_used_at)}</td>
      <td>${revoked ? `<span class="badge s-failed">revoked</span>` : `<span class="badge s-sent">active</span>`}</td>
      <td style="white-space:nowrap">
        ${revoked ? "" : `<button class="secondary small" data-connect="${k.id}">Connect</button>`}
        <button class="secondary small" data-logs="${k.id}">Logs</button>
        ${revoked ? "" : `<button class="secondary small" data-edit="${k.id}">Edit</button>
        <button class="danger small" data-revoke="${k.id}">Revoke</button>`}
      </td></tr>`;
  }).join("") : `<tr><td colspan="9" class="muted">No API keys yet. Create one per app.</td></tr>`;
}

$("#keys-body").addEventListener("click", async (e) => {
  const t = e.target.closest("button");
  if (!t) return;
  if (t.dataset.edit) openKeyDialog(window._keys.find((k) => k.id == t.dataset.edit));
  if (t.dataset.connect) {
    const k = window._keys.find((k) => k.id == t.dataset.connect);
    $("#connect-title").textContent = `How to connect "${k.name}"`;
    $("#connect-body").innerHTML = renderConnect(await getConnectInfo(), k, null);
    $("#connect-dialog").showModal();
  }
  if (t.dataset.logs) {
    const k = window._keys.find((k) => k.id == t.dataset.logs);
    resetFilters(); switchTab("logs");
    await loadAppOptions(); $("#f-app").value = k.name; logOffset = 0; loadLogs();
  }
  if (t.dataset.revoke) {
    const k = window._keys.find((k) => k.id == t.dataset.revoke);
    if (!confirm(`Revoke the key for "${k.name}"? Apps using it will immediately get 403 errors. This cannot be undone.`)) return;
    await api(`/admin/api/keys/${k.id}/revoke`, { method: "POST" });
    loadKeys();
  }
});

// Mirrors app/security.py:slugify_username (the server is the source of truth).
function slugifyUsername(name) {
  const special = { "ß": "ss", "æ": "ae", "œ": "oe", "ø": "o", "đ": "d", "ð": "d", "þ": "th", "ł": "l", "ı": "i" };
  const s = [...name.toLowerCase()].map((c) => special[c] ?? c).join("")
    .normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32).replace(/-+$/g, "");
  return s || "app";
}
function updateUsernamePreview() {
  $("#k-username-preview").textContent = slugifyUsername($("#k-name").value);
}
$("#k-name").addEventListener("input", updateUsernamePreview);

function openKeyDialog(key = null) {
  editingKeyId = key?.id ?? null;
  $("#key-dialog-title").textContent = key ? `Edit "${key.name}"` : "New API key";
  $("#k-name").value = key?.name ?? "";
  updateUsernamePreview();
  $("#k-rpm").value = key?.rate_per_minute ?? "";
  $("#k-rpd").value = key?.rate_per_day ?? "";
  $("#k-from").value = (key?.allowed_from ?? []).join(", ");
  $("#k-notes").value = key?.notes ?? "";
  $("#key-error").textContent = "";
  $("#key-dialog").showModal();
}
$("#new-key-btn").addEventListener("click", () => openKeyDialog());
$("#key-cancel").addEventListener("click", () => $("#key-dialog").close());

$("#key-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const num = (v) => (v === "" ? null : Number(v));
  const body = {
    name: $("#k-name").value.trim(),
    rate_per_minute: num($("#k-rpm").value),
    rate_per_day: num($("#k-rpd").value),
    allowed_from: $("#k-from").value.split(",").map((s) => s.trim()).filter(Boolean),
    notes: $("#k-notes").value.trim() || null,
  };
  try {
    if (editingKeyId) {
      await api(`/admin/api/keys/${editingKeyId}`, { method: "PATCH", body });
      $("#key-dialog").close();
    } else {
      const created = await api("/admin/api/keys", { method: "POST", body });
      $("#key-dialog").close();
      $("#secret-value").textContent = created.api_key;
      $("#secret-connect").innerHTML = renderConnect(await getConnectInfo(), created, created.api_key);
      $("#secret-dialog").showModal();
    }
    loadKeys();
  } catch (err) { $("#key-error").textContent = err.message; }
});

$("#secret-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("#secret-value").textContent);
  $("#secret-copy").textContent = "Copied";
});
$("#secret-close").addEventListener("click", () => {
  $("#secret-value").textContent = "";  // drop it from the DOM
  $("#secret-connect").innerHTML = "";
  $("#secret-copy").textContent = "Copy";
  $("#secret-dialog").close();
});
$("#secret-dialog").addEventListener("cancel", (e) => e.preventDefault()); // force explicit acknowledgement

// ---------------------------------------------------------------- logs
async function loadAppOptions() {
  const { apps } = await api("/admin/api/stats");
  const cur = $("#f-app").value;
  $("#f-app").innerHTML = `<option value="">All apps</option>` + apps.map((a) => `<option>${esc(a)}</option>`).join("");
  $("#f-app").value = cur;
}

function dateToEpoch(v, endOfDay) {
  if (!v) return null;
  const d = new Date(`${v}T00:00:00`);
  if (endOfDay) d.setDate(d.getDate() + 1);
  return d.getTime() / 1000;
}

async function loadLogs() {
  if ($("#f-app").options.length <= 1) await loadAppOptions();
  const p = new URLSearchParams({ limit: PAGE, offset: logOffset });
  const add = (k, v) => v !== null && v !== "" && p.set(k, v);
  add("q", $("#f-q").value.trim());
  add("app", $("#f-app").value);
  add("status", $("#f-status").value);
  add("since", dateToEpoch($("#f-since").value, false));
  add("until", dateToEpoch($("#f-until").value, true));
  const { items, total } = await api(`/admin/api/messages?${p}`);
  $("#logs-body").innerHTML = items.length ? items.map((m) => {
    const to = [...(m.recipients.to || []), ...(m.recipients.cc || [])];
    const bcc = (m.recipients.bcc || []).length;
    return `<tr class="clickable" data-id="${esc(m.id)}">
      <td style="white-space:nowrap">${fmtTime(m.created_at)}</td>
      <td>${esc(m.app_name)}</td>
      <td>${esc(m.username || "")}</td>
      <td>${esc(m.source || "")}</td>
      <td class="ellip">${esc(to.join(", "))}${bcc ? ` <span class="muted">+${bcc} bcc</span>` : ""}</td>
      <td class="ellip">${esc(m.subject)}${m.attachment_count ? ` <span class="muted">📎${m.attachment_count}</span>` : ""}</td>
      <td>${badge(m.status)}</td><td>${m.attempts}</td>
      <td class="ellip">${esc(m.error)}</td></tr>`;
  }).join("") : `<tr><td colspan="9" class="muted">No matching messages</td></tr>`;
  const end = Math.min(logOffset + PAGE, total);
  $("#page-info").textContent = total ? `${logOffset + 1}–${end} of ${total}` : "";
  $("#prev").disabled = logOffset === 0;
  $("#next").disabled = end >= total;
}

function resetFilters() { $("#log-filters").reset(); logOffset = 0; }
$("#log-filters").addEventListener("submit", (e) => { e.preventDefault(); logOffset = 0; loadLogs(); });
$("#f-reset").addEventListener("click", () => { resetFilters(); loadLogs(); });
$("#prev").addEventListener("click", () => { logOffset = Math.max(0, logOffset - PAGE); loadLogs(); });
$("#next").addEventListener("click", () => { logOffset += PAGE; loadLogs(); });

$("#logs-body").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-id]");
  if (tr) openMessage(tr.dataset.id);
});

async function openMessage(id) {
  const m = await api(`/admin/api/messages/${id}`);
  const r = m.recipients || {};
  const rows = [
    ["ID", `<code>${esc(m.id)}</code>`], ["Status", badge(m.status)], ["App", esc(m.app_name)],
    ["From", esc(m.from_addr)], ["To", esc((r.to || []).join(", "))], ["Cc", esc((r.cc || []).join(", "))],
    ["Bcc", esc((r.bcc || []).join(", "))], ["Subject", esc(m.subject)], ["Created", fmtTime(m.created_at)],
    ["Updated", fmtTime(m.updated_at)], ["Attempts", m.attempts],
    ["Next attempt", m.next_attempt_at ? fmtTime(m.next_attempt_at) : "—"],
    ["Size", `${m.size_bytes} bytes, ${m.attachment_count} attachment(s), ${m.has_html ? "HTML" : "text only"}`],
    ["Message-ID", `<code>${esc(m.provider_id)}</code>`], ["Username", esc(m.username)], ["Via", esc(m.source)], ["Client IP", esc(m.client_ip)], ["Error", esc(m.error)],
  ].filter(([, v]) => v !== "" && v !== "<code></code>");
  const events = m.events.map((ev) => `<tr><td style="white-space:nowrap">${fmtTime(ev.ts)}</td><td>${esc(ev.event)}</td><td>${esc(ev.detail)}</td></tr>`).join("");
  const body = m.payload
    ? `<h3>Body (retained until delivered)</h3>${m.payload.text ? `<pre>${esc(m.payload.text)}</pre>` : ""}${m.payload.html ? `<pre>${esc(m.payload.html)}</pre>` : ""}`
    : "";
  $("#msg-body").innerHTML = `<dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>
    ${m.retryable ? `<p><button id="retry-btn">Retry now</button></p>` : ""}
    <h3>Events</h3><table><tbody>${events}</tbody></table>${body}`;
  $("#retry-btn")?.addEventListener("click", async () => {
    await api(`/admin/api/messages/${id}/retry`, { method: "POST" });
    $("#msg-dialog").close(); loadLogs();
  });
  $("#msg-dialog").showModal();
}
$("#msg-close").addEventListener("click", () => $("#msg-dialog").close());

// ---------------------------------------------------------------- boot
api("/admin/api/me").then((r) => (r.admin ? showApp() : showLogin())).catch(showLogin);
