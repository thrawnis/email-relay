"use strict";
/* Charts tab: emails per day across all keys (stacked columns) and per API key (one multi-line chart).
   Plain SVG, no libraries. Daily buckets are built in the browser's local time zone from hourly UTC counts. */
(() => {
  const NS = "http://www.w3.org/2000/svg";
  const $ = (s, r = document) => r.querySelector(s);
  const MAX_DAYS = 366;
  const TOP_KEYS = 7; // seven categorical colors + a gray "other keys" line
  const SERIES_VARS = ["--s1", "--s2", "--s3", "--s4", "--s5", "--s6", "--s7"];

  const fmtN = (n) => Number(n).toLocaleString();
  const dayStart = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const addDays = (d, n) => new Date(d.getFullYear(), d.getMonth(), d.getDate() + n);
  const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  const parseYmd = (s) => { const [y, m, d] = s.split("-").map(Number); return new Date(y, m - 1, d); };
  const fmtShort = (d) => d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const fmtLong = (d) => d.toLocaleDateString(undefined, { weekday: "short", year: "numeric", month: "short", day: "numeric" });

  function el(name, attrs = {}, parent) {
    const e = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (parent) parent.appendChild(e);
    return e;
  }
  function h(tag, props = {}, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") e.className = v; else if (k === "text") e.textContent = v; else e.setAttribute(k, v);
    }
    for (const kid of kids) if (kid) e.append(kid);
    return e;
  }

  const state = { preset: 14, from: null, to: null, days: [], raw: null, hidden: new Set(), loaded: false, token: 0 };

  // ------------------------------------------------------------------ range controls
  function setRange(from, to) {
    state.from = dayStart(from);
    state.to = dayStart(to);
    $("#c-from").value = ymd(state.from);
    $("#c-to").value = ymd(state.to);
  }
  function applyPreset(n) {
    state.preset = n;
    const today = dayStart(new Date());
    setRange(addDays(today, -(n - 1)), today);
    syncPresetButtons();
    load();
  }
  function syncPresetButtons() {
    document.querySelectorAll("#c-presets button").forEach((b) => {
      const on = state.preset !== null && Number(b.dataset.days) === state.preset;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on);
    });
  }
  function onCustomChange(ev) {
    const f = $("#c-from").value, t = $("#c-to").value;
    if (!f || !t) return;
    const editedFrom = ev.target.id === "c-from";
    let from = parseYmd(f), to = parseYmd(t);
    const note = $("#c-note");
    note.textContent = "";
    // Keep the range valid by moving the date that was NOT just edited, so editing one field after the other works.
    if (from > to) { editedFrom ? (to = from) : (from = to); }
    if ((to - from) / 86400000 + 1 > MAX_DAYS) {
      if (editedFrom) to = addDays(from, MAX_DAYS - 1); else from = addDays(to, -(MAX_DAYS - 1));
      note.textContent = `Ranges are limited to ${MAX_DAYS} days.`;
    }
    state.preset = null;
    setRange(from, to);
    syncPresetButtons();
    load();
  }

  // ------------------------------------------------------------------ data
  async function load() {
    const my = ++state.token;
    const root = $("#charts-root");
    root.classList.add("loading"); // keep the previous render, dimmed, while refetching
    const since = state.from.getTime() / 1000;
    const until = addDays(state.to, 1).getTime() / 1000;
    try {
      const res = await fetch(`/admin/api/stats/timeseries?since=${since}&until=${until}`, { credentials: "same-origin" });
      if (res.status === 401) { location.reload(); return; }
      if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
      const data = await res.json();
      if (my !== state.token) return; // a newer request superseded this one
      state.raw = data;
      state.loaded = true;
      render();
    } catch (e) {
      $("#c-note").textContent = `Could not load chart data: ${e.message}`;
    } finally {
      if (my === state.token) root.classList.remove("loading");
    }
  }

  function aggregate() {
    const days = [];
    for (let d = state.from; d <= state.to; d = addDays(d, 1)) days.push(d);
    const index = new Map(days.map((d, i) => [ymd(d), i]));
    const blank = () => ({ ok: new Array(days.length).fill(0), bad: new Array(days.length).fill(0) });
    const total = blank();
    const perKey = new Map();
    const meta = new Map(state.raw.keys.map((k) => [k.id, k]));
    for (const b of state.raw.buckets) {
      const i = index.get(ymd(new Date(b.h * 1000)));
      if (i === undefined) continue;
      total.ok[i] += b.ok; total.bad[i] += b.bad;
      const id = b.key_id ?? "admin";
      if (!perKey.has(id)) perKey.set(id, blank());
      perKey.get(id).ok[i] += b.ok; perKey.get(id).bad[i] += b.bad;
    }
    const sum = (a) => a.reduce((x, y) => x + y, 0);
    const keys = [...perKey.entries()].map(([id, v]) => {
      const m = meta.get(id);
      return { id, name: m ? m.name : "(admin tests)", username: m ? m.username : "", revoked: !!(m && m.revoked_at),
               ok: v.ok, bad: v.bad, sent: sum(v.ok), problems: sum(v.bad) };
    }).sort((a, b) => b.sent - a.sent || String(a.id).localeCompare(String(b.id), undefined, { numeric: true }));
    // keys with no traffic in the range still appear in the table
    for (const m of state.raw.keys) {
      if (!perKey.has(m.id)) keys.push({ id: m.id, name: m.name, username: m.username, revoked: !!m.revoked_at,
        ok: new Array(days.length).fill(0), bad: new Array(days.length).fill(0), sent: 0, problems: 0 });
    }
    return { days, total, keys, sum };
  }

  // ------------------------------------------------------------------ chart helpers
  function niceTicks(max) {
    if (max <= 0) return { top: 4, ticks: [0, 1, 2, 3, 4] };
    const rough = max / 4;
    const p = Math.pow(10, Math.floor(Math.log10(rough)));
    const f = rough / p;
    const step = Math.max(1, (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p);
    const top = Math.ceil(max / step) * step;
    const ticks = [];
    for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v);
    return { top, ticks };
  }

  function makeFrame(host, days, maxVal, height) {
    host.textContent = "";
    const W = Math.max(320, host.clientWidth);
    const m = { l: 44, r: 12, t: 12, b: 26 };
    const pw = W - m.l - m.r, ph = height - m.t - m.b;
    const { top, ticks } = niceTicks(maxVal);
    const svg = el("svg", { width: W, height, viewBox: `0 0 ${W} ${height}`, role: "img" }, host);
    const y = (v) => m.t + ph - (v / top) * ph;
    const band = pw / days.length;
    const cx = (i) => m.l + band * (i + 0.5);
    for (const t of ticks) {
      el("line", { x1: m.l, x2: m.l + pw, y1: y(t), y2: y(t), class: "grid" }, svg);
      const lab = el("text", { x: m.l - 8, y: y(t) + 4, "text-anchor": "end", class: "tick" }, svg);
      lab.textContent = top >= 10000 ? `${t / 1000}K` : fmtN(t);
    }
    const step = Math.max(1, Math.ceil(56 / band));
    days.forEach((d, i) => {
      if (i % step !== 0) return;
      const lab = el("text", { x: cx(i), y: height - 8, "text-anchor": "middle", class: "tick" }, svg);
      lab.textContent = fmtShort(d);
    });
    return { svg, W, m, pw, ph, y, band, cx, top, host, height };
  }

  function topRounded(x, y, w, hgt, r) {
    r = Math.min(r, w / 2, hgt);
    if (r <= 0) return `M${x},${y + hgt}V${y}H${x + w}V${y + hgt}Z`;
    return `M${x},${y + hgt}V${y + r}A${r},${r} 0 0 1 ${x + r},${y}H${x + w - r}A${r},${r} 0 0 1 ${x + w},${y + r}V${y + hgt}Z`;
  }

  // One tooltip per chart, shared by every day band. Labels come from API data: textContent only.
  function makeTip(host) {
    const tip = h("div", { class: "tip", role: "status" });
    tip.hidden = true;
    host.appendChild(tip);
    return {
      show(frame, i, content) {
        tip.textContent = "";
        tip.append(h("div", { class: "tip-title", text: content.title }));
        for (const r of content.rows) {
          tip.append(h("div", { class: "tip-row" },
            h("span", { class: `key ${r.kind || "rect"}`, style: `background:${r.color}` }),
            h("strong", { text: fmtN(r.value) }),
            h("span", { class: "tip-name", text: r.label })));
        }
        if (content.foot) tip.append(h("div", { class: "tip-foot", text: content.foot }));
        tip.hidden = false;
        const hostW = frame.host.clientWidth;
        const w = tip.offsetWidth;
        // beside the hovered day, flipping to the left near the right edge, so the lines stay visible
        let left = frame.cx(i) + 18;
        if (left + w > hostW - 4) left = frame.cx(i) - w - 18;
        left = Math.max(4, left);
        tip.style.left = `${left}px`;
        tip.style.top = `${frame.m.t + 4}px`;
      },
      hide() { tip.hidden = true; },
    };
  }

  // ------------------------------------------------------------------ chart 1: stacked columns
  function drawTotals(agg) {
    const host = $("#chart-total");
    const { days, total } = agg;
    const maxVal = Math.max(0, ...days.map((_, i) => total.ok[i] + total.bad[i]));
    const f = makeFrame(host, days, maxVal, 240);
    const tip = makeTip(host);
    const barW = Math.max(1, Math.min(24, f.band - 2));
    const gap = 2, r = 4;
    const sent = "var(--c-sent)", bad = "var(--c-bad)";
    const wash = el("rect", { y: f.m.t, height: f.ph, class: "wash", visibility: "hidden" }, f.svg);
    days.forEach((d, i) => {
      const hOk = (total.ok[i] / f.top) * f.ph, hBad = (total.bad[i] / f.top) * f.ph;
      const x = f.cx(i) - barW / 2;
      const base = f.m.t + f.ph;
      const okH = total.ok[i] ? Math.max(2, hOk) : 0;
      const badH = total.bad[i] ? Math.max(2, hBad) : 0;
      if (okH) el("path", { d: topRounded(x, base - okH, barW, okH, badH ? 0 : r), fill: sent }, f.svg);
      if (badH) el("path", { d: topRounded(x, base - okH - (okH ? gap : 0) - badH, barW, badH, r), fill: bad }, f.svg);
    });
    // hit areas: bigger than the marks, keyboard focusable
    days.forEach((d, i) => {
      const t = total.ok[i] + total.bad[i];
      const hit = el("rect", { x: f.cx(i) - f.band / 2, y: f.m.t, width: f.band, height: f.ph, fill: "transparent",
        tabindex: 0, role: "img", "aria-label": `${fmtLong(d)}: ${fmtN(total.ok[i])} sent, ${fmtN(total.bad[i])} failed or partial` }, f.svg);
      const on = () => {
        wash.setAttribute("x", f.cx(i) - f.band / 2); wash.setAttribute("width", f.band); wash.setAttribute("visibility", "visible");
        tip.show(f, i, { title: fmtLong(d), rows: [
          { color: sent, value: total.ok[i], label: "Sent" },
          { color: bad, value: total.bad[i], label: "Failed or partial" }], foot: `${fmtN(t)} total` });
      };
      const off = () => { wash.setAttribute("visibility", "hidden"); tip.hide(); };
      hit.addEventListener("pointerenter", on); hit.addEventListener("focus", on);
      hit.addEventListener("pointerleave", off); hit.addEventListener("blur", off);
    });
  }

  // ------------------------------------------------------------------ chart 2: one line per key
  function seriesFor(agg) {
    const shown = agg.keys.filter((k) => k.sent > 0);
    const top = shown.slice(0, TOP_KEYS).map((k, i) => ({ id: k.id, name: k.name, color: `var(${SERIES_VARS[i]})`, vals: k.ok, total: k.sent, bad: k.bad }));
    const rest = shown.slice(TOP_KEYS);
    if (rest.length) {
      const vals = agg.days.map((_, i) => rest.reduce((s, k) => s + k.ok[i], 0));
      const bad = agg.days.map((_, i) => rest.reduce((s, k) => s + k.bad[i], 0));
      top.push({ id: "other", name: `All other keys (${rest.length})`, color: "var(--c-other)", vals, total: agg.sum(vals), bad });
    }
    return top;
  }

  function drawLegend(series) {
    const legend = $("#legend-keys");
    legend.textContent = "";
    for (const s of series) {
      const btn = h("button", { type: "button", class: `legend-item${state.hidden.has(s.id) ? " off" : ""}`,
        "aria-pressed": String(!state.hidden.has(s.id)), title: "Click to show or hide this line" },
        h("span", { class: "key line", style: `background:${s.color}` }),
        h("span", { class: "legend-name", text: s.name }),
        h("span", { class: "legend-total", text: fmtN(s.total) }));
      btn.addEventListener("click", () => {
        state.hidden.has(s.id) ? state.hidden.delete(s.id) : state.hidden.add(s.id);
        drawKeys(state.agg);
      });
      legend.appendChild(btn);
    }
  }

  function drawKeys(agg) {
    const host = $("#chart-keys");
    const all = seriesFor(agg);
    drawLegend(all);
    const visible = all.filter((s) => !state.hidden.has(s.id));
    $("#keys-empty").hidden = all.length > 0;
    host.hidden = all.length === 0;
    if (!all.length) return;
    const { days } = agg;
    const maxVal = Math.max(0, ...visible.flatMap((s) => s.vals));
    const f = makeFrame(host, days, maxVal, 300);
    const tip = makeTip(host);
    const cross = el("line", { y1: f.m.t, y2: f.m.t + f.ph, class: "cross", visibility: "hidden" }, f.svg);
    for (const s of visible) {
      const pts = s.vals.map((v, i) => `${f.cx(i).toFixed(1)},${f.y(v).toFixed(1)}`).join(" ");
      el("polyline", { points: pts, fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, f.svg);
    }
    // end dots (>= 8px, with a surface ring) + direct labels when there are few lines and they don't collide
    const last = days.length - 1;
    const ends = visible.map((s) => ({ s, y: f.y(s.vals[last]) })).sort((a, b) => a.y - b.y);
    for (const { s, y } of ends) el("circle", { cx: f.cx(last), cy: y, r: 4, fill: s.color, stroke: "var(--surface)", "stroke-width": 2 }, f.svg);
    const roomy = ends.every((e, i) => i === 0 || e.y - ends[i - 1].y >= 14);
    if (visible.length <= 4 && roomy && f.band > 0) {
      for (const { s, y } of ends) {
        const t = el("text", { x: f.cx(last) - 10, y: y - 8, "text-anchor": "end", class: "end-label" }, f.svg);
        t.textContent = s.name.length > 28 ? `${s.name.slice(0, 27)}…` : s.name;
      }
    }
    const dots = visible.map((s) => el("circle", { r: 4, fill: s.color, stroke: "var(--surface)", "stroke-width": 2, visibility: "hidden" }, f.svg));
    days.forEach((d, i) => {
      const hit = el("rect", { x: f.cx(i) - f.band / 2, y: f.m.t, width: f.band, height: f.ph, fill: "transparent", tabindex: 0, role: "img",
        "aria-label": `${fmtLong(d)}: ${visible.map((s) => `${s.name} ${fmtN(s.vals[i])}`).join(", ")}` }, f.svg);
      const on = () => {
        cross.setAttribute("x1", f.cx(i)); cross.setAttribute("x2", f.cx(i)); cross.setAttribute("visibility", "visible");
        visible.forEach((s, k) => { dots[k].setAttribute("cx", f.cx(i)); dots[k].setAttribute("cy", f.y(s.vals[i])); dots[k].setAttribute("visibility", "visible"); });
        const rows = visible.map((s) => ({ color: s.color, kind: "line", value: s.vals[i], label: s.name })).sort((a, b) => b.value - a.value);
        const sum = rows.reduce((t, r) => t + r.value, 0);
        tip.show(f, i, { title: fmtLong(d), rows: rows.slice(0, 9), foot: `${fmtN(sum)} sent by the lines shown` });
      };
      const off = () => { cross.setAttribute("visibility", "hidden"); dots.forEach((c) => c.setAttribute("visibility", "hidden")); tip.hide(); };
      hit.addEventListener("pointerenter", on); hit.addEventListener("focus", on);
      hit.addEventListener("pointerleave", off); hit.addEventListener("blur", off);
    });
  }

  // ------------------------------------------------------------------ KPI tiles + data tables
  function drawKpis(agg) {
    const sent = agg.sum(agg.total.ok), bad = agg.sum(agg.total.bad);
    let best = 0;
    agg.days.forEach((_, i) => { if (agg.total.ok[i] > agg.total.ok[best]) best = i; });
    const tiles = [
      ["Sent", fmtN(sent)],
      ["Failed or partial", fmtN(bad)],
      ["Daily average sent", agg.days.length ? (sent / agg.days.length).toLocaleString(undefined, { maximumFractionDigits: 1 }) : "0"],
      ["Busiest day", sent ? `${fmtShort(agg.days[best])} · ${fmtN(agg.total.ok[best])}` : "—"],
    ];
    const box = $("#c-kpis");
    box.textContent = "";
    for (const [l, v] of tiles) box.append(h("div", { class: "stat" }, h("div", { class: "n", text: v }), h("div", { class: "l", text: l })));
  }

  function drawTables(agg) {
    const keyBody = $("#table-keys");
    keyBody.textContent = "";
    for (const k of agg.keys) {
      keyBody.append(h("tr", {}, h("td", { text: k.name + (k.revoked ? " (revoked)" : "") }), h("td", { text: k.username }),
        h("td", { text: fmtN(k.sent) }), h("td", { text: fmtN(k.problems) }), h("td", { text: fmtN(k.sent + k.problems) })));
    }
    const dayBody = $("#table-days");
    dayBody.textContent = "";
    agg.days.forEach((d, i) => {
      dayBody.append(h("tr", {}, h("td", { text: fmtLong(d) }), h("td", { text: fmtN(agg.total.ok[i]) }),
        h("td", { text: fmtN(agg.total.bad[i]) }), h("td", { text: fmtN(agg.total.ok[i] + agg.total.bad[i]) })));
    });
  }

  function render() {
    if (!state.raw || !$("#tab-charts") || $("#tab-charts").classList.contains("hidden")) return;
    const agg = aggregate();
    state.agg = agg;
    $("#c-range-label").textContent = `${fmtLong(state.from)} – ${fmtLong(state.to)} · ${agg.days.length} day${agg.days.length === 1 ? "" : "s"} · ${Intl.DateTimeFormat().resolvedOptions().timeZone}`;
    drawKpis(agg);
    drawTotals(agg);
    drawKeys(agg);
    drawTables(agg);
  }

  // ------------------------------------------------------------------ boot
  window.loadCharts = function loadCharts() {
    if (!state.from) {
      document.querySelectorAll("#c-presets button").forEach((b) => b.addEventListener("click", () => applyPreset(Number(b.dataset.days))));
      $("#c-from").addEventListener("change", onCustomChange);
      $("#c-to").addEventListener("change", onCustomChange);
      let raf = 0, lastW = 0;
      new ResizeObserver(() => {
        const w = $("#charts-root").clientWidth;
        if (w === lastW) return; // only react to width changes; rendering changes the height
        lastW = w;
        cancelAnimationFrame(raf); raf = requestAnimationFrame(render);
      }).observe($("#charts-root"));
      applyPreset(14); // default: the past two weeks
    } else {
      load(); // refresh when returning to the tab
    }
  };
})();
