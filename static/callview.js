/* Call view: header, findings, SIP ladder (SVG), CDR legs, voice quality.
   Shared by the live app and the exported static HTML report. */
(function () {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const pad = (n, w = 2) => String(n).padStart(w, "0");
  const tz = { mode: "utc" };

  function fmtTime(ts, ms = true, date = false) {
    const d = new Date(ts * 1000);
    const u = tz.mode === "utc";
    const H = u ? d.getUTCHours() : d.getHours(), M = u ? d.getUTCMinutes() : d.getMinutes(), S = u ? d.getUTCSeconds() : d.getSeconds();
    const MS = u ? d.getUTCMilliseconds() : d.getMilliseconds();
    let s = `${pad(H)}:${pad(M)}:${pad(S)}` + (ms ? "." + pad(MS, 3) : "");
    if (date) {
      const y = u ? d.getUTCFullYear() : d.getFullYear(), mo = (u ? d.getUTCMonth() : d.getMonth()) + 1, dd = u ? d.getUTCDate() : d.getDate();
      s = `${y}-${pad(mo)}-${pad(dd)} ` + s;
    }
    return s + (u ? "Z" : "");
  }
  const fmtDur = (n) => (n >= 3600 ? Math.floor(n / 3600) + "h " : "") + (n >= 60 ? Math.floor((n % 3600) / 60) + "m " : "") + (n % 60) + "s";
  const epochOrBlank = (t, date = true) => (t ? fmtTime(t, false, date) : "—");

  /* ---------------- ladder ---------------- */
  function ladderSvg(L, selectedIds, opts) {
    const msgs = L.messages.filter((m) => selectedIds.has(m.call_id) && (opts.showRetrans || !m.retrans) && (opts.showAll || !(opts.hideOptions && m.method === "OPTIONS")));
    if (!msgs.length) return { svg: '<div class="empty">No SIP messages for the selected dialogs.</div>', msgs };
    // participants used, ordered: first-seen along messages, CUCM nodes to the middle-left
    const used = [];
    msgs.forEach((m) => { [m.from, m.to].forEach((k) => { if (!used.includes(k)) used.push(k); }); });
    const rank = (k) => (L.participants[k].kind === "cucm-node" ? 1 : 0);
    const nodes = used.filter((k) => rank(k)), others = used.filter((k) => !rank(k));
    // endpoints which sent the first INVITE go left; the rest right of the nodes
    const first = msgs.find((m) => m.method === "INVITE") || msgs[0];
    const left = [], right = [];
    // the party that sent the first INVITE sits left of the CUCM node(s); everyone else sits right
    others.forEach((k) => { (k === first.from ? left : right).push(k); });
    const order = [...left, ...nodes, ...right];
    const COL = Math.max(190, Math.min(250, 1100 / Math.max(order.length, 1)));
    const X0 = 96, TOP = 76, ROW = 46, W = X0 + order.length * COL + 40;
    const xs = Object.fromEntries(order.map((k, i) => [k, X0 + i * COL + COL / 2 - 40]));
    const H = TOP + msgs.length * ROW + 24;
    const dialogColor = Object.fromEntries(L.dialogs.map((d) => [d.call_id, d.color]));
    const colVar = (c) => `var(--d${c})`;
    let s = `<svg class="ladder" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="SIP ladder diagram">`;
    s += `<defs>${[0, 1, 2, 3, 4, 5, 6, 7].map((c) => `<marker id="ar${c}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="${colVar(c)}"/></marker>`).join("")}</defs>`;
    order.forEach((k) => {
      const p = L.participants[k], x = xs[k], isN = p.kind === "cucm-node";
      s += `<line class="lifeline" x1="${x}" y1="${TOP - 6}" x2="${x}" y2="${H - 10}"/>`;
      const nm = esc(clip(p.name || p.ip, 26));
      s += `<g><rect class="pbox ${isN ? "node" : ""}" x="${x - 84}" y="8" width="168" height="${TOP - 24}" rx="7"/>`
        + `<text class="pkind" x="${x}" y="22" text-anchor="middle">${esc(isN ? "CUCM node" : p.kind || "")}</text>`
        + `<text class="pname ${isN ? "node" : ""}" x="${x}" y="38" text-anchor="middle">${nm}</text>`
        + `<text class="pip ${isN ? "node" : ""}" x="${x}" y="53" text-anchor="middle">${esc(p.ip || "")}${p.port && !isN ? ":" + esc(p.port) : ""}</text></g>`;
    });
    const t0 = msgs[0].ts;
    msgs.forEach((m, i) => {
      const y = TOP + i * ROW + 22, x1 = xs[m.from], x2 = xs[m.to], c = dialogColor[m.call_id] ?? 7;
      const prev = i ? msgs[i - 1].ts : m.ts;
      const col = m.status >= 400 ? "var(--err)" : colVar(c);
      const dash = m.retrans ? ' stroke-dasharray="5 4" opacity=".6"' : m.status && m.status < 200 ? ' stroke-dasharray="2 3"' : "";
      s += `<g class="row" data-i="${msgs.indexOf(m)}" data-id="${m.id}"><rect class="hit" x="0" y="${y - 22}" width="${W}" height="${ROW}"/>`;
      s += `<text class="ts" x="8" y="${y - 3}">${fmtTime(m.ts)}</text><text class="dt" x="8" y="${y + 10}">${i ? "+" + (m.ts - t0).toFixed(3) + "s" : ""}${i && m.ts - prev > 1 ? " Δ" + (m.ts - prev).toFixed(1) : ""}</text>`;
      if (x1 === x2) {
        s += `<path d="M${x1},${y - 8} h34 v16 h-34" fill="none" stroke="${col}" stroke-width="1.8" marker-end="url(#ar${c})"${dash}/>`;
        s += `<text class="lbl" x="${x1 + 42}" y="${y + 4}" fill="${col}">${esc(m.label)}</text>`;
      } else {
        const dir = x2 > x1 ? 1 : -1, a = x1 + dir * 4, b = x2 - dir * 2;
        s += `<line x1="${a}" y1="${y}" x2="${b}" y2="${y}" stroke="${col}" stroke-width="1.8" marker-end="url(#ar${c})"${dash}/>`;
        const mx = (x1 + x2) / 2;
        s += `<text class="lbl" x="${mx}" y="${y - 6}" text-anchor="middle" fill="${col}">${esc(m.label)}${m.retrans ? " (retrans)" : ""}</text>`;
        const sub = [m.sdp, m.cseq && !m.is_request ? "" : ""].filter(Boolean).join(" ");
        if (sub) s += `<text class="sdp" x="${mx}" y="${y + 13}" text-anchor="middle">${esc(clip(sub, Math.floor(Math.abs(x2 - x1) / 5.6)))}</text>`;
      }
      s += `</g>`;
    });
    s += "</svg>";
    return { svg: s, msgs };
  }
  const clip = (t, n) => (t.length > n ? t.slice(0, n - 1) + "…" : t);

  function highlightSip(raw) {
    const lines = raw.split("\n");
    let inSdp = false;
    return lines.map((ln, i) => {
      const e = esc(ln);
      if (i === 0) return `<span class="fl">${e}</span>`;
      if (!ln.trim()) { inSdp = true; return e; }
      if (inSdp) return `<span class="sdp">${e}</span>`;
      const c = e.indexOf(":");
      return c > 0 ? `<span class="hn">${e.slice(0, c)}</span>${e.slice(c)}` : e;
    }).join("\n");
  }

  /* ---------------- sections ---------------- */
  function head(D) {
    const L0 = D.legs[0] || {};
    const first = Math.min(...D.legs.map((l) => l.orig_ts).filter(Boolean));
    const last = Math.max(...D.legs.map((l) => l.disconnect_ts || l.orig_ts));
    const dur = Math.max(...D.legs.map((l) => l.duration));
    const err = D.findings.filter((f) => f.level === "error").length, warn = D.findings.filter((f) => f.level === "warn").length;
    const status = err ? '<span class="badge error">problems found</span>' : warn ? '<span class="badge warn">warnings</span>' : '<span class="badge ok">looks normal</span>';
    return `<div class="panel"><div class="callhead">
      <div><div class="parties">${esc(L0.calling || "?")}<span class="arr">→</span>${esc(L0.orig_called || L0.final_called || "?")}</div>
      <div class="meta"><span>${epochOrBlank(first)}</span><span>Duration <b>${fmtDur(dur)}</b></span><span>${D.legs.length} CDR leg${D.legs.length > 1 ? "s" : ""}</span>
      <span class="mono">${esc(D.call_key)}</span>${status}</div></div>
      <div class="actions"></div></div></div>`;
  }

  function findingsPanel(D) {
    if (!D.findings.length) return "";
    const order = { error: 0, warn: 1, info: 2 };
    const items = [...D.findings].sort((a, b) => order[a.level] - order[b.level]).map((f) =>
      `<li><span><span class="badge ${f.level === "info" ? "info" : f.level}">${f.level}</span></span><div><div class="t">${esc(f.title)}</div>${f.detail ? `<div class="d">${esc(f.detail)}</div>` : ""}</div></li>`).join("");
    return `<div class="panel" id="findings"><header><h2>Analysis</h2><span class="sub">from CDR, CMR and the SIP trace</span></header><ul class="findings">${items}</ul></div>`;
  }

  function ladderPanel(D) {
    const L = D.ladder;
    let h = `<div class="panel"><header><h2>SIP ladder</h2><span class="sub" id="ladder-sub"></span></header>`;
    if (!L.has_traces) {
      h += `<div class="empty">No SIP messages loaded for this time window.<br>Use <b>Pull SDL traces</b> above, or upload SDL trace files on the Data tab.</div></div>`;
      return h;
    }
    if (!L.dialogs.length) {
      h += `<div class="empty">${L.sip_in_window} SIP messages exist in this window, but none could be tied to this call.<br>The traces may be from a node that did not handle the call, or the call numbers differ from the SIP URIs.</div></div>`;
      return h;
    }
    h += `<div class="ladder-tools">
      <label class="chk"><input type="checkbox" id="opt-retrans"> Show retransmissions</label>
      <label class="chk"><input type="checkbox" id="opt-options" checked> Hide OPTIONS</label>
      <label class="chk"><input type="radio" name="tzm" value="utc" checked> UTC</label>
      <label class="chk"><input type="radio" name="tzm" value="local"> Browser local time</label></div>`;
    h += `<div class="dialogs" id="dialogs">` + L.dialogs.map((d) =>
      `<label class="dialog"><input type="checkbox" data-cid="${esc(d.call_id)}" ${d.selected ? "checked" : ""}><span class="sw bg${d.color}"></span>
       <span><b>${esc(d.method)}</b> ${esc(d.from_user)} → ${esc(d.to_user)}</span><span class="cid" title="${esc(d.call_id)}">${esc(d.call_id)}</span>
       <span class="why" title="${esc(d.why.join("; "))}">${esc(d.why[0] || "")}${d.why.length > 1 ? " +" + (d.why.length - 1) : ""}${d.score < 2 ? " (weak match)" : ""}</span>
       <span class="fin">${d.final ? `<span class="badge ${/^2/.test(d.final) ? "ok" : /^(4|5|6)/.test(d.final) ? "error" : "mute"}">${esc(d.final)}</span>` : ""}</span></label>`).join("") + `</div>`;
    h += `<div class="ladder-split closed" id="split"><div class="ladder-scroll" id="ladder"></div>
      <aside class="msgpane"><header><div class="meta" id="msgmeta"></div><button class="btn small" id="msgclose">Close</button></header><pre id="msgraw"></pre></aside></div></div>`;
    return h;
  }

  function legsPanel(D) {
    return D.legs.map((l, i) => {
      const grp = l.fields.groups.filter((g) => g.rows.length).map((g) =>
        `<details class="fields" ${g.title === "Parties" || g.title === "Termination" ? "open" : ""}><summary>${esc(g.title)}</summary><div><table class="kv"><tbody>` +
        g.rows.map((r) => `<tr><td>${esc(r.field)}</td><td class="mono">${esc(r.value)}${r.decoded ? `<span class="dec">${esc(r.decoded)}</span>` : ""}</td></tr>`).join("") + `</tbody></table></div></details>`).join("");
      const all = `<details class="fields"><summary>All ${l.fields.all.length} fields</summary><div><table class="kv"><tbody>` +
        l.fields.all.map((r) => `<tr><td>${esc(r.field)}</td><td class="mono">${esc(r.value)}${r.decoded ? `<span class="dec">${esc(r.decoded)}</span>` : ""}</td></tr>`).join("") + `</tbody></table></div></details>`;
      const cause = (v, t) => `${v}${t ? ` <span class="dec" style="color:var(--ink-3)">${esc(t)}</span>` : ""}`;
      return `<div class="panel"><header><h2>CDR leg ${i + 1}</h2><span class="sub">${esc(l.orig_device || "?")} → ${esc(l.dest_device || "?")}</span></header>
        <div class="tablewrap"><table><tbody>
        <tr><th>Calling</th><td class="mono">${esc(l.calling)}</td><th>Original called</th><td class="mono">${esc(l.orig_called)}</td><th>Final called</th><td class="mono">${esc(l.final_called)}</td></tr>
        <tr><th>Originated</th><td>${epochOrBlank(l.orig_ts)}</td><th>Connected</th><td>${epochOrBlank(l.connect_ts)}</td><th>Disconnected</th><td>${epochOrBlank(l.disconnect_ts)}</td></tr>
        <tr><th>Orig device</th><td class="mono">${esc(l.orig_device)} <span class="dec">${esc(l.orig_ip)}</span></td><th>Dest device</th><td class="mono">${esc(l.dest_device)} <span class="dec">${esc(l.dest_ip)}</span></td><th>Duration</th><td>${fmtDur(l.duration)}</td></tr>
        <tr><th>Orig cause</th><td>${cause(l.orig_cause, l.orig_cause_text)}${l.orig_term ? ` · by ${esc(l.orig_term)}` : ""}</td><th>Dest cause</th><td>${cause(l.dest_cause, l.dest_cause_text)}${l.dest_term ? ` · by ${esc(l.dest_term)}` : ""}</td><th>Redirect</th><td>${esc(l.last_redirect)} ${esc(l.redirect_reason)}</td></tr>
        <tr><th>Orig media</th><td class="mono">${esc(l.orig_media)} ${esc(l.orig_codec)}</td><th>Dest media</th><td class="mono">${esc(l.dest_media)} ${esc(l.dest_codec)}</td><th>Security</th><td>${esc(l.secured)}</td></tr>
        </tbody></table></div>
        ${quality(l)}
        <div style="margin-top:12px" class="fieldgroups">${grp}</div>${all}</div>`;
    }).join("");
  }

  function quality(l) {
    if (!l.quality.length) return `<p class="hint">No CMR (voice quality) records for this leg.</p>`;
    const rows = l.quality.map((q) => {
      const tot = q.received + q.lost, loss = tot ? (q.lost / tot) * 100 : 0;
      const mosCls = q.mos == null ? "" : q.mos >= 4 ? "qgood" : q.mos >= 3.6 ? "qwarn" : "qbad";
      return `<tr><td>${esc(q.device)} <span class="badge mute">${q.side}</span></td><td class="num">${q.sent}</td><td class="num">${q.received}</td>
        <td class="num ${loss > 1 ? "qbad" : ""}">${q.lost} (${loss.toFixed(2)}%)</td><td class="num ${q.jitter > 30 ? "qwarn" : ""}">${q.jitter} ms</td>
        <td class="num ${q.latency > 150 ? "qwarn" : ""}">${q.latency} ms</td><td class="num ${mosCls}">${q.mos ?? "—"}</td><td class="num">${q.mos_min ?? "—"}</td><td class="num">${q.ccr ?? "—"}</td></tr>`;
    }).join("");
    return `<h3 style="margin:14px 0 6px">Voice quality (CMR)</h3><div class="tablewrap"><table><thead><tr><th>Device</th><th class="num">Sent</th><th class="num">Received</th><th class="num">Lost</th><th class="num">Jitter</th><th class="num">Latency</th><th class="num">MOS-LQK</th><th class="num">MOS min</th><th class="num">Conceal ratio</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  /* ---------------- main ---------------- */
  window.renderCall = function (root, D, opts = {}) {
    root.innerHTML = head(D) + findingsPanel(D) + ladderPanel(D) + legsPanel(D);
    const L = D.ladder;
    if (!L.has_traces || !L.dialogs.length) return;
    const selected = new Set(L.dialogs.filter((d) => d.selected).map((d) => d.call_id));
    const $ = (id) => root.querySelector("#" + id);
    let cur = null;
    function draw() {
      const { svg, msgs } = ladderSvg(L, selected, { showRetrans: $("opt-retrans").checked, hideOptions: $("opt-options").checked });
      $("ladder").innerHTML = svg;
      $("ladder-sub").textContent = `${msgs.length} messages · ${selected.size} dialog${selected.size === 1 ? "" : "s"} · ${fmtTime(msgs[0]?.ts ?? 0, true, true)}`;
      root.querySelectorAll("svg.ladder .row").forEach((g) => g.addEventListener("click", () => open(msgs[+g.dataset.i], g)));
      if (cur) { const g = root.querySelector(`svg.ladder .row[data-id="${cur}"]`); if (g) g.classList.add("sel"); }
    }
    function open(m, g) {
      cur = m.id;
      root.querySelectorAll("svg.ladder .row.sel").forEach((x) => x.classList.remove("sel"));
      g.classList.add("sel");
      $("split").classList.remove("closed");
      const P = L.participants;
      $("msgmeta").innerHTML = `<b>${esc(m.label)}</b><br>${fmtTime(m.ts, true, true)}<br>${esc(P[m.from].name)} → ${esc(P[m.to].name)}<br>
        ${m.direction === "in" ? "received" : "sent"} by ${esc(m.node || "node")} · ${esc(m.transport)} ${esc(m.remote)}<br><span class="mono">${esc(m.call_id)}</span>`;
      $("msgraw").innerHTML = highlightSip(m.raw);
    }
    $("msgclose").onclick = () => $("split").classList.add("closed");
    root.querySelectorAll("#dialogs input").forEach((cb) => cb.addEventListener("change", () => {
      cb.checked ? selected.add(cb.dataset.cid) : selected.delete(cb.dataset.cid);
      draw();
      if (opts.onSelect) opts.onSelect([...selected]);
    }));
    ["opt-retrans", "opt-options"].forEach((id) => $(id).addEventListener("change", draw));
    root.querySelectorAll('input[name="tzm"]').forEach((r) => r.addEventListener("change", () => { tz.mode = r.value; draw(); }));
    draw();
    root.__selected = () => [...selected];
  };
  window.escapeHtml = esc;
  window.fmtTime = fmtTime;
})();
