(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = window.escapeHtml;
  const api = async (path, opts) => {
    const r = await fetch(path, opts);
    let j = {};
    try { j = await r.json(); } catch (e) { /* non-JSON */ }
    if (!r.ok) throw new Error(j.error || j.detail || `HTTP ${r.status}`);
    return j;
  };
  const post = (p, b) => api(p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) });
  let toastT;
  function toast(msg, err) {
    const t = $("#toast"); t.textContent = msg; t.className = "toast" + (err ? " err" : ""); t.hidden = false;
    clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), err ? 9000 : 4000);
  }
  const iso = (ts) => new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19);
  const dur = (n) => (n >= 3600 ? Math.floor(n / 3600) + "h" : "") + (n >= 60 ? Math.floor((n % 3600) / 60) + "m" : "") + (n % 60) + "s";
  const NORMAL = new Set([0, 16, 31, 393216, 458752]);

  /* ---------- theme ---------- */
  try { const t = localStorage.getItem("cca-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
  $("#theme").onclick = () => {
    const dark = getComputedStyle(document.documentElement).colorScheme === "dark";
    const n = dark ? "light" : "dark"; document.documentElement.dataset.theme = n;
    try { localStorage.setItem("cca-theme", n); } catch (e) {}
  };

  /* ---------- tabs ---------- */
  function show(view) {
    $$(".view").forEach((v) => v.classList.toggle("on", v.id === "view-" + view));
    $$("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
    if (view === "data") loadStatus();
    if (view === "settings") loadSettings();
  }
  $("#tabs").onclick = (e) => { const b = e.target.closest("button"); if (b) show(b.dataset.view); };

  /* ---------- status ---------- */
  let STATUS = null;
  async function loadStatus() {
    STATUS = await api("/api/status");
    const s = STATUS.stats;
    $("#stats").innerHTML = `<span><b>${s.cdr}</b> CDRs</span><span><b>${s.cmr}</b> CMRs</span><span><b>${s.sip}</b> SIP msgs</span>`;
    $("#datasummary").textContent = s.cdr ? `CDRs ${iso(s.first)} → ${iso(s.last)} UTC` : "nothing loaded yet";
    $("#filesbody").innerHTML = STATUS.files.map((f) =>
      `<tr><td>${esc(f.loaded_at.replace("T", " "))}</td><td><span class="badge mute">${esc(f.kind)}</span></td><td class="mono">${esc(f.name)}</td><td>${esc(f.node)}</td><td class="num">${f.records}</td><td class="num">${(f.size / 1024).toFixed(1)} KB</td></tr>`).join("") || `<tr><td colspan="6" class="empty">No files loaded.</td></tr>`;
  }

  /* ---------- search ---------- */
  const localToUtcIso = (v) => (v ? v + ":00Z" : "");
  async function search(e) {
    if (e) e.preventDefault();
    const f = new FormData($("#searchform")); const q = new URLSearchParams();
    for (const k of ["number", "calling", "called", "device"]) if (f.get(k)) q.set(k, f.get(k).trim());
    if (f.get("start")) q.set("start", localToUtcIso(f.get("start")));
    if (f.get("end")) q.set("end", localToUtcIso(f.get("end")));
    if (f.get("failed")) q.set("failed", "true");
    const { calls } = await api("/api/calls?" + q);
    const box = $("#callstable");
    if (!calls.length) { box.innerHTML = `<div class="empty">${STATUS && STATUS.stats.cdr ? "No calls match." : "No CDRs loaded. Use the Data tab to pull from CUCM or upload files."}</div>`; return; }
    box.innerHTML = `<table><thead><tr><th>Time (UTC)</th><th>Calling</th><th>Original called</th><th>Final called</th><th>Orig device</th><th>Dest device</th><th class="num">Duration</th><th>Result</th></tr></thead><tbody>` +
      calls.map((c) => {
        const bad = (!NORMAL.has(c.orig_cause)) || (!NORMAL.has(c.dest_cause));
        const res = !c.connect_ts ? '<span class="badge warn">not answered</span>' : bad ? `<span class="badge error">cause ${c.orig_cause}/${c.dest_cause}</span>` : '<span class="badge ok">normal</span>';
        return `<tr class="click" data-key="${esc(c.call_key)}"><td class="mono">${iso(c.orig_ts)}</td><td class="mono">${esc(c.calling)}</td><td class="mono">${esc(c.orig_called)}</td><td class="mono">${esc(c.final_called)}</td><td>${esc(c.orig_device)}</td><td>${esc(c.dest_device)}</td><td class="num">${dur(c.duration)}${c.legs > 1 ? ` <span class="badge mute">${c.legs} legs</span>` : ""}</td><td>${res}</td></tr>`;
      }).join("") + "</tbody></table>";
  }
  $("#searchform").onsubmit = search;
  $("#resetsearch").onclick = () => setTimeout(search, 0);
  $("#callstable").onclick = (e) => { const tr = e.target.closest("tr.click"); if (tr) openCall(tr.dataset.key); };

  /* ---------- call detail ---------- */
  let CUR = null, SELECTED = null;
  async function openCall(key, dialogs) {
    CUR = key;
    show("call"); $("#tab-call").hidden = false;
    $("#callroot").innerHTML = '<div class="empty">Loading…</div>';
    const q = "key=" + encodeURIComponent(key) + (dialogs ? "&dialogs=" + encodeURIComponent(dialogs.join("\n")) : "");
    try {
      const D = await api("/api/call?" + q);
      renderCall($("#callroot"), D, { onSelect: (ids) => { SELECTED = ids; refreshFindings(); } });
      SELECTED = $("#callroot").__selected ? $("#callroot").__selected() : null;
      $("#exportbtn").href = "/api/call/export?key=" + encodeURIComponent(key) + (SELECTED ? "&dialogs=" + encodeURIComponent(SELECTED.join("\n")) : "");
      $("#callbarmsg").textContent = D.ladder.has_traces ? "" : "No SIP traces for this call yet.";
    } catch (e) { $("#callroot").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  }
  async function refreshFindings() {
    if (!CUR) return;
    try {
      const { findings } = await post("/api/call/findings", { key: CUR, dialogs: SELECTED });
      const order = { error: 0, warn: 1, info: 2 };
      const ul = $("#findings .findings");
      if (ul) ul.innerHTML = findings.sort((a, b) => order[a.level] - order[b.level]).map((f) =>
        `<li><span><span class="badge ${f.level}">${f.level}</span></span><div><div class="t">${esc(f.title)}</div>${f.detail ? `<div class="d">${esc(f.detail)}</div>` : ""}</div></li>`).join("");
      $("#exportbtn").href = "/api/call/export?key=" + encodeURIComponent(CUR) + "&dialogs=" + encodeURIComponent(SELECTED.join("\n"));
    } catch (e) { /* keep old */ }
  }
  $("#backbtn").onclick = () => show("calls");
  $("#sdlbtn").onclick = async () => {
    if (!CUR) return;
    $("#sdlbtn").disabled = true;
    try {
      const j = await post("/api/call/sdl", { key: CUR });
      await watchJob(j.id, $("#sdljob"));
      await loadStatus();
      await openCall(CUR);
    } catch (e) { toast(e.message, true); }
    $("#sdlbtn").disabled = false;
  };

  /* ---------- jobs ---------- */
  async function watchJob(id, box) {
    for (;;) {
      const j = await api("/api/jobs/" + id);
      box.innerHTML = `<div class="bar"><i style="width:${Math.round(j.progress * 100)}%"></i></div><pre class="joblog">${esc(j.log.join("\n"))}</pre>`;
      const pre = $(".joblog", box); if (pre) pre.scrollTop = pre.scrollHeight;
      if (j.state !== "running") { if (j.state === "error") toast("Job failed. See the log.", true); return j; }
      await new Promise((r) => setTimeout(r, 1000));
    }
  }

  /* ---------- data tab ---------- */
  function setRange(mins) {
    const end = new Date(), start = new Date(end.getTime() - mins * 60000);
    const f = (d) => d.toISOString().slice(0, 16);
    $("#cdr-start").value = f(start); $("#cdr-end").value = f(end);
  }
  $$("[data-quick]").forEach((b) => (b.onclick = () => setRange(+b.dataset.quick)));
  setRange(60);
  $("#cdr-pull").onclick = async () => {
    $("#cdr-pull").disabled = true;
    try {
      const j = await post("/api/cdr/fetch", { start: localToUtcIso($("#cdr-start").value), end: localToUtcIso($("#cdr-end").value) });
      await watchJob(j.id, $("#cdrjob"));
      await loadStatus(); search();
    } catch (e) { toast(e.message, true); }
    $("#cdr-pull").disabled = false;
  };
  const drop = $("#drop"), pick = $("#filepick");
  drop.onclick = () => pick.click();
  ["dragover", "dragenter"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => upload(e.dataTransfer.files));
  pick.onchange = () => upload(pick.files);
  async function upload(files) {
    if (!files.length) return;
    const fd = new FormData();
    [...files].forEach((f) => fd.append("files", f));
    fd.append("node", $("#up-node").value); fd.append("trace_date", $("#up-date").value);
    $("#upresult").innerHTML = '<p class="hint">Uploading…</p>';
    try {
      const j = await api("/api/upload", { method: "POST", body: fd });
      $("#upresult").innerHTML = `<div class="tablewrap" style="margin-top:10px"><table><thead><tr><th>File</th><th>Type</th><th class="num">Records</th><th>Note</th></tr></thead><tbody>` +
        j.results.map((r) => `<tr><td class="mono">${esc(r.file)}</td><td>${esc(r.kind || "—")}</td><td class="num">${r.records}</td><td>${esc(r.note)}</td></tr>`).join("") + "</tbody></table></div>";
      await loadStatus(); search();
    } catch (e) { $("#upresult").innerHTML = ""; toast(e.message, true); }
    pick.value = "";
  }
  $$("[data-clear]").forEach((b) => (b.onclick = async () => {
    if (!confirm("Remove the loaded " + (b.dataset.clear === "sip" ? "SIP traces" : "CDR/CMR data") + "?")) return;
    await post("/api/clear", { what: b.dataset.clear }); await loadStatus(); search();
  }));

  /* ---------- settings ---------- */
  function getPath(o, p) { return p.split(".").reduce((a, k) => (a == null ? a : a[k]), o); }
  function setPath(o, p, v) { const ks = p.split("."); let a = o; ks.slice(0, -1).forEach((k) => (a = a[k] = a[k] || {})); a[ks.at(-1)] = v; }
  async function loadSettings() {
    const s = await api("/api/settings");
    $$("#settingsform [name]").forEach((el) => {
      const n = el.name;
      if (n.startsWith("secret.")) { el.value = ""; el.placeholder = s.secrets_set[n.slice(7)] ? "•••••• (set)" : el.placeholder; return; }
      let v = getPath(s.settings || s, n);
      if (n === "cucm.node_addresses") v = Object.entries(v || {}).map(([k, x]) => `${k}=${x}`).join("\n");
      if (el.type === "checkbox") el.checked = !!v; else el.value = v ?? "";
    });
    toggleDelivery();
    const st = (await api("/api/status")).receiver;
    $("#recvstatus").textContent = st.mode === "embedded" ? (st.running ? `Receiver listening on port ${st.port}; CUCM will be told to connect to ${st.advertise_host || "?"}.` : `Receiver is NOT running: ${st.error || "unknown error"}`) : "";
  }
  function toggleDelivery() {
    const emb = $("[name='cdr_delivery.mode']").value === "embedded";
    $("#emb-fields").style.display = emb ? "" : "none"; $("#ext-fields").style.display = emb ? "none" : "";
  }
  $("[name='cdr_delivery.mode']").onchange = toggleDelivery;
  function collect() {
    const out = {}, secrets = {};
    $$("#settingsform [name]").forEach((el) => {
      const n = el.name; let v = el.type === "checkbox" ? el.checked : el.type === "number" ? +el.value : el.value.trim();
      if (n.startsWith("secret.")) { if (v) secrets[n.slice(7)] = v; return; }
      if (n === "cucm.node_addresses") { const m = {}; v.split("\n").forEach((l) => { const [a, ...b] = l.split("="); if (a && b.length) m[a.trim()] = b.join("=").trim(); }); v = m; }
      setPath(out, n, v);
    });
    out.secrets = secrets; return out;
  }
  async function saveSettings() { const r = await post("/api/settings", collect()); toast("Settings saved"); loadSettings(); return r; }
  $("#settingsform").onsubmit = async (e) => { e.preventDefault(); try { await saveSettings(); } catch (x) { toast(x.message, true); } };
  $("#testbtn").onclick = async () => {
    const out = $("#testout"); out.hidden = false; out.textContent = "Saving and testing…";
    try {
      await saveSettings();
      const r = await post("/api/test");
      out.textContent = `CDR on Demand : ${r.cdr_on_demand}\nLog Collection: ${r.log_collection}\n` +
        (r.node_addresses ? Object.entries(r.node_addresses).map(([n, a]) => `  node ${n} → ${a}`).join("\n") + "\n" : "") +
        `SFTP receiver : ${r.receiver.mode === "embedded" ? (r.receiver.running ? "listening on " + r.receiver.port : "NOT RUNNING " + r.receiver.error) : "external"}`;
    } catch (e) { out.textContent = "FAILED: " + e.message; }
  };
  $("#discoverbtn").onclick = async () => {
    try { await saveSettings(); const r = await post("/api/nodes/discover"); toast("Nodes: " + r.nodes.join(", ")); } catch (e) { toast(e.message, true); }
  };

  /* ---------- boot ---------- */
  (async function () {
    await loadStatus();
    if (!STATUS.configured && !STATUS.stats.cdr) show("settings");
    search();
  })();
})();
