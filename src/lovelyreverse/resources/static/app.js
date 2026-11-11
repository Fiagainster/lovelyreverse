/* lovelyreverse workstation UI — vanilla JS, no dependencies */
"use strict";

/* ═══════════════════════ tiny helpers ═══════════════════════ */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hexa = (n) => "0x" + Number(n).toString(16);
const hexpad = (n, w = 8) => "0x" + Number(n).toString(16).padStart(w, "0");
const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const bytesToB64 = (u8) => btoa(String.fromCharCode(...u8));

function funcNameByAddr(addr) {
  for (const [name, a] of S.funcMap) if (a === addr) return name;
  return null;
}

async function api(path, opts = {}) {
  const res = await fetch("/api/" + path, opts);
  let body = null;
  try { body = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw new Error((body && body.error) || `HTTP ${res.status}`);
  return body;
}

function toast(msg, cls = "info", ms = 4200) {
  const el = document.createElement("div");
  el.className = `toast ${cls}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), ms);
}

function logLine(msg, cls = "") {
  const v = $("#logview");
  const t = new Date().toLocaleTimeString();
  v.innerHTML += `<div><span class="t">${t}</span> ${cls ? `<span class="${cls}">` : ""}${esc(msg)}${cls ? "</span>" : ""}</div>`;
  while (v.childElementCount > 600) v.firstChild.remove();
  v.scrollTop = v.scrollHeight;
}

/* theme-aware canvas colors: read once per draw from CSS custom props */
function graphPalette() {
  const cs = getComputedStyle(document.documentElement);
  const g = (n) => cs.getPropertyValue(n).trim();
  return {
    bg: g("--graph-bg"), edge: g("--graph-edge"), edgeHi: g("--graph-edge-hi"),
    text: g("--graph-text"), addr: g("--graph-addr"),
    fill: g("--graph-node-fill"), fillHover: g("--graph-node-hover"),
    stroke: g("--graph-node-stroke"), caller: g("--graph-caller"), callee: g("--graph-callee"),
    rose: g("--rose"), cyan: g("--cyan"), amber: g("--amber"),
    roseRgb: g("--rose-rgb"),
  };
}

/* ── modals ── */
function openModal(sel) { $(sel).classList.remove("hidden"); }
function closeModal(sel) { $(sel).classList.add("hidden"); }

let askResolve = null;
function askText(title, initial) {
  return new Promise((resolve) => {
    askResolve = resolve;
    $("#ask-title").textContent = title;
    $("#ask-input").value = initial || "";
    openModal("#modal-ask");
    $("#ask-input").focus();
    $("#ask-input").select();
  });
}
function closeAsk(value) {
  closeModal("#modal-ask");
  if (askResolve) { const r = askResolve; askResolve = null; r(value); }
}

/* ── F3: one-click send to the decoder lab ── */
function sendToDecoder(text, mode = "text") {
  $("#dec-input").value = text;
  const radio = document.querySelector(`input[name="dec-mode"][value="${mode}"]`);
  if (radio) radio.checked = true;
  $("#drawer").classList.remove("closed");
  $("#drawer").classList.add("open"); // keep the two state classes mutually exclusive
  $("#drawer-toggle").textContent = t("drawer.hide");
  $$("#drawer-tabs .tab").forEach((tb) => tb.classList.toggle("active", tb.dataset.tab === "decoder"));
  $$("#drawer-body > .tabpane").forEach((p) => p.classList.toggle("active", p.dataset.pane === "decoder"));
  toast(t("toast.sent"), "info", 1800);
}

function fmtSize(n) {
  n = Number(n);
  if (!Number.isFinite(n)) return "—";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}

/* ── X2: right-click context menu ── */

function openCtxMenu(x, y, items) {
  const m = $("#ctx-menu");
  m.innerHTML = items.map((it, i) =>
    it === "-" ? `<div class="menu-sep"></div>`
      : `<div class="menu-item" data-i="${i}"${it.title ? ` title="${esc(it.title)}"` : ""}>${it.icon ? `<span class="mi-icon">${it.icon}</span>` : ""}<span class="mi-name">${esc(it.label)}</span></div>`).join("");
  m.classList.remove("hidden");
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 8)) + "px";
  m.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 8)) + "px";
  m.querySelectorAll(".menu-item").forEach((el) =>
    el.onclick = () => { m.classList.add("hidden"); items[Number(el.dataset.i)].run(); });
}

function closeCtxMenu() {
  const m = $("#ctx-menu");
  if (m) m.classList.add("hidden");
}

/* IDA-style: jump to a string's first referencing function, highlight the line */
async function jumpStringRef(sAddr) {
  try {
    const res = await api(`xrefs/${sAddr}`);
    const refs = res.to.filter((r) => r.function_addr != null);
    if (refs.length) {
      const r0 = refs[0];
      selectFunction(r0.function_addr, r0.function || hexpad(r0.function_addr), {
        highlightAddr: r0.addr,
        highlightTarget: sAddr,
      });
    } else toast(t("toast.no_refs"), "info");
  } catch (e) { toast(e.message, "error"); }
}

document.addEventListener("contextmenu", (e) => {
  closeCtxMenu();

  // ── symbol in decompiled C (function name / address)
  const sym = e.target.closest("#code-decompile .a, #code-decompile .f");
  if (sym && sym.dataset.addr) {
    e.preventDefault();
    const addr = parseInt(sym.dataset.addr, 16);
    const name = sym.dataset.name || sym.textContent;
    const items = [
      { icon: "⌖", label: t("ctx.jump"), run: () => navigateAddr(addr, name) },
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(addr, { focus: true }) },
    ];
    if (S.funcMap.has(name))
      items.push({ icon: "◈", label: t("ctx.graph"), run: () => { switchCenter("graph"); showGraph(addr); } });
    items.push("-",
      { icon: "⧉", label: t("ctx.copy_name"), run: () => navigator.clipboard.writeText(name) },
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(addr)) });
    openCtxMenu(e.clientX, e.clientY, items);
    return;
  }

  // ── text selection anywhere in code / hex → decoder
  const selText = String(window.getSelection ? getSelection() : "").trim();
  if (selText && (e.target.closest("#code-decompile") || e.target.closest("#code-hex"))) {
    e.preventDefault();
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⚗", label: t("ctx.decode_text"), title: t("ctx.decode.title"), run: () => sendToDecoder(selText, "text") },
      { icon: "⚗", label: t("ctx.decode_hex"), title: t("ctx.decode.title"), run: () => sendToDecoder(selText.replace(/[^0-9a-fA-F]/g, ""), "hex") },
      "-",
      { icon: "⧉", label: t("ctx.copy"), run: () => navigator.clipboard.writeText(selText) },
    ]);
    return;
  }

  // ── xref row (inspector): jump / copy
  const xrow = e.target.closest("#xrefs-info .xref-row");
  if (xrow && xrow.dataset.addr) {
    e.preventDefault();
    const target = parseInt(xrow.dataset.addr, 16);
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌖", label: t("ctx.jump"), run: () => {
          if (xrow.dataset.faddr) {
            const fa = Number(xrow.dataset.faddr);
            selectFunction(fa, xrow.dataset.fname || funcNameByAddr(fa) || hexpad(fa), { highlightAddr: target });
          } else {
            const fn = funcNameByAddr(target);
            if (fn) selectFunction(target, fn);
            else showDisasm(target);
          }
        } },
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(target)) },
    ]);
    return;
  }

  // ── crypto-constant hit: refs / disasm / copy
  const crow = e.target.closest("#constants-info .xref-row");
  if (crow && crow.dataset.addr) {
    e.preventDefault();
    const a = parseInt(crow.dataset.addr, 16);
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(a, { focus: true }) },
      { icon: "⌗", label: t("ctx.disasm"), run: () => showDisasm(a) },
      "-",
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) },
    ]);
    return;
  }

  // ── function-list row: decompile / graph / rename / note / copy
  const frow = e.target.closest("#list-functions .row");
  if (frow && frow.dataset.addr) {
    e.preventDefault();
    const fa = Number(frow.dataset.addr);
    const fname = (frow.querySelector(".name") || {}).textContent || funcNameByAddr(fa) || hexpad(fa);
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌖", label: t("ctx.decompile"), run: () => selectFunction(fa, fname) },
      { icon: "◈", label: t("ctx.graph"), run: () => { switchCenter("graph"); showGraph(fa); } },
      "-",
      { icon: "✎", label: t("ctx.rename"), run: () => selectFunction(fa, fname).then(renameCurrentFn) },
      { icon: "✚", label: t("ctx.note"), run: () => selectFunction(fa, fname).then(noteCurrentFn) },
      "-",
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(fa)) },
    ]);
    return;
  }

  // ── string row: jump-to-ref / refs / decode / copy
  const srow = e.target.closest("#list-strings .row");
  if (srow && srow.dataset.addr != null) {
    e.preventDefault();
    const sAddr = Number(srow.dataset.addr);
    const lit = srow.querySelector(".lit");
    const sVal = lit ? lit.textContent : "";
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌖", label: t("ctx.jump_ref"), title: t("ctx.jump_ref.title"), run: () => jumpStringRef(sAddr) },
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(sAddr, { focus: true }) },
      { icon: "⚗", label: t("ctx.decode"), run: () => sendToDecoder(sVal, "text") },
      "-",
      { icon: "⧉", label: t("ctx.copy"), run: () => navigator.clipboard.writeText(sVal) },
    ]);
    return;
  }

  // ── import row: callers / copy
  const irow = e.target.closest("#list-imports .row");
  if (irow && irow.dataset.addr) {
    e.preventDefault();
    const a = Number(irow.dataset.addr);
    const nm = irow.dataset.name || (irow.querySelector(".name") || {}).textContent || "";
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌕", label: t("ctx.callers"), title: t("ctx.callers.title"), run: () => loadXrefs(a, { focus: true }) },
      "-",
      { icon: "⧉", label: t("ctx.copy_name"), run: () => navigator.clipboard.writeText(nm) },
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) },
    ]);
    return;
  }

  // ── export row: jump / refs / copy
  const erow = e.target.closest("#list-exports .row");
  if (erow && erow.dataset.addr) {
    e.preventDefault();
    const a = Number(erow.dataset.addr);
    const nm = erow.dataset.name || (erow.querySelector(".name") || {}).textContent || "";
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌖", label: t("ctx.jump"), run: () => {
          const fn = funcNameByAddr(a);
          if (fn) selectFunction(a, fn);
          else showDisasm(a);
        } },
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(a, { focus: true }) },
      "-",
      { icon: "⧉", label: t("ctx.copy_name"), run: () => navigator.clipboard.writeText(nm) },
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) },
    ]);
    return;
  }

  // ── search-result row: depends on which index it came from
  const qrow = e.target.closest("#search-results .row");
  if (qrow && qrow.dataset.addr) {
    e.preventDefault();
    const a = parseInt(qrow.dataset.addr, 16);
    const items = [];
    if (qrow.dataset.kind === "string") {
      const lit = qrow.querySelector(".name");
      items.push(
        { icon: "⌖", label: t("ctx.jump_ref"), title: t("ctx.jump_ref.title"), run: () => jumpStringRef(a) },
        { icon: "⚗", label: t("ctx.decode"), run: () => sendToDecoder(lit ? lit.textContent : "", "text") },
        "-",
      );
    } else if (qrow.dataset.kind === "function") {
      items.push(
        { icon: "⌖", label: t("ctx.decompile"), run: () => selectFunction(a, qrow.dataset.fname) },
        { icon: "◈", label: t("ctx.graph"), run: () => { switchCenter("graph"); showGraph(a); } },
        "-",
      );
    }
    items.push(
      { icon: "⌗", label: t("ctx.disasm"), run: () => showDisasm(a) },
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(a, { focus: true }) },
      "-",
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) },
    );
    openCtxMenu(e.clientX, e.clientY, items);
    return;
  }

  // ── disassembly row: follow call target / refs / copy
  const drow = e.target.closest("#code-disasm .disasm-row");
  if (drow && drow.dataset.addr) {
    e.preventDefault();
    const a = parseInt(drow.dataset.addr, 16);
    const tgt = drow.querySelector(".disasm-target");
    const items = [];
    if (tgt)
      items.push({ icon: "⌖", label: t("ctx.follow"), run: () => {
        const ta = parseInt(tgt.dataset.addr, 16);
        const fn = funcNameByAddr(ta);
        if (fn) selectFunction(ta, fn);
        else showDisasm(ta);
      } });
    items.push(
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(a, { focus: true }) },
      "-",
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) });
    openCtxMenu(e.clientX, e.clientY, items);
    return;
  }
});

/* ── X3: DIE-style packer verdict (查壳结论) ── */

const PACKER_SECTION_SIGS = [
  [/^upx/i, "UPX"], [/^\.?vmp[0-9]/i, "VMProtect"], [/themida|winlice/i, "Themida"],
  [/^\.?aspack|^\.?adata/i, "ASPack"], [/petite/i, "Petite"], [/^\.?mpress/i, "MPRESS"],
  [/^\.fsg|^fsg/i, "FSG"], [/nspack|^\.?nsp[0-9]/i, "NsPack"],
  [/pecompact|^\.?pec[0-9]/i, "PECompact"], [/enigma/i, "Enigma"],
  [/^\.?mew/i, "MEW"], [/^\.?upack/i, "UPack"],
];

function renderVerdict() {
  const box = $("#verdict-info");
  const tri = S.triage;
  if (!tri) { box.innerHTML = `<div class="insp-empty">${esc(t("insp.nothing"))}</div>`; return; }
  const secs = tri.sections || [];
  const ent = Number(tri.max_entropy || 0);
  const hits = [];
  for (const sec of secs)
    for (const [re, name] of PACKER_SECTION_SIGS)
      if (re.test(String(sec.name || ""))) hits.push(`${name} · ${sec.name}`);
  let cls, main, hint;
  if (hits.length) {
    cls = "v-bad";
    main = t("verdict.packed", { n: [...new Set(hits)].join(", ") });
    hint = t("verdict.packed.hint");
  } else if (ent >= 7.5) {
    // high entropy outranks a bare overlay — a compressed payload IS packing
    cls = "v-bad";
    main = t("verdict.high_entropy", { e: ent.toFixed(2) });
    hint = t("verdict.high_entropy.hint");
  } else if (tri.overlay_present) {
    cls = "v-warn";
    main = t("verdict.overlay");
    hint = t("verdict.overlay.hint");
  } else if (ent >= 6.5) {
    cls = "v-warn";
    main = t("verdict.mid_entropy", { e: ent.toFixed(2) });
    hint = t("verdict.mid_entropy.hint");
  } else {
    cls = "v-ok";
    main = t("verdict.clean");
    hint = t("verdict.clean.hint");
  }
  box.innerHTML = `<div class="verdict ${cls}"><div class="verdict-main">${esc(main)}</div><div class="verdict-hint">${esc(hint)}</div></div>`;
}

/* ═══════════════════════ global state ═══════════════════════ */

const S = {
  program: null,
  triage: null,
  funcMap: new Map(),      // name -> addr
  functionsLoaded: 0,
  functionsTotal: 0,
  functionsQuery: "",
  stringsQuery: "",
  currentFunc: null,       // {addr, name}
  disasmCache: new Map(),  // addr -> rendered? (skip cache, cheap)
  blocks: [],
  hexBlock: null,
  hexOffset: 0,
  hexChunk: 4096,
  hexBytes: null,          // last-read chunk (F3: send to decoder)
  selectedString: null,
  ops: [],
};

/* ═══════════════════════ tabs (generic) ═══════════════════════ */

function wireTabs(barSel, bodySel, onChange) {
  const bar = $(barSel);
  bar.addEventListener("click", (e) => {
    const btn = e.target.closest(".tab[data-tab]");
    if (!btn) return;
    $$(barSel + " .tab").forEach((t) => t.classList.toggle("active", t === btn));
    const name = btn.dataset.tab;
    $$(bodySel + " > .tabpane").forEach((p) =>
      p.classList.toggle("active", p.dataset.pane === name));
    if (onChange) onChange(name);
  });
}
const activeTab = (barSel) => $(barSel + " .tab.active")?.dataset.tab;

/* ═══════════════════════ engine status ═══════════════════════ */

function engineState(mode) {
  const dot = $("#engine-dot");
  dot.className = `engine-dot ${mode}`;
  dot.querySelector(".dot-label").textContent =
    t(mode === "busy" ? "engine.analyzing" : mode === "ready" ? "engine.ready" : mode === "error" ? "engine.error" : "engine.idle");
  const st = $("#st-engine");
  st.textContent = t(mode === "busy" ? "engine.st.analyzing" : mode === "ready" ? "engine.st.ready" : mode === "error" ? "engine.st.error" : "engine.st.idle");
  st.className = mode;
}

function setBusy(b, jobLabel = "") {
  engineState(b ? "busy" : (S.program ? "ready" : "idle"));
  $("#st-job").textContent = b ? jobLabel : "";
}

/* ═══════════════════════ opening binaries ═══════════════════════ */

async function openByPath(path) {
  if (!path) return;
  // wipe every panel FIRST — during the (potentially long) open the UI must
  // never keep showing the previous project's strings/functions/xrefs
  resetWorkspace(t("st.opening"));
  setBusy(true, t("job.opening"));
  logLine(`open ${path}`, "hi");
  try {
    const { job } = await api("open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    await pollJob(job, (j) => {
      $("#st-job").textContent = j.progress || t("job.opening");
    });
    logLine(t("log.analysis_done"), "ok");
    await loadProgram();
  } catch (e) {
    toast(t("toast.open_fail", { err: e.message }), "error");
    logLine(`open failed: ${e.message}`, "err");
    await recoverAfterOpenFail();
  } finally {
    setBusy(false);
  }
}

/* A failed open must not leave the workspace showing a phantom project.
   Re-sync with what the server actually holds: if it still has a program,
   rebuild from it; if not, back to the clean empty state. */
async function recoverAfterOpenFail() {
  try {
    await api("program");
    await loadProgram();
  } catch {
    resetWorkspace();
  }
}

async function uploadAndOpen(file) {
  setBusy(true, t("job.uploading"));
  logLine(`upload ${file.name} (${file.size} bytes)`, "hi");
  try {
    const buf = await file.arrayBuffer();
    const res = await fetch(`/api/upload?name=${encodeURIComponent(file.name)}`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: buf,
    });
    if (!res.ok) throw new Error(`upload failed: HTTP ${res.status}`);
    const { path } = await res.json();
    $("#path-input").value = path;
    // uploads are copies (the browser never reveals the original path) — say
    // so, and point at the path bar for in-place analysis
    logLine(`${t("toast.upload_copied")} ${path}`, "hi");
    toast(t("toast.upload_copied"), "info", 5200);
    await openByPath(path);
  } catch (e) {
    toast(e.message, "error");
    setBusy(false);
  }
}

function pollJob(id, onTick) {
  return new Promise((resolve, reject) => {
    let lastLog = "";
    const timer = setInterval(async () => {
      try {
        const j = await api(`job/${id}`);
        if (onTick) onTick(j);
        if (j.log.length) {
          const last = j.log[j.log.length - 1];
          if (last !== lastLog) { lastLog = last; logLine(last); }
        }
        if (j.status === "done") { clearInterval(timer); resolve(j); }
        if (j.status === "error") { clearInterval(timer); reject(new Error(j.error)); }
      } catch (e) { clearInterval(timer); reject(e); }
    }, 500);
  });
}

/* Wipe every panel so no project's data ever leaks into another's view
   (the "opening shows the previous project's strings" complaint). Used at
   open start, on open failure recovery, and before loadProgram rebuilds. */
function resetWorkspace(statusMsg) {
  S.program = null;
  S.triage = null;
  S.currentFunc = null;
  S.selectedString = null;
  S.ops = [];
  renderOps();
  $("#hero").classList.add("hidden");
  $("#st-program").textContent = statusMsg || t("st.noprogram");
  renderVerdict();   // handles S.triage == null → "nothing loaded"
  $("#decompile-title").textContent = t("decompile.title.none");
  $("#code-decompile").innerHTML = `<div class="code-empty">${esc(t("code.empty.dec"))}</div>`;
  $("#disasm-title").textContent = t("code.title.none");
  $("#code-disasm").innerHTML = `<div class="code-empty">${esc(t("disasm.empty"))}</div>`;
  for (const id of ["btn-copy-code", "btn-download-code", "btn-rename-fn", "btn-note-fn"])
    $(`#${id}`).classList.add("hidden");
  $("#xrefs-target").textContent = "—";
  $("#xrefs-target").removeAttribute("data-addr");
  $("#xrefs-info").innerHTML = `<div class="insp-empty">${esc(t("insp.select"))}</div>`;
  $("#constants-info").innerHTML = `<div class="insp-empty">${esc(t("insp.constants.hint"))}</div>`;
  $("#count-constants").textContent = "";
  $("#program-info").innerHTML = `<div class="insp-empty">${esc(t("insp.nothing"))}</div>`;
  $("#sections-info").innerHTML = "";
  $("#overlay-info").innerHTML = "";
  $("#graph-info").textContent = t("graph.info.none");
  $("#graph-stats").textContent = "";
  G.rawNodes = new Map(); G.rawEdges = new Set();
  G.nodes = []; G.edges = []; G.byId = new Map();
  G.center = 0; G.selected = null; G.hover = null;
  pokeGraph();
  S.functionsLoaded = 0; S.funcMap.clear();
  $("#list-functions").innerHTML = "";
  $("#count-functions").textContent = "";
  $("#st-fn").textContent = "";
  $("#list-strings").innerHTML = "";
  $("#count-strings").textContent = "";
  $("#st-str").textContent = "";
  $("#search-results").innerHTML = `<div class="code-empty">${esc(t("search.hint"))}</div>`;
  $("#search-info").textContent = "";
}

async function loadProgram() {
  // fetch first, wipe second: resetWorkspace() nulls S.program/S.triage, so
  // the freshly fetched data must be re-installed AFTER the wipe or every
  // load dies with "Cannot read properties of null" and the workspace stays
  // stuck on the empty state (regression caught by the open-path E2E)
  const prog = await api("program");
  const tri = await api("triage");
  resetWorkspace();
  S.program = prog;
  S.triage = tri;
  engineState("ready");
  $("#st-program").textContent = prog.name;
  renderVerdict();
  renderProgramInfo();
  renderSections();
  renderOverlay();
  await loadFunctions(false);
  loadStrings();
  loadImportsExports();
  loadBlocks();
  loadConstants();
  toast(t("toast.analyzed", { name: S.program.name, n: S.program.function_count }), "info");
}

/* ═══════════════════════ left: functions ═══════════════════════ */

const PAGE = 400;

async function loadFunctions(append) {
  const list = $("#list-functions");
  if (!append) { S.functionsLoaded = 0; list.innerHTML = `<div class="loading">${esc(t("list.loading.fn"))}</div>`; }
  const offset = S.functionsLoaded;
  try {
    const data = await api(`functions?q=${encodeURIComponent(S.functionsQuery)}&offset=${offset}&limit=${PAGE}`);
    if (!append) list.innerHTML = "";
    S.functionsTotal = data.total;
    $("#count-functions").textContent = data.total;
    $("#st-fn").textContent = t("st.fn", { n: data.total });
    for (const f of data.items) addFuncRow(list, f);
    S.functionsLoaded += data.items.length;
    if (!data.items.length && !append)
      list.innerHTML = `<div class="code-empty">${esc(t("list.no_match"))}</div>`;
  } catch (e) {
    if (!append) list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`;
  }
}

function addFuncRow(list, f) {
  S.funcMap.set(f.name, f.addr);
  const row = document.createElement("div");
  row.className = "row";
  row.tabIndex = 0;
  row.dataset.addr = f.addr;
  row.innerHTML = `<span class="addr">${hexpad(f.addr)}</span><span class="name">${esc(f.name)}</span><span class="meta">${f.size}</span>`;
  row.onclick = () => selectFunction(f.addr, f.name);
  list.appendChild(row);
}

async function selectFunction(addr, name, opts = {}) {
  S.currentFunc = { addr, name };
  $$("#list-functions .row").forEach((r) =>
    r.classList.toggle("active", Number(r.dataset.addr) === addr));
  $("#decompile-title").innerHTML = `<b>${esc(name)}</b> · ${hexpad(addr)}`;
  for (const id of ["btn-copy-code", "btn-download-code", "btn-rename-fn", "btn-note-fn"])
    $(`#${id}`).classList.remove("hidden");
  const code = $("#code-decompile");
  code.innerHTML = `<div class="loading">${esc(t("dec.decompiling", { name }))}</div>`;
  try {
    const res = await api(`function/${addr}/decompile`);
    renderCode(res.code, {
      addrLines: res.addr_lines,
      addrLinesHi: res.addr_lines_hi,
      addrData: res.addr_data,
      highlightAddr: opts.highlightAddr,
      highlightTarget: opts.highlightTarget,
    });
    if (activeTab("#center-tabs") !== "decompile" && !opts.keepTab && activeTab("#center-tabs") !== "graph")
      switchCenter("decompile");
  } catch (e) {
    code.innerHTML = `<div class="code-empty">${esc(t("dec.fail", { err: e.message }))}</div>`;
  }
  loadXrefs(addr);
}

/* F1: rename / note the current function */
async function renameCurrentFn() {
  if (!S.currentFunc) { toast(t("toast.select_fn"), "info"); return; }
  const { addr, name } = S.currentFunc;
  const next = await askText(t("rename.prompt", { old: name }), name);
  if (next == null) return;
  const clean = next.trim();
  if (!clean || clean === name) return;
  try {
    await api(`function/${addr}/rename`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: clean }),
    });
    S.funcMap.delete(name);
    S.funcMap.set(clean, addr);
    S.currentFunc = { addr, name: clean };
    $("#decompile-title").innerHTML = `<b>${esc(clean)}</b> · ${hexpad(addr)}`;
    const row = $(`#list-functions .row[data-addr="${addr}"] .name`);
    if (row) row.textContent = clean;
    if (G.rawNodes.has(addr)) { G.rawNodes.set(addr, clean); layoutGraph(); pokeGraph(); }
    toast(t("toast.renamed", { name: clean }), "ok");
    logLine(`rename ${hexpad(addr)}: ${name} → ${clean}`, "hi");
  } catch (e) { toast(e.message, "error"); }
}

async function noteCurrentFn() {
  if (!S.currentFunc) { toast(t("toast.select_fn"), "info"); return; }
  const { addr, name } = S.currentFunc;
  let cur = "";
  try {
    const r = await api(`function/${addr}/comment`);
    cur = r.comment || "";
  } catch { /* first note */ }
  const text = await askText(t("note.prompt", { name }), cur);
  if (text == null) return;
  try {
    await api(`function/${addr}/comment`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    toast(t("toast.note"), "ok");
    logLine(`note ${hexpad(addr)}: ${text ? text.slice(0, 60) : "(cleared)"}`, "hi");
  } catch (e) { toast(e.message, "error"); }
}

function switchCenter(tab) {
  $$("#center-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
  $$("#center-body > .tabpane").forEach((p) => p.classList.toggle("active", p.dataset.pane === tab));
}

/* ═══════════════════════ C syntax highlight ═══════════════════════ */

const C_TOKEN = new RegExp([
  "(\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/)",                                    // 1 comment
  "(\"(?:[^\"\\\\]|\\\\.)*\")",                                                 // 2 string
  "('(?:[^'\\\\]|\\\\.)*')",                                                    // 3 char
  "(\\b0x[0-9a-fA-F]{4,}\\b)",                                                  // 4 hex
  "(\\b(?:FUN_|SUB_|DAT_|s_|u_|_)[-\\w]{4,}\\b)",                               // 5 ghidra syms
  "\\b(int|char|void|long|short|unsigned|signed|float|double|bool|undefined\\d?|uint|u?long\\s?long|byte|word|dword|qword|if|else|for|while|do|return|switch|case|default|break|continue|sizeof|struct|union|enum|const|static|true|false|null|NULL)\\b", // 6 kw
  "\\b(\\d+)\\b",                                                               // 7 dec
  "([A-Za-z_]\\w*)(?=\\s*\\()",                                                 // 8 call
].join("|"), "g");

function addrFromSym(sym) {
  const m = sym.match(/([0-9a-fA-F]{6,16})$/);
  return m ? parseInt(m[1], 16) : null;
}

function highlightC(code) {
  let out = "", last = 0, m;
  C_TOKEN.lastIndex = 0;
  while ((m = C_TOKEN.exec(code))) {
    out += esc(code.slice(last, m.index));
    const [tok, comment, str, chr, hexnum, ghsym, kw, dec, call] = m;
    if (comment) out += `<span class="c">${esc(comment)}</span>`;
    else if (str || chr) out += `<span class="s">${esc(str || chr)}</span>`;
    else if (hexnum) out += `<span class="n">${esc(hexnum)}</span>`;
    else if (ghsym) {
      const addr = addrFromSym(ghsym);
      // B1: data-addr carries HEX digits everywhere; readers use parseInt(…, 16)
      out += `<span class="a" data-addr="${addr != null ? addr.toString(16) : ""}" data-name="${esc(ghsym)}">${esc(ghsym)}</span>`;
    }
    else if (kw) out += `<span class="k">${esc(kw)}</span>`;
    else if (dec) out += `<span class="n">${esc(dec)}</span>`;
    else if (call) {
      const known = S.funcMap.get(call);
      out += `<span class="f${known != null ? " a" : ""}"${known != null ? ` data-addr="${known.toString(16)}" data-name="${esc(call)}"` : ""}>${esc(call)}</span>`;
    }
    last = m.index + tok.length;
  }
  out += esc(code.slice(last));
  return out;
}

function renderCode(codeText, opts = {}) {
  const box = $("#code-decompile");
  const lines = codeText.replace(/\n$/, "").split("\n");
  box.innerHTML = lines.map((line, i) =>
    `<div class="codeline"><span class="ln">${i + 1}</span><span>${highlightC(line)}</span></div>`
  ).join("");
  box.onclick = (e) => {
    const t = e.target.closest(".a");
    if (!t) return;
    if (t.dataset.addr) navigateAddr(parseInt(t.dataset.addr, 16), t.dataset.name);
    else if (t.dataset.name) {
      const addr = S.funcMap.get(t.dataset.name);
      if (addr != null) selectFunction(addr, t.dataset.name);
    }
  };
  // X1: highlight the decompiled line that references the xref target.
  // Rules (in order): exact data-address match on the target (string/const
  // literal tokens carry their own data address), containment of the ref
  // instruction in a line's code range, nearest following code line
  // (argument-setup instructions precede the call they feed → gaps belong
  // to the NEXT line), fallback to the last line starting at/below the ref.
  if (opts.highlightAddr != null && opts.addrLines) {
    const H = opts.highlightAddr;
    const T = opts.highlightTarget != null ? Number(opts.highlightTarget) : null;
    const lnos = Object.keys(opts.addrLines).map(Number).sort((a, b) => a - b);
    let lineNo = null;
    if (T != null && opts.addrData) {
      for (const ln of lnos) if (Number(opts.addrData[ln]) === T) { lineNo = ln; break; }
    }
    if (lineNo == null) {
      for (const ln of lnos) {
        const lo = Number(opts.addrLines[ln]);
        const hi = opts.addrLinesHi && opts.addrLinesHi[ln] != null ? Number(opts.addrLinesHi[ln]) : lo;
        if (lo <= H && H <= hi) { lineNo = ln; break; }
      }
    }
    if (lineNo == null) for (const ln of lnos) if (Number(opts.addrLines[ln]) > H) { lineNo = ln; break; }
    if (lineNo == null) for (const ln of lnos) if (Number(opts.addrLines[ln]) <= H) lineNo = ln;
    const el = lineNo ? box.querySelector(`.codeline:nth-child(${lineNo})`) : null;
    if (el) {
      el.classList.add("hl");
      setTimeout(() => el.scrollIntoView({ block: "center" }), 60);
    }
  }
}

function navigateAddr(addr, name) {
  const known = S.funcMap.get(name);
  if (known != null) { selectFunction(known, name); return; }
  // try containing function via disasm, then decompile it
  showDisasm(addr, true);
}

/* ═══════════════════════ disassembly ═══════════════════════ */

async function showDisasm(addr, alsoSelect) {
  switchCenter("disasm");
  const box = $("#code-disasm");
  $("#disasm-title").textContent = `${hexpad(addr)} …`;
  try {
    const res = await api(`function/${addr}/disasm`);
    $("#disasm-title").innerHTML = `<b>${esc(res.function || "?")}</b> · ${hexpad(res.function_addr ?? addr)}`;
    box.innerHTML = res.instructions.map((ins) => {
      const parts = ins.text.split(/\s+/);
      const mn = parts[0] || "";
      const rest = ins.text.slice(mn.length);
      const ref = ins.refs && ins.refs.length ? ins.refs[0] : null;
      const alreadyShown = ref != null && ins.text.toLowerCase().includes(ref.toString(16));
      const target = ref != null && !alreadyShown
        ? ` <span class="disasm-target" data-addr="${ref.toString(16)}">${hexpad(ref)}</span>`
        : "";
      return `<div class="disasm-row" data-addr="${ins.addr.toString(16)}">
        <span class="disasm-addr">${hexpad(ins.addr)}</span>
        <span class="disasm-bytes">${esc(ins.bytes)}</span>
        <span class="disasm-text"><span class="disasm-mnemonic">${esc(mn)}</span>${esc(rest)}${target}</span>
      </div>`;
    }).join("");
    box.querySelectorAll(".disasm-target").forEach((t) =>
      t.onclick = () => {
        const a = parseInt(t.dataset.addr, 16);
        const fn = funcNameByAddr(a);
        if (fn) selectFunction(a, fn);
        else showDisasm(a);
      });
    // mark current row
    const cur = box.querySelector(`.disasm-row[data-addr="${addr.toString(16)}"]`);
    if (cur) cur.classList.add("cur"), cur.scrollIntoView({ block: "center" });
    if (alsoSelect && res.function_addr != null) {
      S.currentFunc = { addr: res.function_addr, name: res.function };
      loadXrefs(res.function_addr);
    }
  } catch (e) {
    box.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`;
  }
}

/* ═══════════════════════ strings / imports / exports ═══════════════════════ */

async function loadStrings(append = false) {
  const list = $("#list-strings");
  if (!append) list.innerHTML = `<div class="loading">${esc(t("list.loading.str"))}</div>`;
  try {
    const data = await api(`strings?q=${encodeURIComponent(S.stringsQuery)}&limit=400`);
    if (!append) list.innerHTML = "";
    $("#count-strings").textContent = data.total;
    $("#st-str").textContent = t("st.strings", { n: data.total });
    if (!data.items.length) { list.innerHTML = `<div class="code-empty">${esc(t("list.no_match"))}</div>`; return; }
    for (const s of data.items) {
      const row = document.createElement("div");
      row.className = "row";
      row.tabIndex = 0;
      row.dataset.addr = s.addr;
      row.innerHTML = `<span class="addr">${hexpad(s.addr)}</span><span class="val"><span class="lit">${esc(s.value)}</span></span><span class="meta">${s.length}</span><button class="row-btn" title="${esc(t("hex.send.title"))}">⚗</button>`;
      row.onclick = () => {
        S.selectedString = s.value;
        $$("#list-strings .row").forEach((r) => r.classList.toggle("active", r === row));
        loadXrefs(s.addr, { focus: true });
      };
      // IDA reflex: double-click a string → jump straight into the code using it
      row.ondblclick = () => jumpStringRef(s.addr);
      row.querySelector(".row-btn").onclick = (e) => {
        e.stopPropagation();
        S.selectedString = s.value;
        sendToDecoder(s.value, "text");
      };
      list.appendChild(row);
    }
  } catch (e) { if (!append) list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
}

async function loadImportsExports() {
  for (const [which, sel] of [["imports", "#list-imports"], ["exports", "#list-exports"]]) {
    const list = $(sel);
    list.innerHTML = `<div class="loading">…</div>`;
    try {
      const data = await api(which);
      list.innerHTML = "";
      if (!data.items.length) { list.innerHTML = `<div class="code-empty">${esc(t("list.none"))}</div>`; continue; }
      for (const it of data.items) {
        const row = document.createElement("div");
        row.className = "row";
        row.tabIndex = 0;
        row.dataset.name = it.name;
        if (it.addr != null) row.dataset.addr = it.addr;
        row.innerHTML = which === "imports"
          ? `<span class="name">${esc(it.name)}</span><span class="meta">${esc(it.library || "")}</span>`
          : `<span class="addr">${hexpad(it.addr)}</span><span class="name">${esc(it.name)}</span>`;
        // X1: click an import → who calls it (via its thunk function)
        if (which === "imports" && it.addr != null) {
          row.title = t("imports.xref.title");
          row.onclick = () => loadXrefs(it.addr, { focus: true });
        }
        list.appendChild(row);
      }
    } catch (e) { list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
  }
}

/* ═══════════════════════ inspector ═══════════════════════ */

function renderProgramInfo() {
  const p = S.program;
  $("#program-info").innerHTML = `<dl class="kv">
    <dt>${esc(t("label.name"))}</dt><dd class="long">${esc(p.name)}</dd>
    <dt>${esc(t("label.format"))}</dt><dd>${esc(p.format)}</dd>
    <dt>${esc(t("label.language"))}</dt><dd>${esc(p.language_id)}</dd>
    <dt>${esc(t("label.compiler"))}</dt><dd>${esc(p.compiler)}</dd>
    <dt>${esc(t("label.base"))}</dt><dd class="mono-addr">${hexpad(parseInt(p.image_base, 16))}</dd>
    <dt>${esc(t("label.size"))}</dt><dd>${Number(p.size).toLocaleString()}</dd>
    <dt>${esc(t("label.functions"))}</dt><dd>${p.function_count}</dd>
    <dt>${esc(t("label.project"))}</dt><dd class="long" title="${esc(p.project_dir || "")}">${esc(p.project_dir || "—")}</dd>
  </dl>`;
}

function renderSections() {
  const box = $("#sections-info");
  const secs = S.triage.sections || [];
  if (!secs.length) { box.innerHTML = `<div class="insp-empty">${esc(t("list.none"))}</div>`; return; }
  box.innerHTML = secs.map((s) => {
    const ent = s.entropy != null ? s.entropy.toFixed(2) : "—";
    const w = s.entropy != null ? Math.min(100, s.entropy / 8 * 100) : 0;
    const packed = s.entropy > 7.2 ? ` <span style="color:var(--rose)">· ${esc(t("sec.packed"))}</span>` : "";
    // B4: malformed section tables must not print NaN
    const sz = Number(s.raw_size ?? s.size);
    const off = s.raw_offset ?? s.offset;
    const szText = Number.isFinite(sz) && sz >= 0 ? sz.toLocaleString() : "—";
    const offText = off != null && Number.isFinite(Number(off)) ? hexa(Number(off)) : "—";
    return `<div class="sec-row">
      <div class="sec-line1"><span class="sec-name">${esc(s.name)}</span><span class="sec-ent">H=${ent}${packed}</span></div>
      <div class="sec-bar"><i style="width:${w}%"></i></div>
      <div class="sec-meta">${szText} B @ ${offText}</div>
    </div>`;
  }).join("");
}

function renderOverlay() {
  const box = $("#overlay-info");
  const tri = S.triage;
  if (tri.overlay_present) {
    box.innerHTML = `<div class="overlay-box">
      <div class="overlay-title">${esc(t("ov.detected"))}</div>
      <div class="sec-meta">${t("ov.size")}: ${Number(tri.overlay_size).toLocaleString()} B · ${t("ov.offset")}: ${hexa(tri.overlay_offset)}</div>
      <div class="sec-meta">${esc(t("ov.hint"))}</div>
    </div>`;
  } else {
    const coff = Number(tri.coff_symbols || 0);
    box.innerHTML = `<div class="overlay-box clean"><div class="overlay-title clean">${esc(t("ov.clean"))}</div>` +
      (coff > 0 ? `<div class="sec-meta">${esc(t("ov.coff", { n: coff.toLocaleString() }))}</div>` : "") +
      `</div>`;
  }
}

async function loadXrefs(addr, opts = {}) {
  $("#xrefs-target").textContent = hexa(addr);
  $("#xrefs-target").dataset.addr = addr;
  const box = $("#xrefs-info");
  box.innerHTML = `<div class="loading">${esc(t("list.loading.refs"))}</div>`;
  try {
    const res = await api(`xrefs/${addr}`);
    let html = "";
    if (res.to.length) {
      html += `<div class="xref-label">${esc(t("xrefs.to"))} (${res.to.length})</div>`;
      html += res.to.slice(0, 40).map((r) =>
        `<div class="xref-row" tabindex="0" data-addr="${Number(r.addr).toString(16)}"${r.function_addr != null ? ` data-faddr="${Number(r.function_addr)}" data-fname="${esc(r.function || "")}"` : ""}><span class="xref-type">${esc(r.type)}</span><span class="xref-addr">${hexpad(r.addr)}</span><span class="xref-name">${esc(r.function || "")}</span></div>`).join("");
    } else html += `<div class="insp-empty">${esc(t("xrefs.none"))}</div>`;
    if (res.from.length) {
      html += `<div class="xref-label">${esc(t("xrefs.from"))} (${res.from.length})</div>`;
      html += res.from.slice(0, 40).map((r) =>
        `<div class="xref-row" tabindex="0" data-addr="${Number(r.to).toString(16)}"><span class="xref-type">${esc(r.type)}</span><span class="xref-addr">${hexpad(r.to)}</span></div>`).join("");
    }
    box.innerHTML = html;
    box.querySelectorAll(".xref-row").forEach((row) =>
      row.onclick = () => {
        const target = parseInt(row.dataset.addr, 16);
        // X1: prefer the containing function — jump into decompiled C, not raw asm
        if (row.dataset.faddr) {
          const fa = Number(row.dataset.faddr);
          selectFunction(fa, row.dataset.fname || funcNameByAddr(fa) || hexpad(fa), {
            highlightAddr: target,
            highlightTarget: Number($("#xrefs-target").dataset.addr),
          });
        } else {
          const fn = funcNameByAddr(target);
          if (fn) selectFunction(target, fn);
          else showDisasm(target);
        }
      });
    if (opts.focus) {
      const g = $("#insp-xrefs");
      g.scrollIntoView({ block: "nearest", behavior: "smooth" });
      g.classList.remove("flash");
      void g.offsetWidth; // restart the flash animation
      g.classList.add("flash");
    }
  } catch (e) { box.innerHTML = `<div class="insp-empty">${esc(e.message)}</div>`; }
}

async function loadConstants() {
  const box = $("#constants-info");
  box.innerHTML = `<div class="loading">${esc(t("list.loading.const"))}</div>`;
  try {
    const res = await api("constants");
    $("#count-constants").textContent = res.items.length;
    if (!res.items.length) {
      box.innerHTML = `<div class="insp-empty">${esc(t("const.none"))}</div>`;
      return;
    }
    box.innerHTML = res.items.map((h) =>
      `<div class="xref-row" tabindex="0" data-addr="${Number(h.addr).toString(16)}" title="${esc(h.note || "")}">
        <span class="xref-addr">${hexpad(h.addr)}</span>
        <span class="xref-name">${esc(h.name)}</span>
        <span class="chip c-${h.category === "hash" ? "hash" : h.category === "ecc" ? "ecc" : h.category === "encoding" ? "encoding" : "crypto"}">${esc(h.function || h.block || "")}</span>
      </div>`).join("");
    box.querySelectorAll(".xref-row").forEach((row) =>
      row.onclick = () => showDisasm(parseInt(row.dataset.addr, 16)));
    toast(t("const.hits", { n: res.items.length }), "info");
  } catch (e) { box.innerHTML = `<div class="insp-empty">${esc(e.message)}</div>`; }
}

/* ═══════════════════════ memory hex ═══════════════════════ */

async function loadBlocks() {
  try {
    const res = await api("memory/blocks");
    S.blocks = res.items;
    const sel = $("#hex-block");
    sel.innerHTML = S.blocks.map((b) =>
      `<option value="${esc(b.name)}">${esc(b.name)} (${hexa(b.start)}, ${Number(b.size).toLocaleString()})</option>`).join("");
    S.hexBlock = S.blocks[0]?.name || null;
    S.hexOffset = 0;
    if (S.hexBlock) readHex();
  } catch (e) { /* ignore */ }
}

async function readHex() {
  const box = $("#code-hex");
  if (!S.hexBlock) { box.innerHTML = `<div class="code-empty">${esc(t("hex.empty"))}</div>`; return; }
  box.innerHTML = `<div class="loading">${esc(t("list.loading.mem"))}</div>`;
  try {
    const res = await api(`memory/read?block=${encodeURIComponent(S.hexBlock)}&offset=${S.hexOffset}&len=${S.hexChunk}`);
    const bytes = b64ToBytes(res.data_b64);
    S.hexBytes = bytes;   // F3: keep for "send to decoder"
    $("#hex-info").textContent = `${S.hexBlock} @ +${S.hexOffset}`;
    let html = "";
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const addr = S.hexOffset + i;
      let hx = "", asc = "";
      for (const b of chunk) {
        hx += `<span class="hexbyte${b === 0 ? " zero" : ""}">${b.toString(16).padStart(2, "0")}</span> `;
        asc += (b >= 0x20 && b < 0x7f) ? `<span class="hexascii">${esc(String.fromCharCode(b))}</span>` : `<span class="hexbyte">·</span>`;
      }
      html += `<div class="hexgrid"><span class="hexaddr">${hexpad(addr)}</span>  ${hx} <span class="hexaddr">|</span>${asc}<span class="hexaddr">|</span></div>`;
    }
    box.innerHTML = html;
  } catch (e) { box.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
}

/* ═══════════════════════ decoder lab ═══════════════════════ */

const OPS = [
  { op: "to_hex", label: "Hex → encode", zh: "Hex 编码", args: [["sep", "str", "e.g. ' '"], ["upper", "bool"]] },
  { op: "from_hex", label: "Hex → decode", zh: "Hex 解码", args: [] },
  { op: "to_base64", label: "Base64 → encode", zh: "Base64 编码", args: [["urlsafe", "bool"]] },
  { op: "from_base64", label: "Base64 → decode", zh: "Base64 解码", args: [] },
  { op: "to_base32", label: "Base32 → encode", zh: "Base32 编码", args: [] },
  { op: "from_base32", label: "Base32 → decode", zh: "Base32 解码", args: [] },
  { op: "to_ascii85", label: "Ascii85 → encode", zh: "Ascii85 编码", args: [] },
  { op: "from_ascii85", label: "Ascii85 → decode", zh: "Ascii85 解码", args: [] },
  { op: "url_encode", label: "URL → encode", zh: "URL 编码", args: [] },
  { op: "url_decode", label: "URL → decode", zh: "URL 解码", args: [] },
  { op: "rot", label: "ROT-n", zh: "ROT-n 移位", args: [["n", "int", 13]] },
  { op: "rot47", label: "ROT47", zh: "ROT47 移位", args: [["n", "int", 47]] },
  { op: "xor", label: "XOR repeating key", zh: "XOR 重复密钥", args: [["key", "str", "ATRI"], ["hex", "bool"]] },
  { op: "xor_pos", label: "XOR with offset", zh: "XOR 位置偏移", args: [["key", "str", "00"], ["offset", "int", 0], ["hex", "bool"]] },
  { op: "rc4", label: "RC4", zh: "RC4", args: [["key", "str", "secret"]] },
  { op: "reverse", label: "Reverse bytes", zh: "字节反转", args: [] },
  { op: "bit_not", label: "NOT bits", zh: "按位取反", args: [] },
  { op: "c_escape", label: "C escape", zh: "C 转义", args: [] },
  { op: "c_unescape", label: "C unescape", zh: "C 反转义", args: [] },
  { op: "hexdump", label: "Hexdump", zh: "Hexdump 视图", args: [] },
  { op: "gzip_decompress", label: "GZip decompress", zh: "GZip 解压", args: [] },
  { op: "gzip_compress", label: "GZip compress", zh: "GZip 压缩", args: [] },
  { op: "zlib_decompress", label: "Zlib decompress", zh: "Zlib 解压", args: [] },
  { op: "zlib_compress", label: "Zlib compress", zh: "Zlib 压缩", args: [] },
  { op: "raw_inflate", label: "Raw inflate", zh: "Raw inflate 解压", args: [] },
  { op: "md5", label: "MD5", zh: "MD5", args: [] },
  { op: "sha1", label: "SHA-1", zh: "SHA-1", args: [] },
  { op: "sha256", label: "SHA-256", zh: "SHA-256", args: [] },
];

/* op names follow the UI language (zh labels added 2026-11: "decoding lab confusing" feedback) */
function opLabel(spec) {
  return (LV_LANG === "zh" && spec.zh) ? spec.zh : spec.label;
}

/* one-click recipes — the "how do I even use this" answer.
   b64 keeps mode text (the base64 characters ARE the input), hex preset only
   flips the input mode — from_hex on top of hex-mode input would decode twice. */
const DEC_PRESETS = {
  b64:     { ops: [{ op: "from_base64", args: {} }], mode: "text" },
  hex:     { ops: [], mode: "hex" },
  rot13:   { ops: [{ op: "rot", args: { n: "13" } }], mode: "text" },
  reverse: { ops: [{ op: "reverse", args: {} }], mode: "text" },
};

function applyPreset(key) {
  const p = DEC_PRESETS[key];
  if (!p) return;
  S.ops = p.ops.map((o) => ({ op: o.op, args: { ...o.args } }));
  renderOps();
  const radio = document.querySelector(`input[name="dec-mode"][value="${p.mode}"]`);
  if (radio) radio.checked = true;
  runChain();
}

function renderOpSelect() {
  $("#op-select").innerHTML = OPS.map((o, i) =>
    `<option value="${i}">${esc(opLabel(o))}</option>`).join("");
}

function renderOps() {
  const list = $("#op-list");
  if (!S.ops.length) { list.innerHTML = `<div class="insp-empty">${esc(t("dec.noops"))}</div>`; return; }
  list.innerHTML = S.ops.map((o, i) => {
    const spec = OPS.find((s) => s.op === o.op);
    const args = spec.args.map(([name, type, def]) => {
      const v = o.args[name] ?? def ?? "";
      if (type === "bool") return `<label class="chk"><input type="checkbox" data-i="${i}" data-arg="${name}" ${v ? "checked" : ""}>${name}</label>`;
      return `<span class="op-arg">${name}<input data-i="${i}" data-arg="${name}" value="${esc(String(v))}"></span>`;
    }).join("");
    return `<div class="op-item">
      <span class="op-arrow">${i + 1}.</span><span class="op-name">${esc(opLabel(spec))}</span>
      <span class="op-args">${args}</span>
      <span class="spring"></span>
      <button class="op-rm" data-rm="${i}" title="remove">✕</button>
    </div>`;
  }).join("");
  list.querySelectorAll("input[data-arg]").forEach((inp) =>
    inp.onchange = () => {
      const i = Number(inp.dataset.i), arg = inp.dataset.arg;
      S.ops[i].args[arg] = inp.type === "checkbox" ? inp.checked : inp.value;
    });
  list.querySelectorAll("[data-rm]").forEach((b) =>
    b.onclick = () => { S.ops.splice(Number(b.dataset.rm), 1); renderOps(); });
}

function decInputBytes() {
  const mode = document.querySelector('input[name="dec-mode"]:checked').value;
  const raw = $("#dec-input").value;
  if (mode === "hex") return Uint8Array.from(raw.trim().replace(/0x|[\s,:-]/g, "").match(/.{1,2}/g)?.map((h) => parseInt(h, 16)) || []);
  if (mode === "b64") return b64ToBytes(raw.trim());
  return new TextEncoder().encode(raw);
}

async function runChain() {
  const input = decInputBytes();
  $("#dec-in-size").textContent = `(${input.length} bytes)`;
  const declog = $("#dec-log");
  declog.innerHTML = "";
  try {
    const res = await api("decode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input_b64: bytesToB64(input), recipe: S.ops.map((o) => ({ op: o.op, args: o.args })) }),
    });
    const out = b64ToBytes(res.result_b64);
    $("#dec-out-size").textContent = `(${out.length} bytes)`;
    renderDecOutput(out);
    declog.innerHTML = res.log.map((l) => `<div>${esc(l)}</div>`).join("");
  } catch (e) {
    declog.innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }
}

function renderDecOutput(bytes) {
  const showHex = $("#dec-show-hex").checked;
  const ta = $("#dec-output");
  if (showHex) {
    let s = "";
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hx = [...chunk].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      const asc = [...chunk].map((b) => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".").join("");
      s += i.toString(16).padStart(8, "0") + "  " + hx.padEnd(48) + " |" + asc + "|\n";
    }
    ta.value = s;
  } else {
    ta.value = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
}

async function xorBrute() {
  const input = decInputBytes();
  const box = $("#xor-results");
  try {
    const res = await api("xor/brute", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input_b64: bytesToB64(input) }),
    });
    box.classList.add("show");
    box.innerHTML = res.items.length
      ? res.items.map((r) =>
          `<div class="xor-row" tabindex="0" data-key="${r.key}"><span class="xor-key">${esc(r.key_hex)}</span><span class="xor-score">${r.score}</span><span class="xor-preview">${esc(r.preview)}</span></div>`).join("")
      : `<div class="insp-empty">${esc(t("xor.none.brute"))}</div>`;
    box.querySelectorAll(".xor-row").forEach((row) =>
      row.onclick = () => {
        // dataset carries the decimal key; feed the xor op its hex form (B5 radix)
        S.ops = [{ op: "xor", args: { key: Number(row.dataset.key).toString(16), hex: true } }];
        renderOps(); runChain();
      });
  } catch (e) { toast(e.message, "error"); }
}

async function xorDerive() {
  const prefix = $("#dec-prefix").value;
  if (!prefix) { toast(t("toast.prefix"), "info"); return; }
  const input = decInputBytes();
  const box = $("#xor-results");
  try {
    const res = await api("xor/derive", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input_b64: bytesToB64(input), prefix }),
    });
    box.classList.add("show");
    box.innerHTML = res.items.length
      ? res.items.map((r) =>
          `<div class="xor-row" tabindex="0"><span class="xor-key">len ${r.length}</span><span class="xor-score">${r.key_ascii ? "ascii" : "hex"}</span><span class="xor-preview">${esc(r.key_display)}</span></div>`).join("")
      : `<div class="insp-empty">${esc(t("xor.none.derive"))}</div>`;
    box.querySelectorAll(".xor-row").forEach((row, i) =>
      row.onclick = () => {
        const r = res.items[i];
        // key_bytes is always the hex encoding; prefer the readable ascii form
        S.ops = [{ op: "xor", args: r.key_ascii ? { key: r.key_ascii } : { key: r.key_bytes, hex: true } }];
        renderOps(); runChain();
      });
  } catch (e) { toast(e.message, "error"); }
}

/* ═══════════════════════ search ═══════════════════════
   One box, three indexes: a plain query searches STRING LITERALS and
   FUNCTION NAMES (the RE anchors), an even-length hex pattern additionally
   searches raw memory bytes. Results are grouped; clearing the box restores
   the empty state (it used to stick with the last hits). */

function looksLikeHexPat(s) {
  const t = s.replace(/0x/gi, "").replace(/[\s,:-]/g, "");
  return /^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0;
}

function searchGroup(title, rowsHtml) {
  if (!rowsHtml) return "";
  return `<div class="search-group"><div class="search-group-label">${esc(title)}</div>${rowsHtml}</div>`;
}

async function runSearch() {
  const pat = $("#search-q").value.trim();
  const box = $("#search-results");
  if (!pat) {                       // cleared input → restore the empty state
    box.innerHTML = `<div class="code-empty">${esc(t("search.hint"))}</div>`;
    $("#search-info").textContent = "";
    return;
  }
  box.innerHTML = `<div class="loading">${esc(t("list.loading.search"))}</div>`;
  $("#search-info").textContent = "";

  const hexMode = looksLikeHexPat(pat);
  // strings + function names are useful even for a hex-looking query
  const strP = api(`strings?q=${encodeURIComponent(pat)}&limit=200`)
    .catch(() => ({ items: [], total: 0 }));
  const fnP = api(`functions?q=${encodeURIComponent(pat)}&offset=0&limit=100`)
    .catch(() => ({ items: [], total: 0 }));
  const memP = hexMode
    ? api(`search?hex=${encodeURIComponent(pat)}&limit=200`).catch(() => ({ items: [] }))
    : Promise.resolve({ items: [] });
  const [strRes, fnRes, memRes] = await Promise.all([strP, fnP, memP]);

  let html = "";
  // strings — the anchor of the solving chain: click → xrefs, dblclick → jump
  let rows = "";
  for (const s of strRes.items) {
    rows += `<div class="row" tabindex="0" data-kind="string" data-addr="${s.addr.toString(16)}">
      <span class="addr">${hexpad(s.addr)}</span><span class="name lit">${esc(s.value)}</span><span class="meta">${s.length}</span>
    </div>`;
  }
  html += searchGroup(t("search.group.strings", { n: strRes.total ?? strRes.items.length }), rows);

  // function names — click → decompile
  rows = "";
  for (const f of fnRes.items) {
    rows += `<div class="row" tabindex="0" data-kind="function" data-addr="${f.addr.toString(16)}" data-fname="${esc(f.name)}">
      <span class="addr">${hexpad(f.addr)}</span><span class="name">${esc(f.name)}</span><span class="meta">${f.size}</span>
    </div>`;
  }
  html += searchGroup(t("search.group.functions", { n: fnRes.total ?? fnRes.items.length }), rows);

  // raw memory bytes (only for a hex-shaped pattern)
  rows = "";
  for (const h of memRes.items || []) {
    rows += `<div class="row" tabindex="0" data-kind="mem" data-addr="${h.addr.toString(16)}">
      <span class="addr">${hexpad(h.addr)}</span><span class="name">${esc(h.block)}</span><span class="meta">${esc(h.function || "")}</span>
    </div>`;
  }
  html += searchGroup(t("search.group.mem", { n: (memRes.items || []).length }), rows);

  if (!html) {
    box.innerHTML = `<div class="code-empty">${esc(t("search.nohits"))}</div>`;
    $("#search-info").textContent = t("search.hits.none");
    return;
  }
  box.innerHTML = html;
  const nAll = (strRes.total ?? strRes.items.length) + (fnRes.total ?? fnRes.items.length) + (memRes.items || []).length;
  $("#search-info").textContent = t("search.hits", { n: nAll });

  box.querySelectorAll('.row[data-kind="string"]').forEach((row) => {
    const a = parseInt(row.dataset.addr, 16);
    row.onclick = () => loadXrefs(a, { focus: true });
    row.ondblclick = () => jumpStringRef(a);
  });
  box.querySelectorAll('.row[data-kind="function"]').forEach((row) => {
    const a = parseInt(row.dataset.addr, 16);
    row.onclick = () => selectFunction(a, row.dataset.fname);
  });
  box.querySelectorAll('.row[data-kind="mem"]').forEach((row) => {
    const a = parseInt(row.dataset.addr, 16);
    row.onclick = () => showDisasm(a);
  });
}

/* ═══════════════════════ decompile-all ═══════════════════════ */

async function decompileAll() {
  setBusy(true, t("job.decompiling"));
  logLine(t("log.batch"), "hi");
  try {
    const { job } = await api("export/decompile-all", { method: "POST" });
    await pollJob(job, (j) => {
      $("#st-job").textContent = j.progress || t("job.decompiling");
      if (j.log.length) logLine(j.log[j.log.length - 1]);
    });
    toast(t("toast.zip"), "ok");
    logLine(t("log.batch_done"), "ok");
    window.location = `/api/download/decompile-all.zip?job=${job}`;
  } catch (e) {
    toast(t("log.batch_fail", { err: e.message }), "error");
    logLine(`batch failed: ${e.message}`, "err");
  } finally { setBusy(false); }
}

/* ═══════════════════════ call graph (Ghidra-style Sugiyama layout) ═══════════════════════
   Layout model borrowed from Ghidra's GraphServices (jungrapht):
   hierarchical ranks (callers above, callees below), barycenter ordering to
   minimize edge crossings, orthogonal-ish edges with arrowheads, and
   incremental expansion by double-clicking a node. */

const GRAPH_LAYER_H = 118;
const GRAPH_GAP = 26;
const GRAPH_MAX_NODES = 400;

const G = {
  rawNodes: new Map(),   // addr -> name
  rawEdges: new Set(),   // "callerAddr>calleeAddr"
  center: 0,
  nodes: [],             // laid out: {addr,name,rank,kind,x,y,w,h}
  byId: new Map(),
  edges: [],             // {from,to,fromNode,toNode}
  scale: 1, tx: 0, ty: 0,
  hover: null, selected: null,
  panning: false, dragging: null, down: null, moved: false,
  canvas: null, ctx: null, raf: 0,
};

function resetGraph(centerAddr) {
  G.rawNodes = new Map();
  G.rawEdges = new Set();
  G.center = centerAddr;
  G.selected = centerAddr;
  G.hover = null;
  G.scale = 1;
  G.tx = 0;
  G.ty = 0;
}

function mergeGraphPiece(g) {
  for (const n of g.nodes) if (!G.rawNodes.has(n.addr)) G.rawNodes.set(n.addr, n.name);
  for (const [a, b] of g.edges) G.rawEdges.add(`${a}>${b}`);
}

async function showGraph(addr) {
  resetGraph(addr);
  $("#graph-info").innerHTML = t("graph.building", { addr: hexpad(addr) });
  try {
    const depth = Number($("#graph-depth").value || 2);
    mergeGraphPiece(await api(`function/${addr}/callgraph?depth=${depth}&max=${GRAPH_MAX_NODES}`));
    layoutGraph();
    fitGraph();
    updateGraphStats();
    pokeGraph();
  } catch (e) {
    $("#graph-info").textContent = t("graph.fail", { err: e.message });
  }
}

async function expandGraphNode(node) {
  if (G.rawNodes.size >= GRAPH_MAX_NODES) {
    toast(t("toast.graph_limit", { n: GRAPH_MAX_NODES }), "info");
    return;
  }
  try {
    const g = await api(`function/${node.addr}/callgraph?depth=1&max=120`);
    const beforeN = G.rawNodes.size, beforeE = G.rawEdges.size;
    mergeGraphPiece(g);
    if (G.rawNodes.size === beforeN && G.rawEdges.size === beforeE) {
      toast(t("toast.no_new"), "info", 1600);
      return;
    }
    layoutGraph();
    fitGraph();
    updateGraphStats();
    pokeGraph();
    logLine(`graph: expanded ${node.name} (${G.rawNodes.size} nodes)`, "hi");
  } catch (e) {
    toast("expand failed: " + e.message, "error");
  }
}

function updateGraphStats() {
  $("#graph-info").innerHTML = `<b>${esc(t("graph.center_addr", { addr: hexpad(G.center) }))}</b>`;
  $("#graph-stats").textContent = `${t("graph.stats", { n: G.rawNodes.size, m: G.rawEdges.size })} · ${t("graph.hint")}`;
}

/* ---------------- rank computation: callers negative, callees positive ---------------- */

function computeRanks() {
  const ranks = new Map([[G.center, 0]]);
  const adj = new Map();
  const touch = (a) => { if (!adj.has(a)) adj.set(a, []); };
  for (const key of G.rawEdges) {
    const [a, b] = key.split(">").map(Number);
    touch(a); touch(b);
    adj.get(a).push({ next: b, delta: 1 });   // a calls b
    adj.get(b).push({ next: a, delta: -1 });  // a is a caller of b
  }
  const queue = [G.center];
  while (queue.length) {
    const cur = queue.shift();
    const r = ranks.get(cur);
    for (const { next, delta } of adj.get(cur) || []) {
      if (!ranks.has(next)) {
        ranks.set(next, Math.max(-3, Math.min(3, r + delta)));
        queue.push(next);
      }
    }
  }
  for (const addr of G.rawNodes.keys()) if (!ranks.has(addr)) ranks.set(addr, 0);
  return ranks;
}

/* ---------------- layout: layers + barycenter ordering ---------------- */

function layoutGraph() {
  const ctx = G.ctx;
  const FONT = "12px 'JetBrains Mono', Consolas, monospace";
  ctx.font = FONT;
  const ranks = computeRanks();

  const nodes = [];
  const byId = new Map();
  for (const [addr, name] of G.rawNodes) {
    const tw = ctx.measureText(name).width;
    const n = {
      addr, name,
      rank: ranks.get(addr),
      w: Math.max(110, Math.min(300, tw + 34)),
      h: 42, x: 0, y: 0, kind: "same",
    };
    nodes.push(n);
    byId.set(addr, n);
  }
  for (const n of nodes) {
    n.kind = n.addr === G.center ? "center"
      : n.rank < 0 ? "caller"
      : n.rank > 0 ? "callee" : "same";
  }

  const edges = [];
  for (const key of G.rawEdges) {
    const [a, b] = key.split(">").map(Number);
    const fa = byId.get(a), fb = byId.get(b);
    if (fa && fb) edges.push({ from: a, to: b, fromNode: fa, toNode: fb });
  }

  const layers = new Map();
  for (const n of nodes) {
    if (!layers.has(n.rank)) layers.set(n.rank, []);
    layers.get(n.rank).push(n);
  }
  const sortedRanks = [...layers.keys()].sort((a, b) => a - b);

  // seed order: center first in its layer, then by address for stability
  for (const r of sortedRanks) {
    layers.get(r).sort((a, b) =>
      (a.addr === G.center ? -1 : b.addr === G.center ? 1 : a.addr - b.addr));
  }

  // barycenter sweeps to reduce crossings
  const neighbors = new Map();
  for (const e of edges) {
    if (!neighbors.has(e.from)) neighbors.set(e.from, []);
    if (!neighbors.has(e.to)) neighbors.set(e.to, []);
    neighbors.get(e.from).push(e.to);
    neighbors.get(e.to).push(e.from);
  }
  for (let pass = 0; pass < 4; pass++) {
    const pos = new Map();
    for (const r of sortedRanks) layers.get(r).forEach((n, i) => pos.set(n.addr, i));
    for (const r of sortedRanks) {
      const layer = layers.get(r);
      const bary = new Map();
      for (const n of layer) {
        const others = (neighbors.get(n.addr) || []).filter((a) => {
          const m = byId.get(a);
          return m && m.rank !== r;
        });
        bary.set(n.addr, others.length
          ? others.reduce((s, a) => s + (pos.get(a) ?? 0), 0) / others.length
          : pos.get(n.addr));
      }
      layer.sort((a, b) => (bary.get(a.addr) - bary.get(b.addr)) || (a.addr - b.addr));
    }
  }

  // pack each layer horizontally, y by rank
  for (const r of sortedRanks) {
    const layer = layers.get(r);
    const total = layer.reduce((s, n) => s + n.w, 0) + GRAPH_GAP * (layer.length - 1);
    let x = -total / 2;
    for (const n of layer) {
      n.x = x + n.w / 2;
      n.y = r * GRAPH_LAYER_H;
      x += n.w + GRAPH_GAP;
    }
  }
  const cNode = byId.get(G.center);
  if (cNode) {
    const dx = -cNode.x;
    for (const n of nodes) n.x += dx;
  }

  G.nodes = nodes;
  G.byId = byId;
  G.edges = edges;
}

function fitGraph() {
  if (!G.nodes.length) return;
  const c = G.canvas;
  const host = c.parentElement;
  let W = host ? host.clientWidth : 0;
  let H = host ? host.clientHeight : 0;
  if (!W || !H || W > 8000 || H > 8000) { W = 800; H = 500; }
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of G.nodes) {
    minX = Math.min(minX, n.x - n.w / 2); maxX = Math.max(maxX, n.x + n.w / 2);
    minY = Math.min(minY, n.y - n.h / 2); maxY = Math.max(maxY, n.y + n.h / 2);
  }
  const pad = 46;
  const gw = Math.max(1, maxX - minX + pad * 2);
  const gh = Math.max(1, maxY - minY + pad * 2);
  const fit = Math.min(W / gw, H / gh);
  // Keep labels readable: never zoom below 0.6; when the graph is wider than
  // the viewport, anchor the center node instead of the bounding box.
  G.scale = Math.max(0.6, Math.min(1.5, fit));
  const anchor = (fit < 0.6 && G.byId?.get(G.center)) || null;
  if (anchor) {
    G.tx = W / 2 - anchor.x * G.scale;
    G.ty = H / 2 - anchor.y * G.scale;
  } else {
    G.tx = W / 2 - ((minX + maxX) / 2) * G.scale;
    G.ty = H / 2 - ((minY + maxY) / 2) * G.scale;
  }
}

/* ---------------- drawing ---------------- */

function rrPath(ctx, x, y, w, h, r) {
  if (ctx.roundRect) { ctx.beginPath(); ctx.roundRect(x, y, w, h, r); return; }
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function arrowHead(ctx, x, y, angle) {
  const s = 7;
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(x - s * Math.cos(angle - 0.42), y - s * Math.sin(angle - 0.42));
  ctx.lineTo(x - s * Math.cos(angle + 0.42), y - s * Math.sin(angle + 0.42));
  ctx.closePath();
  ctx.fill();
}

function clipText(ctx, text, maxW) {
  if (ctx.measureText(text).width <= maxW) return text;
  let lo = 0, hi = text.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (ctx.measureText(text.slice(0, mid) + "…").width <= maxW) lo = mid;
    else hi = mid - 1;
  }
  return text.slice(0, lo) + "…";
}

function pokeGraph() {
  if (G.raf) return;
  G.raf = requestAnimationFrame(() => { G.raf = 0; drawGraph(); });
}

function drawGraph() {
  const c = G.canvas, ctx = G.ctx;
  if (!c || !ctx) return;
  // Guard against a layout feedback loop: never let the canvas attribute
  // size drive its own CSS size. Measure the parent instead.
  const host = c.parentElement;
  let W = host ? host.clientWidth : 0;
  let H = host ? host.clientHeight : 0;
  if (!W || !H) { W = c.clientWidth; H = c.clientHeight; }
  if (!W || !H) return;
  if (W > 8000 || H > 8000) return;   // runaway layout: refuse to draw
  const dpr = window.devicePixelRatio || 1;
  const wantW = Math.round(W * dpr), wantH = Math.round(H * dpr);
  if (c.width !== wantW || c.height !== wantH) {
    c.width = wantW;
    c.height = wantH;
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  // theme-aware palette (task: light default + graphite&rose dark)
  const P = graphPalette();
  if (P.bg) c.style.background = P.bg;
  ctx.save();
  ctx.translate(G.tx, G.ty);
  ctx.scale(G.scale, G.scale);

  const hot = G.hover;
  // ---- edges (call direction: caller -> callee) ----
  for (const e of G.edges) {
    const a = e.fromNode, b = e.toNode;
    if (!a || !b) continue;
    const lit = hot != null && (e.from === hot || e.to === hot);
    ctx.strokeStyle = lit ? P.edgeHi : P.edge;
    ctx.fillStyle = ctx.strokeStyle;
    ctx.lineWidth = lit ? 1.6 : 1.1;

    if (b.y > a.y) {
      // normal downward call edge
      const x1 = a.x, y1 = a.y + a.h / 2;
      const x2 = b.x, y2 = b.y - b.h / 2;
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
      arrowHead(ctx, x2, y2, Math.atan2(y2 - y1, x2 - x1));
    } else if (b.y < a.y) {
      // cycle / backward edge: dashed
      const x1 = a.x, y1 = a.y - a.h / 2;
      const x2 = b.x, y2 = b.y + b.h / 2;
      ctx.setLineDash([5, 4]);
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
      ctx.setLineDash([]);
      arrowHead(ctx, x2, y2, Math.atan2(y2 - y1, x2 - x1));
    } else {
      // same rank: arc above
      const dir = a.x <= b.x ? 1 : -1;
      const x1 = a.x + dir * a.w / 2, y1 = a.y - a.h / 4;
      const x2 = b.x - dir * b.w / 2, y2 = b.y - b.h / 4;
      const mx = (x1 + x2) / 2, my = Math.min(y1, y2) - 40;
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.quadraticCurveTo(mx, my, x2, y2); ctx.stroke();
      arrowHead(ctx, x2, y2, Math.atan2(y2 - my, x2 - mx));
    }
  }

  // ---- nodes ----
  for (const n of G.nodes) {
    const isCenter = n.addr === G.center;
    const isSel = n.addr === G.selected;
    const isHover = n.addr === G.hover;
    const x = n.x - n.w / 2, y = n.y - n.h / 2;

    rrPath(ctx, x, y, n.w, n.h, 6);
    ctx.fillStyle = isCenter
      ? `rgba(${P.roseRgb || "255,93,143"},.13)`
      : isHover ? P.fillHover : P.fill;
    ctx.fill();
    ctx.strokeStyle = isCenter ? P.rose
      : isSel ? P.cyan : P.stroke;
    ctx.lineWidth = isCenter || isSel ? 1.8 : 1;
    ctx.stroke();

    // left kind stripe
    const stripe = n.kind === "caller" ? P.caller
      : n.kind === "callee" ? P.callee
      : n.kind === "center" ? P.rose : P.amber;
    ctx.fillStyle = stripe;
    rrPath(ctx, x + 1.5, y + 1.5, 3.5, n.h - 3, 1.75);
    ctx.fill();

    ctx.textAlign = "left";
    ctx.font = "10px 'JetBrains Mono', Consolas, monospace";
    ctx.fillStyle = P.addr;
    ctx.fillText(hexpad(n.addr), x + 13, y + 15);

    ctx.font = "12px 'JetBrains Mono', Consolas, monospace";
    ctx.fillStyle = isCenter ? P.rose : P.text;
    ctx.fillText(clipText(ctx, n.name, n.w - 22), x + 13, y + 32);
  }

  ctx.restore();
}

function graphHit(mx, my) {
  const x = (mx - G.tx) / G.scale;
  const y = (my - G.ty) / G.scale;
  for (let i = G.nodes.length - 1; i >= 0; i--) {
    const n = G.nodes[i];
    if (Math.abs(x - n.x) <= n.w / 2 + 2 && Math.abs(y - n.y) <= n.h / 2 + 2) return n;
  }
  return null;
}

/* ---------------- interactions ---------------- */

function wireGraph() {
  const c = $("#graph-canvas");
  G.canvas = c;
  G.ctx = c.getContext("2d");
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(() => pokeGraph()).observe(c.parentElement);
  }

  c.addEventListener("mousedown", (e) => {
    const r = c.getBoundingClientRect();
    const hit = graphHit(e.clientX - r.left, e.clientY - r.top);
    G.down = hit;
    G.moved = false;
    if (hit) {
      G.dragging = hit;
    } else {
      G.panning = true;
      c.classList.add("grabbing");
    }
    e.preventDefault();
  });

  window.addEventListener("mousemove", (e) => {
    const r = c.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    if (G.dragging) {
      G.moved = true;
      G.dragging.x = (mx - G.tx) / G.scale;
      G.dragging.y = (my - G.ty) / G.scale;
      pokeGraph();
      return;
    }
    if (G.panning) {
      if (Math.abs(e.movementX) + Math.abs(e.movementY) > 2) G.moved = true;
      G.tx += e.movementX;
      G.ty += e.movementY;
      pokeGraph();
      return;
    }
    const hit = graphHit(mx, my);
    const next = hit ? hit.addr : null;
    if (next !== G.hover) {
      G.hover = next;
      c.classList.toggle("nodehover", !!hit);
      pokeGraph();
    }
  });

  window.addEventListener("mouseup", () => {
    if (G.dragging && !G.moved) {
      // plain click: select, keep whichever tab is open
      const n = G.dragging;
      G.selected = n.addr;
      S.currentFunc = { addr: n.addr, name: n.name };
      loadXrefs(n.addr);
      pokeGraph();
    }
    G.dragging = null;
    G.panning = false;
    c.classList.remove("grabbing");
  });

  c.addEventListener("dblclick", (e) => {
    const r = c.getBoundingClientRect();
    const hit = graphHit(e.clientX - r.left, e.clientY - r.top);
    if (hit) expandGraphNode(hit);
  });

  c.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = c.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const k = e.deltaY < 0 ? 1.15 : 1 / 1.15;
    const ns = Math.max(0.15, Math.min(3.5, G.scale * k));
    G.tx = mx - ((mx - G.tx) / G.scale) * ns;
    G.ty = my - ((my - G.ty) / G.scale) * ns;
    G.scale = ns;
    pokeGraph();
  }, { passive: false });

  $("#graph-refresh").onclick = () => {
    if (S.currentFunc) showGraph(S.currentFunc.addr);
  };
  $("#graph-fit").onclick = () => { fitGraph(); pokeGraph(); };
  $("#graph-depth").onchange = () => {
    if (S.currentFunc) showGraph(S.currentFunc.addr);
  };
}

/* ═══════════════════════ goto ═══════════════════════ */

async function gotoInput() {
  const v = $("#goto-input").value.trim();
  if (!v) return;
  if (/^0x[0-9a-f]+$/i.test(v) || /^\d+$/.test(v)) {
    const addr = v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10);
    showDisasm(addr, true);
  } else {
    S.functionsQuery = v;
    $("#filter-functions").value = v;
    $$("#left-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === "functions"));
    $$("#left-body > .tabpane").forEach((p) => p.classList.toggle("active", p.dataset.pane === "functions"));
    await loadFunctions(false);
    // B6: zero hits used to fail silently
    if (!S.functionsTotal) toast(t("goto.none", { q: v }), "info");
  }
}

/* ═══════════════════════ layout: resizers & drawer ═══════════════════════ */

function wireResizer(sel, cssVar, min, max) {
  const el = $(sel);
  let dragging = false;
  el.addEventListener("mousedown", (e) => { dragging = true; e.preventDefault(); });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    if (cssVar === "--left-w") {
      const w = Math.min(max, Math.max(min, e.clientX));
      document.documentElement.style.setProperty(cssVar, w + "px");
    } else {
      const w = Math.min(max, Math.max(min, window.innerWidth - e.clientX));
      document.documentElement.style.setProperty(cssVar, w + "px");
    }
  });
  window.addEventListener("mouseup", () => (dragging = false));
}

/* ═══════════════════════ F2: recent files ═══════════════════════ */

async function toggleRecentMenu() {
  const menu = $("#recent-menu");
  if (!menu.classList.contains("hidden")) { menu.classList.add("hidden"); return; }
  menu.innerHTML = `<div class="menu-empty">…</div>`;
  menu.classList.remove("hidden");
  try {
    const { items } = await api("recent");
    if (!items.length) { menu.innerHTML = `<div class="menu-empty">${esc(t("recent.none"))}</div>`; return; }
    menu.innerHTML = items.map((it) =>
      `<button class="menu-item" data-path="${esc(it.path)}">
        <span class="mi-name">${esc(it.name)}</span>
        <span class="mi-meta">${fmtSize(it.size)} · ${new Date(it.ts * 1000).toLocaleString()}</span>
      </button>`).join("");
    menu.querySelectorAll(".menu-item").forEach((b) =>
      b.onclick = () => {
        menu.classList.add("hidden");
        $("#path-input").value = b.dataset.path;
        openByPath(b.dataset.path);
      });
  } catch { menu.innerHTML = `<div class="menu-empty">—</div>`; }
}

/* ═══════════════════════ F5: PyInstaller unpack modal ═══════════════════════ */

let unpackJob = null;      // job id of the running/finished unpack
let unpackOutdir = "";     // server-side output dir (for "send to Ghidra")
let unpackPreviewName = "";

function looksBinary(bytes, name = "") {
  if (/\.pyc$/i.test(name)) return true;
  const n = Math.min(bytes.length, 800);
  if (!n) return false;
  let odd = 0;
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    if (b === 0 || (b < 0x09) || (b > 0x0d && b < 0x20)) odd++;
  }
  return odd / n > 0.08;
}

/* Only PE / ELF images can be imported by Ghidra — gating the button on the
   magic bytes prevents the "send a .manifest/.pyc to Ghidra" dead end that
   used to fail the open AND empty the engine. */
function isExecImage(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) return true;                    // MZ → PE
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return true; // ELF
  return false;
}

async function openUnpackModal() {
  openModal("#modal-unpack");
  $("#unpack-ghidra").classList.add("hidden");
  const meta = $("#unpack-meta"), list = $("#unpack-list"), prev = $("#unpack-preview");
  meta.textContent = "…";
  list.innerHTML = "";
  prev.textContent = "";
  try {
    const { job } = await api("unpack/pyinstaller", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),   // server uses the currently open binary
    });
    unpackJob = job;
    const j = await pollJob(job, (jj) => { meta.textContent = jj.progress || "…"; });
    renderUnpackResult(j.result);
  } catch (e) {
    if (/NotPyInstaller|not a pyinstaller/i.test(e.message)) meta.textContent = t("unpack.notpy");
    else meta.textContent = t("unpack.failed", { err: e.message });
  }
}

function renderUnpackResult(m) {
  if (!m || !m.outdir) { $("#unpack-meta").textContent = t("unpack.notpy"); return; }
  unpackOutdir = m.outdir;
  const bits = [m.pyinstaller || "PyInstaller", `Python ${m.python || "?"}`,
    `${m.total} ${t("unpack.entries")}`];
  if (m.pyz_modules) bits.push(`PYZ ${m.pyz_modules}`);
  if (m.warnings && m.warnings.length) bits.push(`⚠ ${m.warnings.length}`);
  $("#unpack-meta").textContent = bits.join(" · ");
  const entries = (m.entries || []).slice()
    .sort((a, b) => ((b.type === "s") - (a.type === "s")) || a.name.localeCompare(b.name));
  $("#unpack-list").innerHTML = entries.map((en) =>
    `<div class="row" tabindex="0" data-name="${esc(en.name)}">
      <span class="addr">${en.type === "s" ? "★" : esc(en.type)}</span>
      <span class="name">${esc(en.name)}</span>
      <span class="meta">${fmtSize(en.size)}</span>
    </div>`).join("");
  $("#unpack-preview").textContent = t("unpack.pick");
  $$("#unpack-list .row").forEach((row) =>
    row.onclick = () => previewUnpackedFile(row.dataset.name));
}

async function previewUnpackedFile(name) {
  unpackPreviewName = name;
  const prev = $("#unpack-preview");
  const ghidraBtn = $("#unpack-ghidra");
  prev.textContent = "…";
  ghidraBtn.classList.add("hidden");
  try {
    const res = await api(`unpack/file?job=${encodeURIComponent(unpackJob)}&name=${encodeURIComponent(name)}`);
    const bytes = b64ToBytes(res.data_b64);
    if (isExecImage(bytes)) {
      if (looksBinary(bytes, name)) prev.textContent = t("unpack.bin");
      else prev.textContent = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      ghidraBtn.classList.remove("hidden");
      return;
    }
    // not an executable image: preview text if readable, otherwise explain —
    // but never offer "send to Ghidra" for it
    if (looksBinary(bytes, name)) prev.textContent = t("unpack.bin.noexec");
    else prev.textContent = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch (e) { prev.textContent = e.message; }
}

/* ═══════════════════════ F4: keyboard shortcuts ═══════════════════════ */

function switchLeft(tab) {
  $$("#left-tabs .tab").forEach((tb) => tb.classList.toggle("active", tb.dataset.tab === tab));
  $$("#left-body > .tabpane").forEach((p) => p.classList.toggle("active", p.dataset.pane === tab));
}

function handleShortcut(e) {
  // Esc closes the topmost surface, always
  if (e.key === "Escape") {
    const open = $$(".modal-backdrop:not(.hidden)");
    if (open.length) {
      open.forEach((m) => m.classList.add("hidden"));
      if (askResolve) { const r = askResolve; askResolve = null; r(null); }
    }
    document.body.classList.remove("insp-open");
    closeCtxMenu();
    $("#recent-menu").classList.add("hidden");
    return;
  }
  const tag = document.activeElement ? document.activeElement.tagName : "";
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === "?") { openModal("#modal-keys"); return; }
  if (e.key === "g") { $("#goto-input").focus(); $("#goto-input").select(); return; }
  if (e.key === "/") { e.preventDefault(); switchLeft("functions"); $("#filter-functions").focus(); return; }
  if (e.key >= "1" && e.key <= "4") { switchLeft(["functions", "strings", "imports", "exports"][Number(e.key) - 1]); return; }
  if (e.key === "n") { renameCurrentFn(); return; }
  if (e.key === "m") { noteCurrentFn(); return; }
}

/* B7: lists are clickable divs — give keyboard users the same affordance */
function handleRowKeys(e) {
  if (e.key !== "Enter" && e.key !== " ") return;
  const row = e.target.closest(".row, .xref-row, .xor-row, .menu-item");
  if (!row || row.tagName === "BUTTON" || row.tagName === "A") return;
  e.preventDefault();
  row.click();
}

/* ═══════════════════════ boot ═══════════════════════ */

window.addEventListener("DOMContentLoaded", async () => {
  applyI18n();
  renderOpSelect();
  wireTabs("#left-tabs", "#left-body");
  wireTabs("#center-tabs", "#center-body", (tab) => {
    if (tab === "hex" && S.hexBlock && !$("#code-hex .hexgrid")) readHex();
    if (tab === "disasm" && S.currentFunc) showDisasm(S.currentFunc.addr);
    if (tab === "graph" && S.currentFunc && G.center !== S.currentFunc.addr) {
      showGraph(S.currentFunc.addr);
    } else if (tab === "graph") {
      fitGraph();
      pokeGraph();
    }
  });
  wireTabs("#drawer-tabs", "#drawer-body");
  wireResizer('[data-resize="left"]', "--left-w", 180, 520);
  wireResizer('[data-resize="right"]', "--right-w", 200, 560);
  wireGraph();
  $("#btn-show-graph").onclick = () => {
    if (S.currentFunc) {
      switchCenter("graph");
      showGraph(S.currentFunc.addr);
    } else toast(t("toast.select_fn"), "info");
  };

  // ── modals (settings / ask / keys / unpack) ──
  document.querySelectorAll(".modal-backdrop").forEach((m) => {
    m.addEventListener("mousedown", (e) => {
      if (e.target === m || e.target.closest("[data-close]")) {
        m.classList.add("hidden");
        if (m.id === "modal-ask" && askResolve) { const r = askResolve; askResolve = null; r(null); }
      }
    });
  });
  $("#btn-settings").onclick = () => {
    $("#set-lang").value = LV_LANG;
    $("#set-theme").value = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
    openModal("#modal-settings");
  };
  $("#set-lang").onchange = (e) => setLang(e.target.value);
  $("#set-theme").onchange = (e) => {
    const th = e.target.value === "dark" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", th);
    try { localStorage.setItem("lv.theme", th); } catch { /* private mode */ }
    pokeGraph();
  };
  $("#btn-keys").onclick = () => { closeModal("#modal-settings"); openModal("#modal-keys"); };
  $("#ask-ok").onclick = () => closeAsk($("#ask-input").value);
  $("#ask-clear").onclick = () => { $("#ask-input").value = ""; $("#ask-input").focus(); };
  $("#ask-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") closeAsk($("#ask-input").value);
  });

  // F1: rename / note
  $("#btn-rename-fn").onclick = renameCurrentFn;
  $("#btn-note-fn").onclick = noteCurrentFn;

  // F2: recent
  $("#btn-recent").onclick = toggleRecentMenu;
  document.addEventListener("mousedown", (e) => {
    if (!e.target.closest(".recent-wrap")) $("#recent-menu").classList.add("hidden");
    if (!e.target.closest("#ctx-menu")) closeCtxMenu();
  });

  // F5: unpack
  $("#btn-unpack").onclick = openUnpackModal;
  $("#unpack-ghidra").onclick = () => {
    if (unpackOutdir && unpackPreviewName) {
      closeModal("#modal-unpack");
      openByPath(unpackOutdir + "/" + unpackPreviewName);
    }
  };

  // F6: narrow-screen inspector drawer
  $("#btn-inspector").onclick = () => document.body.classList.toggle("insp-open");

  // F4: shortcuts + B7 row keys
  document.addEventListener("keydown", handleShortcut);
  document.addEventListener("keydown", handleRowKeys);

  // re-render translated dynamic text when the language flips
  document.addEventListener("lv:langchange", () => {
    renderOpSelect();   // op names follow the UI language
    renderOps();
    if (S.program) {
      renderProgramInfo();
      renderVerdict();
      renderSections();
      renderOverlay();
      loadConstants();
    }
    updateGraphStats();
  });

  // boot status (B2: show progress while auto-analysis is still running)
  try {
    const st = await api("status");
    $("#st-version").textContent = "lovelyreverse v" + st.version;
    if (st.analyzing) {
      engineState("busy");
      $("#st-job").textContent = st.progress || t("engine.analyzing");
      const timer = setInterval(async () => {
        try {
          const s2 = await api("status");
          $("#st-job").textContent = s2.progress || t("engine.analyzing");
          if (!s2.analyzing) {
            clearInterval(timer);
            $("#st-job").textContent = "";
            await loadProgram();
          }
        } catch { clearInterval(timer); engineState("error"); }
      }, 900);
    } else {
      engineState("idle");
      if (st.program_loaded) await loadProgram();  // server still holds a program (e.g. page refresh)
    }
  } catch (e) {
    engineState("error");
  }

  // open binary — three ways
  $("#btn-open").onclick = () => $("#file-input").click();
  $("#hero-open").onclick = () => $("#file-input").click();
  $("#file-input").onchange = (e) => { if (e.target.files[0]) uploadAndOpen(e.target.files[0]); };
  $("#path-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") openByPath(e.target.value.trim());
  });
  window.addEventListener("dragover", (e) => { e.preventDefault(); document.body.classList.add("dragging"); });
  window.addEventListener("dragleave", (e) => { if (!e.relatedTarget) document.body.classList.remove("dragging"); });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    document.body.classList.remove("dragging");
    if (e.dataTransfer.files[0]) uploadAndOpen(e.dataTransfer.files[0]);
  });

  // goto
  $("#goto-input").addEventListener("keydown", (e) => { if (e.key === "Enter") gotoInput(); });

  // filters (debounced)
  let ftimer;
  $("#filter-functions").addEventListener("input", (e) => {
    clearTimeout(ftimer);
    ftimer = setTimeout(() => { S.functionsQuery = e.target.value; loadFunctions(false); }, 250);
  });
  let stimer;
  $("#filter-strings").addEventListener("input", (e) => {
    clearTimeout(stimer);
    stimer = setTimeout(() => { S.stringsQuery = e.target.value; loadStrings(false); }, 250);
  });

  // infinite scroll on function list
  $("#list-functions").addEventListener("scroll", (e) => {
    const el = e.target;
    if (el.scrollTop + el.clientHeight > el.scrollHeight - 80 && S.functionsLoaded < S.functionsTotal) {
      loadFunctions(true);
    }
  });

  // center actions
  $("#btn-copy-code").onclick = () => {
    navigator.clipboard.writeText($("#code-decompile").innerText).then(() => toast(t("toast.copied"), "ok", 1800));
  };
  $("#btn-download-code").onclick = () => {
    if (S.currentFunc) window.location = `/api/download/decompile/${S.currentFunc.addr}.c`;
  };
  $("#btn-decompile-all").onclick = decompileAll;

  // hex controls
  $("#hex-block").onchange = (e) => { S.hexBlock = e.target.value; S.hexOffset = 0; readHex(); };
  $("#hex-prev").onclick = () => { S.hexOffset = Math.max(0, S.hexOffset - S.hexChunk); readHex(); };
  $("#hex-next").onclick = () => { S.hexOffset += S.hexChunk; readHex(); };
  $("#hex-go").onclick = () => {
    const v = $("#hex-offset").value.trim();
    if (!v) return;
    S.hexOffset = v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10) || 0;
    readHex();
  };
  $("#hex-send").onclick = () => {
    if (!S.hexBytes || !S.hexBytes.length) { toast(t("hex.empty"), "info"); return; }
    const hexText = [...S.hexBytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    sendToDecoder(hexText, "hex");
  };

  // decoder lab
  $("#btn-op-add").onclick = () => {
    const spec = OPS[Number($("#op-select").value)];
    const args = {};
    for (const [name, type, def] of spec.args) if (type !== "bool") args[name] = def ?? "";
    S.ops.push({ op: spec.op, args });
    renderOps();
  };
  $("#btn-decode").onclick = runChain;
  $("#dec-show-hex").onchange = () => {
    const out = $("#dec-output").value;
    if (out) runChain();
  };
  $("#btn-dec-copy").onclick = () => {
    navigator.clipboard.writeText($("#dec-output").value).then(() => toast(t("toast.copied"), "ok", 1500));
  };
  $("#btn-dec-paste-string").onclick = () => {
    if (S.selectedString == null) { toast(t("toast.no_string"), "info"); return; }
    sendToDecoder(S.selectedString, "text");
  };
  $("#btn-xor-brute").onclick = xorBrute;
  $("#btn-xor-derive").onclick = xorDerive;
  $("#dec-presets").addEventListener("click", (e) => {
    const b = e.target.closest("[data-preset]");
    if (!b) return;
    // xorbrute is a brute-force action, not a chain recipe — route it to xorBrute()
    if (b.dataset.preset === "xorbrute") { xorBrute(); return; }
    applyPreset(b.dataset.preset);
  });

  // search
  $("#btn-search").onclick = runSearch;
  $("#search-q").addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });

  // drawer toggle — `open`/`closed` are mutually exclusive (the hero's
  // body:has(#drawer.open) rule relies on it; stale `.open` used to keep the
  // empty-state hero hidden forever after collapsing)
  $("#drawer-toggle").onclick = () => {
    const d = $("#drawer");
    const closed = d.classList.toggle("closed");
    d.classList.toggle("open", !closed);
    $("#drawer-toggle").textContent = closed ? t("drawer.show") : t("drawer.hide");
  };

  logLine(t("log.welcome"), "ok");
});
