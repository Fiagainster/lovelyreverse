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

function engineState(mode, label) {
  const dot = $("#engine-dot");
  dot.className = `engine-dot ${mode}`;
  dot.querySelector(".dot-label").textContent = label;
  const st = $("#st-engine");
  st.textContent = `● engine ${label}`;
  st.className = mode;
}

function setBusy(b, label = "working") {
  engineState(b ? "busy" : (S.program ? "ready" : "idle"), b ? label : (S.program ? "ready" : "idle"));
  $("#st-job").textContent = b ? label : "";
}

/* ═══════════════════════ opening binaries ═══════════════════════ */

async function openByPath(path) {
  if (!path) return;
  setBusy(true, "opening");
  logLine(`open ${path}`, "hi");
  try {
    const { job } = await api("open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    await pollJob(job, (j) => {
      $("#st-job").textContent = j.progress || "opening";
    });
    logLine("analysis complete", "ok");
    await loadProgram();
  } catch (e) {
    toast(`open failed: ${e.message}`, "error");
    logLine(`open failed: ${e.message}`, "err");
  } finally {
    setBusy(false);
  }
}

async function uploadAndOpen(file) {
  setBusy(true, "uploading");
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

async function loadProgram() {
  S.program = await api("program");
  S.triage = await api("triage");
  $("#hero").classList.add("hidden");
  $("#st-program").textContent = S.program.name;
  engineState("ready", "ready");
  renderProgramInfo();
  renderSections();
  renderOverlay();
  S.functionsLoaded = 0; S.funcMap.clear();
  $("#list-functions").innerHTML = "";
  $("#count-functions").textContent = "";
  await loadFunctions(false);
  loadStrings();
  loadImportsExports();
  loadBlocks();
  loadConstants();
  toast(`${S.program.name} — ${S.program.function_count} functions analyzed`, "info");
}

/* ═══════════════════════ left: functions ═══════════════════════ */

const PAGE = 400;

async function loadFunctions(append) {
  const list = $("#list-functions");
  if (!append) { S.functionsLoaded = 0; list.innerHTML = `<div class="loading">analyzing functions</div>`; }
  const offset = S.functionsLoaded;
  try {
    const data = await api(`functions?q=${encodeURIComponent(S.functionsQuery)}&offset=${offset}&limit=${PAGE}`);
    if (!append) list.innerHTML = "";
    S.functionsTotal = data.total;
    $("#count-functions").textContent = data.total;
    $("#st-fn").textContent = `${data.total} fn`;
    for (const f of data.items) addFuncRow(list, f);
    S.functionsLoaded += data.items.length;
    if (!data.items.length && !append)
      list.innerHTML = `<div class="code-empty">no functions match</div>`;
  } catch (e) {
    if (!append) list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`;
  }
}

function addFuncRow(list, f) {
  S.funcMap.set(f.name, f.addr);
  const row = document.createElement("div");
  row.className = "row";
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
  $("#btn-copy-code").classList.remove("hidden");
  $("#btn-download-code").classList.remove("hidden");
  const code = $("#code-decompile");
  code.innerHTML = `<div class="loading">decompiling ${esc(name)}</div>`;
  try {
    const res = await api(`function/${addr}/decompile`);
    renderCode(res.code);
    if (activeTab("#center-tabs") !== "decompile" && !opts.keepTab)
      switchCenter("decompile");
  } catch (e) {
    code.innerHTML = `<div class="code-empty">decompile failed: ${esc(e.message)}</div>`;
  }
  loadXrefs(addr);
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
      out += `<span class="a" data-addr="${addr ?? ""}" data-name="${esc(ghsym)}">${esc(ghsym)}</span>`;
    }
    else if (kw) out += `<span class="k">${esc(kw)}</span>`;
    else if (dec) out += `<span class="n">${esc(dec)}</span>`;
    else if (call) {
      const known = S.funcMap.get(call);
      out += `<span class="f${known != null ? " a" : ""}"${known != null ? ` data-addr="${known}" data-name="${esc(call)}"` : ""}>${esc(call)}</span>`;
    }
    last = m.index + tok.length;
  }
  out += esc(code.slice(last));
  return out;
}

function renderCode(codeText) {
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
  $("#disasm-title").textContent = `…loading ${hexpad(addr)}`;
  try {
    const res = await api(`function/${addr}/disasm`);
    $("#disasm-title").innerHTML = `<b>${esc(res.function || "?")}</b> · ${hexpad(res.function_addr ?? addr)}`;
    box.innerHTML = res.instructions.map((ins) => {
      const parts = ins.text.split(/\s+/);
      const mn = parts[0] || "";
      const rest = ins.text.slice(mn.length);
      const target = ins.refs && ins.refs.length
        ? `<span class="disasm-target" data-addr="${ins.refs[0]}">${hexpad(ins.refs[0])}</span>`
        : "";
      return `<div class="disasm-row" data-addr="${ins.addr}">
        <span class="disasm-addr">${hexpad(ins.addr)}</span>
        <span class="disasm-bytes">${esc(ins.bytes)}</span>
        <span class="disasm-text"><span class="disasm-mnemonic">${esc(mn)}</span>${esc(rest)} ${target}</span>
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
    const cur = box.querySelector(`.disasm-row[data-addr="${addr}"]`);
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
  if (!append) list.innerHTML = `<div class="loading">collecting strings</div>`;
  try {
    const data = await api(`strings?q=${encodeURIComponent(S.stringsQuery)}&limit=400`);
    if (!append) list.innerHTML = "";
    $("#count-strings").textContent = data.total;
    $("#st-str").textContent = `${data.total} strings`;
    if (!data.items.length) { list.innerHTML = `<div class="code-empty">no strings match</div>`; return; }
    for (const s of data.items) {
      const row = document.createElement("div");
      row.className = "row";
      row.innerHTML = `<span class="addr">${hexpad(s.addr)}</span><span class="val"><span class="lit">${esc(s.value)}</span></span><span class="meta">${s.length}</span>`;
      row.onclick = () => { S.selectedString = s.value; loadXrefs(s.addr); toast("string loaded into decoder lab", "info", 2200); };
      list.appendChild(row);
    }
  } catch (e) { if (!append) list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
}

async function loadImportsExports() {
  for (const [which, sel] of [["imports", "#list-imports"], ["exports", "#list-exports"]]) {
    const list = $(sel);
    list.innerHTML = `<div class="loading">reading ${which}</div>`;
    try {
      const data = await api(which);
      list.innerHTML = "";
      if (!data.items.length) { list.innerHTML = `<div class="code-empty">none</div>`; continue; }
      for (const it of data.items) {
        const row = document.createElement("div");
        row.className = "row";
        row.innerHTML = which === "imports"
          ? `<span class="name">${esc(it.name)}</span><span class="meta">${esc(it.library || "")}</span>`
          : `<span class="addr">${hexpad(it.addr)}</span><span class="name">${esc(it.name)}</span>`;
        list.appendChild(row);
      }
    } catch (e) { list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
  }
}

/* ═══════════════════════ inspector ═══════════════════════ */

function renderProgramInfo() {
  const p = S.program;
  $("#program-info").innerHTML = `<dl class="kv">
    <dt>name</dt><dd class="long">${esc(p.name)}</dd>
    <dt>format</dt><dd>${esc(p.format)}</dd>
    <dt>arch</dt><dd>${esc(p.language_id)}</dd>
    <dt>compiler</dt><dd>${esc(p.compiler)}</dd>
    <dt>base</dt><dd class="mono-addr">${hexpad(parseInt(p.image_base, 16))}</dd>
    <dt>size</dt><dd>${Number(p.size).toLocaleString()}</dd>
    <dt>functions</dt><dd>${p.function_count}</dd>
  </dl>`;
}

function renderSections() {
  const box = $("#sections-info");
  const secs = S.triage.sections || [];
  if (!secs.length) { box.innerHTML = `<div class="insp-empty">no section table</div>`; return; }
  box.innerHTML = secs.map((s) => {
    const ent = s.entropy != null ? s.entropy.toFixed(2) : "—";
    const w = s.entropy != null ? Math.min(100, s.entropy / 8 * 100) : 0;
    const packed = s.entropy > 7.2 ? ` <span style="color:var(--rose)">· likely packed</span>` : "";
    return `<div class="sec-row">
      <div class="sec-line1"><span class="sec-name">${esc(s.name)}</span><span class="sec-ent">H=${ent}${packed}</span></div>
      <div class="sec-bar"><i style="width:${w}%"></i></div>
      <div class="sec-meta">${Number(s.raw_size || s.size).toLocaleString()} bytes @ ${hexa(s.raw_offset ?? s.offset)}</div>
    </div>`;
  }).join("");
}

function renderOverlay() {
  const box = $("#overlay-info");
  const t = S.triage;
  if (t.overlay_present) {
    box.innerHTML = `<div class="overlay-box">
      <div class="overlay-title">⚠ appended data detected</div>
      <div class="sec-meta">${t.overlay_size.toLocaleString()} bytes after last section, starting at ${hexa(t.overlay_offset)}</div>
      <div class="sec-meta">binwalk-style magic scan lives in the search tab · view it in memory hex or carve it out manually</div>
    </div>`;
  } else {
    box.innerHTML = `<div class="overlay-box clean"><div class="overlay-title clean">✓ nothing appended</div></div>`;
  }
}

async function loadXrefs(addr) {
  $("#xrefs-target").textContent = hexa(addr);
  const box = $("#xrefs-info");
  box.innerHTML = `<div class="loading">tracing refs</div>`;
  try {
    const res = await api(`function/${addr}/xrefs`);
    let html = "";
    if (res.to.length) {
      html += `<div class="xref-label">referenced by (${res.to.length})</div>`;
      html += res.to.slice(0, 40).map((r) =>
        `<div class="xref-row" data-addr="${r.addr}"><span class="xref-type">${esc(r.type)}</span><span class="xref-addr">${hexpad(r.addr)}</span><span class="xref-name">${esc(r.function || "")}</span></div>`).join("");
    } else html += `<div class="insp-empty">nothing references this</div>`;
    if (res.from.length) {
      html += `<div class="xref-label">references out (${res.from.length})</div>`;
      html += res.from.slice(0, 40).map((r) =>
        `<div class="xref-row" data-addr="${r.to}"><span class="xref-type">${esc(r.type)}</span><span class="xref-addr">${hexpad(r.to)}</span></div>`).join("");
    }
    box.innerHTML = html;
    box.querySelectorAll(".xref-row").forEach((row) =>
      row.onclick = () => {
        const a = parseInt(row.dataset.addr, 16);
        const fn = funcNameByAddr(a);
        if (fn) selectFunction(a, fn);
        else showDisasm(a);
      });
  } catch (e) { box.innerHTML = `<div class="insp-empty">${esc(e.message)}</div>`; }
}

async function loadConstants() {
  const box = $("#constants-info");
  box.innerHTML = `<div class="loading">scanning crypto constants</div>`;
  try {
    const res = await api("constants");
    $("#count-constants").textContent = res.items.length;
    if (!res.items.length) {
      box.innerHTML = `<div class="insp-empty">no known crypto constants — nothing standard here (or it's custom 🌹)</div>`;
      return;
    }
    box.innerHTML = res.items.map((h) =>
      `<div class="xref-row" data-addr="${h.addr}" title="${esc(h.note)}">
        <span class="xref-type">${hexa(h.addr).slice(2, 10)}</span>
        <span class="xref-name">${esc(h.name)}</span>
        <span class="chip c-${h.category === "hash" ? "hash" : h.category === "ecc" ? "ecc" : h.category === "encoding" ? "encoding" : "crypto"}">${esc(h.function || h.block || "")}</span>
      </div>`).join("");
    box.querySelectorAll(".xref-row").forEach((row) =>
      row.onclick = () => showDisasm(parseInt(row.dataset.addr, 16)));
    toast(`${res.items.length} crypto constant hits — check the inspector`, "info");
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
  if (!S.hexBlock) { box.innerHTML = `<div class="code-empty">no memory blocks</div>`; return; }
  box.innerHTML = `<div class="loading">reading memory</div>`;
  try {
    const res = await api(`memory/read?block=${encodeURIComponent(S.hexBlock)}&offset=${S.hexOffset}&len=${S.hexChunk}`);
    const bytes = b64ToBytes(res.data_b64);
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
  { op: "to_hex", label: "Hex → encode", args: [["sep", "str", "e.g. ' '"], ["upper", "bool"]] },
  { op: "from_hex", label: "Hex → decode", args: [] },
  { op: "to_base64", label: "Base64 → encode", args: [["urlsafe", "bool"]] },
  { op: "from_base64", label: "Base64 → decode", args: [] },
  { op: "to_base32", label: "Base32 → encode", args: [] },
  { op: "from_base32", label: "Base32 → decode", args: [] },
  { op: "to_ascii85", label: "Ascii85 → encode", args: [] },
  { op: "from_ascii85", label: "Ascii85 → decode", args: [] },
  { op: "url_encode", label: "URL → encode", args: [] },
  { op: "url_decode", label: "URL → decode", args: [] },
  { op: "rot", label: "ROT-n", args: [["n", "int", 13]] },
  { op: "rot47", label: "ROT47", args: [["n", "int", 47]] },
  { op: "xor", label: "XOR repeating key", args: [["key", "str", "ATRI"], ["hex", "bool"]] },
  { op: "xor_pos", label: "XOR with offset", args: [["key", "str", "00"], ["offset", "int", 0], ["hex", "bool"]] },
  { op: "rc4", label: "RC4", args: [["key", "str", "secret"]] },
  { op: "reverse", label: "Reverse bytes", args: [] },
  { op: "bit_not", label: "NOT bits", args: [] },
  { op: "c_escape", label: "C escape", args: [] },
  { op: "c_unescape", label: "C unescape", args: [] },
  { op: "hexdump", label: "Hexdump", args: [] },
  { op: "gzip_decompress", label: "GZip decompress", args: [] },
  { op: "gzip_compress", label: "GZip compress", args: [] },
  { op: "zlib_decompress", label: "Zlib decompress", args: [] },
  { op: "zlib_compress", label: "Zlib compress", args: [] },
  { op: "raw_inflate", label: "Raw inflate", args: [] },
  { op: "md5", label: "MD5", args: [] },
  { op: "sha1", label: "SHA-1", args: [] },
  { op: "sha256", label: "SHA-256", args: [] },
];

function renderOpSelect() {
  $("#op-select").innerHTML = OPS.map((o, i) => `<option value="${i}">${esc(o.label)}</option>`).join("");
}

function renderOps() {
  const list = $("#op-list");
  if (!S.ops.length) { list.innerHTML = `<div class="insp-empty">no ops — result passes through unchanged</div>`; return; }
  list.innerHTML = S.ops.map((o, i) => {
    const spec = OPS.find((s) => s.op === o.op);
    const args = spec.args.map(([name, type, def]) => {
      const v = o.args[name] ?? def ?? "";
      if (type === "bool") return `<label class="chk"><input type="checkbox" data-i="${i}" data-arg="${name}" ${v ? "checked" : ""}>${name}</label>`;
      return `<span class="op-arg">${name}<input data-i="${i}" data-arg="${name}" value="${esc(String(v))}"></span>`;
    }).join("");
    return `<div class="op-item">
      <span class="op-arrow">${i + 1}.</span><span class="op-name">${esc(spec.label)}</span>
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
          `<div class="xor-row" data-key="${r.key}"><span class="xor-key">${r.key_hex}</span><span class="xor-score">${r.score}</span><span class="xor-preview">${esc(r.preview)}</span></div>`).join("")
      : `<div class="insp-empty">no single-byte key produced readable text — try the derive tool</div>`;
    box.querySelectorAll(".xor-row").forEach((row) =>
      row.onclick = () => {
        const key = row.dataset.key;
        S.ops = [{ op: "xor", args: { key: key.toString(16).padStart(2, "0") } }];
        renderOps(); runChain();
      });
  } catch (e) { toast(e.message, "error"); }
}

async function xorDerive() {
  const prefix = $("#dec-prefix").value;
  if (!prefix) { toast("enter a known prefix first (e.g. flag{)", "info"); return; }
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
          `<div class="xor-row" data-key="${r.key_bytes}"><span class="xor-key">len ${r.length}</span><span class="xor-score">key</span><span class="xor-preview">${esc(r.key_display)}</span></div>`).join("")
      : `<div class="insp-empty">no consistent key for that prefix</div>`;
    box.querySelectorAll(".xor-row").forEach((row) =>
      row.onclick = () => {
        S.ops = [{ op: "xor", args: { key: row.dataset.key } }];
        renderOps(); runChain();
      });
  } catch (e) { toast(e.message, "error"); }
}

/* ═══════════════════════ search ═══════════════════════ */

async function runSearch() {
  const pat = $("#search-hex").value.trim();
  const box = $("#search-results");
  if (!pat) return;
  box.innerHTML = `<div class="loading">searching memory</div>`;
  $("#search-info").textContent = "";
  try {
    const res = await api(`search?hex=${encodeURIComponent(pat)}&limit=400`);
    $("#search-info").textContent = `${res.items.length} hit(s)`;
    if (!res.items.length) { box.innerHTML = `<div class="code-empty">no matches in initialized memory</div>`; return; }
    box.innerHTML = "";
    for (const h of res.items) {
      const row = document.createElement("div");
      row.className = "row";
      row.innerHTML = `<span class="addr">${hexpad(h.addr)}</span><span class="name">${esc(h.block)}</span><span class="meta">${esc(h.function || "")}</span>`;
      row.onclick = () => showDisasm(h.addr);
      box.appendChild(row);
    }
  } catch (e) { box.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
}

/* ═══════════════════════ decompile-all ═══════════════════════ */

async function decompileAll() {
  setBusy(true, "decompiling all");
  logLine("batch decompile started", "hi");
  try {
    const { job } = await api("export/decompile-all", { method: "POST" });
    await pollJob(job, (j) => {
      $("#st-job").textContent = j.progress || "decompiling";
      if (j.log.length) logLine(j.log[j.log.length - 1]);
    });
    toast("zip ready — download starting", "ok");
    logLine("batch decompile done", "ok");
    window.location = `/api/download/decompile-all.zip?job=${job}`;
  } catch (e) {
    toast(`batch failed: ${e.message}`, "error");
    logLine(`batch failed: ${e.message}`, "err");
  } finally { setBusy(false); }
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

/* ═══════════════════════ boot ═══════════════════════ */

window.addEventListener("DOMContentLoaded", async () => {
  renderOpSelect();
  wireTabs("#left-tabs", "#left-body");
  wireTabs("#center-tabs", "#center-body", (tab) => {
    if (tab === "hex" && S.hexBlock && !$("#code-hex .hexgrid")) readHex();
    if (tab === "disasm" && S.currentFunc) showDisasm(S.currentFunc.addr);
  });
  wireTabs("#drawer-tabs", "#drawer-body");
  wireResizer('[data-resize="left"]', "--left-w", 180, 520);
  wireResizer('[data-resize="right"]', "--right-w", 200, 560);

  // boot status
  try {
    const st = await api("status");
    $("#st-version").textContent = "lovelyreverse v" + st.version;
    engineState("idle", "idle");
    if (st.program_loaded) {
      await loadProgram();  // server still holds a program (e.g. page refresh)
    }
  } catch (e) {
    engineState("error", "unreachable");
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
    navigator.clipboard.writeText($("#code-decompile").innerText).then(() => toast("pseudocode copied", "ok", 1800));
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
    navigator.clipboard.writeText($("#dec-output").value).then(() => toast("copied", "ok", 1500));
  };
  $("#btn-dec-paste-string").onclick = () => {
    if (S.selectedString == null) { toast("click a string in the sidebar first", "info"); return; }
    $("#dec-input").value = S.selectedString;
    document.querySelector('input[name="dec-mode"][value="text"]').checked = true;
  };
  $("#btn-xor-brute").onclick = xorBrute;
  $("#btn-xor-derive").onclick = xorDerive;

  // search
  $("#btn-search").onclick = runSearch;
  $("#search-hex").addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });

  // drawer toggle
  $("#drawer-toggle").onclick = () => {
    const d = $("#drawer");
    d.classList.toggle("closed");
    $("#drawer-toggle").textContent = d.classList.contains("closed") ? "▴ panels" : "▾ hide";
  };

  logLine("lovelyreverse ready — open a binary to begin", "ok");
});
