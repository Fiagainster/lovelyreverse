"""GDB/MI record parsing — pure logic, no I/O, unit-testable.

GDB Machine Interface output is line-oriented:

    TOKEN? ^result-class ( , result )*        result records (answers to commands)
    TOKEN? *exec-async-class ( , result )*    execution state changed (e.g. *stopped)
    TOKEN? =notify-async-class ( , result )*  bookkeeping (breakpoints created...)
    ~"c-string"                               console stream (program/gdb output)
    &"c-string"                               gdb log stream
    @"c-string"                               target stream
    (gdb)                                     prompt

Result payloads use a tiny value grammar:

    value   := c-string | tuple | list | const
    tuple   := "{" "}" | "{" result ( "," result )* "}"
    list    := "[]" | "[" value ( "," value )* "]" | "[" result ( "," result )* "]"
    result  := variable "=" value

This module classifies lines and parses payloads into plain Python dicts /
lists / strings.  Non-MI noise (e.g. the wsl.exe proxy warning) does not
match the record grammar and is reported as kind="noise" so callers can
route it to a log instead of choking.
"""

from __future__ import annotations

from typing import Any

_MI_FIRST_CHARS = set("^*=~&@")


class MiParseError(ValueError):
    pass


def _unescape_c(body: str) -> str:
    """Decode the inside of an MI c-string.

    gdb escapes '\\\\' and '"' and emits \\n / \\t / \\xHH for non-printables.
    """
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "x" and i + 3 < len(body):
                hexpart = body[i + 2 : i + 4]
                try:
                    out.append(chr(int(hexpart, 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            mapping = {"n": "\n", "r": "\r", "t": "\t", "e": "\x1b", "0": "\0"}
            out.append(mapping.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _read_string(s: str, i: int) -> tuple[str, int]:
    if i >= len(s) or s[i] != '"':
        raise MiParseError(f"expected '\"' at {i}: {s!r}")
    out = []
    i += 1
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append(s[i : i + 2])  # keep escape; unescape later
            i += 2
            continue
        if c == '"':
            return _unescape_c("".join(out)), i + 1
        out.append(c)
        i += 1
    raise MiParseError(f"unterminated string: {s!r}")


def _read_value(s: str, i: int) -> tuple[Any, int]:
    """Parse one MI value starting at s[i]; returns (value, next_index)."""
    if i >= len(s):
        raise MiParseError("unexpected end of value")
    c = s[i]
    if c == '"':
        return _read_string(s, i)
    if c == "{":
        i += 1
        if i < len(s) and s[i] == "}":
            return {}, i + 1
        result: dict[str, Any] = {}
        while True:
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] in "_-"):
                j += 1
            if j == i:
                # "{value,...}" — unnamed tuple degrades to a list
                items = []
                while True:
                    v, i2 = _read_value(s, i)
                    items.append(v)
                    i = i2
                    if i < len(s) and s[i] == ",":
                        i += 1
                        continue
                    if i < len(s) and s[i] == "}":
                        return items, i + 1
                    raise MiParseError(f"bad unnamed tuple at {i}: {s!r}")
            var = s[i:j]
            if j >= len(s) or s[j] != "=":
                raise MiParseError(f"expected '=' after {var!r} at {j}")
            v, i = _read_value(s, j + 1)
            result[var] = v
            if i < len(s) and s[i] == ",":
                i += 1
                continue
            if i < len(s) and s[i] == "}":
                return result, i + 1
            raise MiParseError(f"bad tuple at {i}: {s!r}")
    if c == "[":
        i += 1
        if i < len(s) and s[i] == "]":
            return [], i + 1
        items: list[Any] = []
        while True:
            # list of results: "name=value" vs plain values — peek for '='
            # after an identifier; gdb disambiguates by content, we parse
            # greedily: try result form, fall back to plain value.
            v, i2 = _read_value(s, i)
            if isinstance(v, str) and i2 < len(s) and s[i2] == "=":
                # looks like "var=value" inside a list
                v2, i3 = _read_value(s, i2 + 1)
                items.append({v: v2})
                i = i3
            else:
                items.append(v)
                i = i2
            if i < len(s) and s[i] == ",":
                i += 1
                continue
            if i < len(s) and s[i] == "]":
                return items, i + 1
            raise MiParseError(f"bad list at {i}: {s!r}")
    # const: bare word up to a structural char. '=' and '{' MUST stop the
    # scan — "frame={...}" in a list is var=tuple, and letting the const eat
    # the '=' made the whole "frame={level=\"0\"" one string (real bug).
    j = i
    while j < len(s) and s[j] not in ",}]={":
        j += 1
    word = s[i:j]
    if word == "":
        raise MiParseError(f"empty const at {i}: {s!r}")
    return word, j


def _split_payload(s: str) -> dict[str, Any]:
    """Parse 'var=value,var2={...},...' into a dict; tolerate bare values."""
    out: dict[str, Any] = {}
    i = 0
    n = len(s)
    bare_index = 0
    while i < n:
        j = i
        while j < n and (s[j].isalnum() or s[j] in "_-"):
            j += 1
        if j < n and s[j] == "=":
            v, nxt = _read_value(s, j + 1)
            out[s[i:j]] = v
            i = nxt
        else:
            v, nxt = _read_value(s, i)
            out[f"_bare{bare_index}"] = v
            bare_index += 1
            i = nxt
        if i < n and s[i] == ",":
            i += 1
        elif i < n:
            raise MiParseError(f"unexpected char {s[i]!r} at {i}: {s!r}")
    return out


def parse_mi_line(line: str) -> dict[str, Any] | None:
    """Classify and parse one MI output line.

    Returns {kind, class, token, payload} or None for blank/prompt lines.
    kind ∈ {result, exec, notify, console, log, target, prompt, noise}
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    if line.strip() == "(gdb)":
        return {"kind": "prompt", "class": None, "token": None, "payload": None}

    token = None
    s = line
    j = 0
    while j < len(s) and s[j].isdigit():
        j += 1
    if j > 0:
        token = s[:j]
        s = s[j:]

    if not s or s[0] not in _MI_FIRST_CHARS:
        return {"kind": "noise", "class": None, "token": token, "payload": s}

    kind_map = {"^": "result", "*": "exec", "=": "notify",
                "~": "console", "&": "log", "@": "target"}
    kind = kind_map[s[0]]
    s = s[1:]

    if kind in ("console", "log", "target"):
        text, _ = _read_string(s, 0)
        return {"kind": kind, "class": None, "token": token, "payload": text}

    # result / exec / notify: "<class>[,payload]"
    comma = s.find(",")
    if comma < 0:
        cls, payload_src = s, ""
    else:
        cls, payload_src = s[:comma], s[comma + 1 :]
    payload = _split_payload(payload_src) if payload_src else {}
    return {"kind": kind, "class": cls, "token": token, "payload": payload}


def parse_stopped(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a *stopped payload into UI-friendly fields."""
    out = {
        "reason": payload.get("reason", "unknown"),
        "stopped_threads": payload.get("stopped-threads"),
    }
    frame = payload.get("frame")
    if isinstance(frame, dict):
        out["addr"] = frame.get("addr")
        out["func"] = frame.get("func")
        out["file"] = frame.get("file")
        out["line"] = frame.get("line")
    return out


def parse_breakpoint_table(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract breakpoint list from -break-list output."""
    bpt = payload.get("BreakpointTable")
    if not isinstance(bpt, dict):
        return []
    body = bpt.get("body")
    if isinstance(body, list):
        return [item.get("bkpt", item) if isinstance(item, dict) else item for item in body]
    if isinstance(body, dict) and "bkpt" in body:
        bk = body["bkpt"]
        return bk if isinstance(bk, list) else [bk]
    return []


def format_register_values(names: list[Any], values: list[Any]) -> dict[str, str]:
    """Zip -data-list-register-names / -values output into {name: hexvalue}."""
    vals = values.get("register-values") if isinstance(values, dict) else values
    out: dict[str, str] = {}
    if not isinstance(vals, list):
        return out
    for item in vals:
        if not isinstance(item, dict):
            continue
        try:
            idx = int(item.get("number"))
        except (TypeError, ValueError):
            continue
        if 0 <= idx < len(names):
            name = names[idx]
            if isinstance(name, str):
                out[name] = str(item.get("value", ""))
    return out
