from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from xsolver.core.hostenv import IS_WINDOWS, base_env, launcher, module_ranges

ATTACH_SECONDS = 6.0
MAX_EVENTS = 64

READERS = {"fgets": 0, "gets": 0, "ReadConsoleA": 1, "ReadConsoleW": 1, "fread": 0,
           "scanf": 1, "fscanf": 2, "sscanf": 1, "_read": 1, "read": 1, "getline": 0}

STREAM_READERS = ("?getline@?$basic_istream@DU", "?read@?$basic_istream@DU",
                  "?sgetn@?$basic_streambuf@DU", "?xsgetn@?$basic_streambuf@DU",
                  "?get@?$basic_istream@DU")

_last_error: str | None = None

def last_error() -> str | None:
    return _last_error

def _same_image(reported: str, wanted: str) -> bool:
    tail = reported.replace("\\", "/").rsplit("/", 1)[-1]
    return tail.lower() == wanted.lower()

def _wine_env() -> dict[str, str]:
    if IS_WINDOWS:
        return base_env()
    env = dict(os.environ)
    env.setdefault("WINEPREFIX", str(Path.home() / ".cache/xsolver-wine"))
    env["WINEDEBUG"] = "-all"
    env.setdefault("XDG_RUNTIME_DIR", "/tmp/rt")
    env.setdefault("DISPLAY", ":99")
    return env

def _modules(pid: int) -> list[tuple[str, int]]:
    if IS_WINDOWS:
        return [(path, base) for path, base, _ in module_ranges(pid)]
    spans: dict[str, list[tuple[int, int]]] = {}
    try:
        lines = Path(f"/proc/{pid}/maps").read_text().splitlines()
    except OSError:
        return []
    for line in lines:
        parts = line.split()
        if len(parts) < 6 or not parts[5].lower().endswith((".dll", ".exe")):
            continue
        start, end = (int(value, 16) for value in parts[0].split("-"))
        spans.setdefault(parts[5], []).append((start, end))
    return [(path, min(r[0] for r in regions)) for path, regions in spans.items()]

def _exports(path: str) -> dict[str, int]:
    try:
        import pefile

        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        return {symbol.name.decode("latin-1"): symbol.address
                for symbol in getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []) if symbol.name}
    except Exception:
        return {}

SCRIPT = r"""
var hooks = {hooks};
var streamHooks = {stream_hooks};
var needleHex = '{needle}';
var armed = false;
var page = null;
var total = 0;
var target = null;

function hex(ptrValue, length) {{
  var out = '';
  try {{
    var bytes = new Uint8Array(ptrValue.readByteArray(length));
    for (var i = 0; i < bytes.length; i++) {{
      out += ('0' + bytes[i].toString(16)).slice(-2);
    }}
  }} catch (e) {{ return ''; }}
  return out;
}}

function rearm() {{
  if (total >= {max_events} || page === null) return;
  try {{
    MemoryAccessMonitor.enable([{{ base: page, size: 0x1000 }}], {{ onAccess: onAccess }});
  }} catch (e) {{ send({{ stage: 'arm_error', error: String(e) }}); }}
}}

function onAccess(details) {{
  total++;
  var record = {{ from: String(details.from), addr: String(details.address),
                 op: details.operation, code: hex(details.from, 12), regs: {{}} }};
  try {{
    var c = details.context;
    record.regs = {{ eax: String(c.eax), ecx: String(c.ecx), edx: String(c.edx),
                     ebx: String(c.ebx), esi: String(c.esi), edi: String(c.edi),
                     esp: String(c.esp), ebp: String(c.ebp) }};
    record.dumps = {{}};
    Object.keys(record.regs).forEach(function (name) {{
      var value = record.regs[name];
      if (value === undefined) return;
      var number = parseInt(value, 16);
      if (!number || number < 0x100000 || number > 0x7fffffff) return;
      try {{
        var text = hex(ptr(value), 48);
        if (text) record.dumps[name] = text;
      }} catch (e) {{}}
    }});
  }} catch (e) {{ record.regs = {{ error: String(e) }}; }}
  send(record);
  MemoryAccessMonitor.disable();
  setTimeout(rearm, 1);
}}

function contains(haystackPtr, length) {{
  try {{
    var bytes = new Uint8Array(haystackPtr.readByteArray(length));
    var pattern = [];
    for (var i = 0; i < needleHex.length; i += 2) pattern.push(parseInt(needleHex.substr(i, 2), 16));
    for (var j = 0; j + pattern.length <= bytes.length; j++) {{
      var match = true;
      for (var k = 0; k < pattern.length; k++) {{
        if (bytes[j + k] !== pattern[k]) {{ match = false; break; }}
      }}
      if (match) return true;
    }}
  }} catch (e) {{}}
  return false;
}}

function locate(candidates) {{
  for (var i = 0; i < candidates.length; i++) {{
    var pointer = candidates[i];
    if (!pointer) continue;
    var number = parseInt(String(pointer), 16);
    if (!number || number < 0x10000 || number > 0x7fffffff) continue;
    if (contains(ptr(number), 128)) return ptr(number);
  }}
  return null;
}}

function arm(bufferPtr) {{
  if (armed || bufferPtr === null) return;
  if (String(bufferPtr) === '0x0') return;
  page = bufferPtr.and(ptr('0xfffff000'));
  armed = true;
  send({{ stage: 'armed', page: String(page), buffer: String(bufferPtr) }});
  rearm();
}}

hooks.forEach(function (hook) {{
  try {{
    Interceptor.attach(ptr(hook.addr), {{
      onEnter: function (args) {{
        this.buffer = null;
        try {{ this.buffer = args[hook.arg]; }} catch (e) {{}}
      }},
      onLeave: function () {{
        if (!armed) arm(this.buffer);
      }}
    }});
    send({{ stage: 'hooked', fn: hook.fn }});
  }} catch (e) {{
    send({{ stage: 'hook_error', fn: hook.fn, error: String(e) }});
  }}
}});
streamHooks.forEach(function (hook) {{
  try {{
    Interceptor.attach(ptr(hook.addr), {{
      onEnter: function (args) {{
        this.snapshot = [];
        for (var i = 0; i < 4; i++) {{
          try {{ this.snapshot.push(args[i]); }} catch (e) {{}}
        }}
        try {{ this.stack = this.context.esp; }} catch (e) {{ this.stack = null; }}
      }},
      onLeave: function (retval) {{
        if (armed) return;
        var hit = locate(this.snapshot);
        if (hit === null && this.stack !== null) {{
          var probe = this.stack.sub(0x2000);
          for (var offset = 0; offset < 0x4000; offset += 0x10) {{
            if (contains(probe.add(offset), 64)) {{ hit = probe.add(offset); break; }}
          }}
        }}
        if (hit !== null) {{
          send({{ stage: 'located', fn: hook.fn, address: String(hit) }});
          arm(hit);
        }}
      }}
    }});
    send({{ stage: 'stream_hooked', fn: hook.fn }});
  }} catch (e) {{
    send({{ stage: 'stream_error', fn: hook.fn, error: String(e) }});
  }}
}});
send({{ stage: 'ready', hooks: hooks.length, streams: streamHooks.length }});
"""

def printable(data: bytes) -> str:
    text = data.split(b"\x00")[0].decode("latin-1", "replace")
    return text if text and all(32 <= ord(ch) < 127 for ch in text) else ""

@dataclass
class Harvest:
    events: list[dict] = field(default_factory=list)
    armed: bool = False
    buffer: str = ""
    hooks: int = 0
    streams: int = 0
    error: str = ""

def _decode(raw: str) -> bytes:
    try:
        return bytes.fromhex(raw or "")
    except ValueError:
        return b""

def harvest(binary_path: Path, candidate: str = "zzqqzzzz", seconds: float = 4.0) -> Harvest:
    global _last_error
    _last_error = None
    try:
        import frida
    except ImportError:
        _last_error = "frida not installed"
        return Harvest(error=_last_error)
    binary_path = Path(binary_path)
    proc = subprocess.Popen(launcher(binary_path), stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            cwd=str(binary_path.parent), env=_wine_env())
    pid = None
    deadline = time.time() + ATTACH_SECONDS
    try:
        device = frida.get_local_device()
    except Exception as exc:
        _last_error = f"no device: {exc}"
        proc.kill()
        return Harvest(error=_last_error)
    while time.time() < deadline and pid is None:
        if proc.poll() is not None:
            break
        try:
            for item in device.enumerate_processes():
                if _same_image(item.name, binary_path.name):
                    pid = item.pid
                    break
        except Exception:
            pass
        if pid is None:
            time.sleep(0.1)
    if pid is None:
        _last_error = "target exited before attach"
        try:
            proc.kill()
        except OSError:
            pass
        return Harvest(error=_last_error)
    time.sleep(0.6)
    hooks = []
    stream_hooks = []
    for path, base in _modules(pid):
        table = _exports(path)
        for name, index in READERS.items():
            address = table.get(name)
            if address is None:
                continue
            hooks.append({"addr": hex(base + address), "fn": name, "arg": index})
        for name, rva in table.items():
            if any(name.startswith(prefix) for prefix in STREAM_READERS):
                stream_hooks.append({"addr": hex(base + rva), "fn": name[:40]})
    messages: list[dict] = []
    session = None
    try:
        session = frida.attach(pid)
        needle = "".join(f"{byte:02x}" for byte in candidate.encode("latin-1", "replace"))
        script = session.create_script(SCRIPT.format(hooks=hooks, stream_hooks=stream_hooks,
                                                    max_events=MAX_EVENTS, needle=needle))
        script.on("message", lambda message, data: messages.append(message.get("payload", {})))
        script.load()
    except Exception as exc:
        _last_error = f"attach failed: {exc}"
        proc.kill()
        return Harvest(error=_last_error)
    try:
        if candidate:
            proc.stdin.write((candidate + "\n").encode())
            proc.stdin.flush()
        end = time.time() + seconds
        while time.time() < end and proc.poll() is None:
            time.sleep(0.05)
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            proc.kill()
        if session:
            try:
                session.detach()
            except Exception:
                pass
    events = [record for record in messages if "from" in record]
    for record in events:
        record["code"] = _decode(record.get("code", ""))
        record["bytes"] = {name: _decode(value) for name, value in (record.get("dumps") or {}).items()}
    streams = sum(1 for record in messages if record.get("stage") == "stream_hooked")
    armed = any(record.get("stage") == "armed" for record in messages)
    buffer = next((record.get("buffer", "") for record in messages
                   if record.get("stage") == "armed"), "")
    if not armed:
        _last_error = "no CRT read function reached"
    return Harvest(events=events, armed=armed, buffer=buffer, hooks=len(hooks), streams=streams,
                   error="" if armed else _last_error or "")

def candidates(result: Harvest, sent: str = "") -> list[str]:
    found: list[str] = []
    sent_bytes = sent.encode("latin-1", "replace")
    for record in result.events:
        for name, data in record.get("bytes", {}).items():
            if not data or data.startswith(sent_bytes):
                continue
            text_value = printable(data)
            if len(text_value) >= 3 and text_value != sent and text_value not in found:
                found.append(text_value)
    return found
