from __future__ import annotations

import ctypes
import ctypes.util
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from xsolver.analysis.winintercept import _exports, _image_modules
from xsolver.core.hostenv import launcher

SCRIPT = r"""
var API = %API%;
function fn(name, ret, args) {
    return new NativeFunction(ptr(API[name]), ret, args);
}
var GetTopWindow = fn('GetTopWindow', 'pointer', ['pointer']);
var GetWindow = fn('GetWindow', 'pointer', ['pointer', 'uint']);
var FindWindowExA = fn('FindWindowExA', 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
var GetClassNameA = fn('GetClassNameA', 'int', ['pointer', 'pointer', 'int']);
var GetWindowTextA = fn('GetWindowTextA', 'int', ['pointer', 'pointer', 'int']);
var SetWindowTextA = fn('SetWindowTextA', 'bool', ['pointer', 'pointer']);
var GetClassNameW = fn('GetClassNameW', 'int', ['pointer', 'pointer', 'int']);
var GetWindowTextW = fn('GetWindowTextW', 'int', ['pointer', 'pointer', 'int']);
var SetWindowTextW = fn('SetWindowTextW', 'bool', ['pointer', 'pointer']);
var SendMessageA = fn('SendMessageA', 'pointer', ['pointer', 'uint', 'pointer', 'pointer']);
var PostMessageA = fn('PostMessageA', 'bool', ['pointer', 'uint', 'pointer', 'pointer']);
var GetWindowThreadProcessId = fn('GetWindowThreadProcessId', 'uint', ['pointer', 'pointer']);
var IsWindowVisible = fn('IsWindowVisible', 'bool', ['pointer']);
var GetDlgCtrlID = fn('GetDlgCtrlID', 'int', ['pointer']);
var GetCurrentProcessId = fn('GetCurrentProcessId', 'uint', []);

var GW_HWNDNEXT = 2;
var BM_CLICK = 0x00F5;
var WM_SETTEXT = 0x000C;
var EDITS = /^(edit|richedit|richedit20a|richedit20w|maskededit|tedit)/i;
var BUTTONS = /^(button|tbutton|tbitbtn)/i;
var STATICS = /^(static|tlabel|label|msctls_statusbar)/i;

var box = null;
var op = null;
var last = null;

function ansiText(handle) {
    try {
        var buffer = Memory.alloc(1024);
        buffer.writeByte(0);
        var size = GetWindowTextA(handle, buffer, 512);
        if (size > 0) { return buffer.readCString(); }
    } catch (error) {}
    try {
        var wide = Memory.alloc(2048);
        wide.writeU16(0);
        var count = GetWindowTextW(handle, wide, 512);
        if (count > 0) { return wide.readUtf16String(); }
    } catch (error) {}
    return '';
}

function ansiClass(handle) {
    try {
        var buffer = Memory.alloc(512);
        buffer.writeByte(0);
        if (GetClassNameA(handle, buffer, 256) > 0) { return buffer.readCString(); }
    } catch (error) {}
    try {
        var wide = Memory.alloc(1024);
        wide.writeU16(0);
        if (GetClassNameW(handle, wide, 256) > 0) { return wide.readUtf16String(); }
    } catch (error) {}
    return '';
}

function writeText(handle, value) {
    var wide = Memory.alloc((value.length + 1) * 2);
    wide.writeUtf16String(value);
    if (SetWindowTextW(handle, wide)) { return true; }
    var narrow = Memory.alloc(value.length + 1);
    narrow.writeUtf8String(value);
    return SetWindowTextA(handle, narrow) !== 0;
}

function childList(parent) {
    var found = [];
    var handle = FindWindowExA(parent, ptr(0), ptr(0), ptr(0));
    var guard = 0;
    while (!handle.isNull() && guard < 256) {
        found.push(handle);
        handle = FindWindowExA(parent, handle, ptr(0), ptr(0));
        guard += 1;
    }
    return found;
}

function descendants(parent, depth) {
    var found = childList(parent);
    if (depth <= 0) { return found; }
    var copy = found.slice();
    copy.forEach(function (item) { found = found.concat(descendants(item, depth - 1)); });
    return found;
}

function topLevel() {
    var list = [];
    var handle = GetTopWindow(ptr(0));
    var guard = 0;
    while (!handle.isNull() && guard < 512) {
        list.push(handle);
        handle = GetWindow(handle, GW_HWNDNEXT);
        guard += 1;
    }
    return list;
}

function scan() {
    var pid = GetCurrentProcessId();
    var candidates = [];
    topLevel().forEach(function (handle) {
        var owner = Memory.alloc(4);
        owner.writeU32(0);
        GetWindowThreadProcessId(handle, owner);
        var mine = owner.readU32() === pid;
        candidates.push({handle: handle, mine: mine, klass: ansiClass(handle), text: ansiText(handle)});
    });
    var ordered = candidates.filter(function (item) { return item.mine; })
        .concat(candidates.filter(function (item) { return !item.mine; }));
    var best = null;
    ordered.forEach(function (item) {
        if (best !== null) { return; }
        var kids = descendants(item.handle, 3);
        var edit = null, button = null, texts = [];
        kids.forEach(function (kid) {
            var klass = ansiClass(kid);
            var text = ansiText(kid);
            if (edit === null && EDITS.test(klass)) { edit = kid; }
            if (button === null && BUTTONS.test(klass)) { button = kid; }
            if (text) { texts.push(text); }
        });
        if (edit !== null) {
            best = {window: item.handle, klass: item.klass, title: item.text,
                    edit: edit, button: button, texts: texts};
        }
    });
    if (best === null) { return {edit: null, windows: candidates.length}; }
    var summary = {edit: 1, button: best.button === null ? 0 : 1,
                   texts: best.texts.length, klass: best.klass, title: best.title,
                   labels: best.texts.slice(0, 8), windows: candidates.length};
    return summary;
}

function textsOf(window) {
    var texts = [];
    descendants(window, 3).forEach(function (kid) {
        if (EDITS.test(ansiClass(kid))) { return; }
        var text = ansiText(kid);
        if (text) { texts.push(text); }
    });
    return texts;
}

function collect(window) {
    var pid = GetCurrentProcessId();
    var texts = [];
    if (window !== null) {
        texts = texts.concat(textsOf(window));
    } else {
        topLevel().forEach(function (handle) {
            var owner = Memory.alloc(4);
            owner.writeU32(0);
            GetWindowThreadProcessId(handle, owner);
            if (owner.readU32() !== pid) { return; }
            texts = texts.concat(textsOf(handle));
        });
    }
    if (box !== null) {
        if (box.text && texts.indexOf(box.text) < 0) { texts.push(box.text); }
        if (box.caption && texts.indexOf(box.caption) < 0) { texts.push(box.caption); }
    }
    return texts;
}

function finish(payload, error) {
    last = {kind: op === null ? null : op.kind, payload: payload, error: error || null};
    op = null;
}

var SKIP_BUTTONS = /(exit|quit|fermer|close|cancel|annul|abort|about|help|clear|raz)/i;
var WANT_BUTTONS = /(check|verif|valid|register|enregistr|ok|submit|login|connect|enter|unlock|go|send|test)/i;

function windowOf(handle) {
    var kids = descendants(handle, 3);
    var edits = [], buttons = [];
    kids.forEach(function (kid) {
        var klass = ansiClass(kid);
        if (EDITS.test(klass)) { edits.push(kid); }
        if (BUTTONS.test(klass)) { buttons.push(kid); }
    });
    return {window: handle, edits: edits, buttons: buttons};
}

function chooseButton(buttons) {
    var best = null, bestScore = -1;
    buttons.forEach(function (handle) {
        var text = ansiText(handle);
        var score = 1;
        if (WANT_BUTTONS.test(text)) { score += 5; }
        if (SKIP_BUTTONS.test(text)) { score -= 8; }
        if (score > bestScore) { best = handle; bestScore = score; }
    });
    return bestScore > 0 ? best : null;
}

function targetWindow() {
    var pid = GetCurrentProcessId();
    var found = null;
    topLevel().forEach(function (handle) {
        if (found !== null) { return; }
        var owner = Memory.alloc(4);
        owner.writeU32(0);
        GetWindowThreadProcessId(handle, owner);
        if (owner.readU32() !== pid) { return; }
        var info = windowOf(handle);
        if (info.edits.length > 0) { found = info; }
    });
    return found;
}

function pressButton(index) {
    var pid = GetCurrentProcessId();
    var list = [];
    topLevel().forEach(function (handle) {
        var owner = Memory.alloc(4);
        owner.writeU32(0);
        GetWindowThreadProcessId(handle, owner);
        if (owner.readU32() !== pid) { return; }
        descendants(handle, 3).forEach(function (kid) {
            if (BUTTONS.test(ansiClass(kid))) { list.push(kid); }
        });
    });
    var usable = list.filter(function (handle) { return !SKIP_BUTTONS.test(ansiText(handle)); });
    if (index < 0 || index >= usable.length) { return {buttons: usable.length, pressed: -1}; }
    PostMessageA(usable[index], BM_CLICK, ptr(0), ptr(0));
    return {buttons: usable.length, pressed: index};
}

function dismissDialogs(keep) {
    var pid = GetCurrentProcessId();
    var closed = 0;
    topLevel().forEach(function (handle) {
        if (handle.equals(keep)) { return; }
        var owner = Memory.alloc(4);
        owner.writeU32(0);
        GetWindowThreadProcessId(handle, owner);
        if (owner.readU32() !== pid) { return; }
        var klass = ansiClass(handle);
        var kids = descendants(handle, 3);
        var hasEdit = false, button = null;
        kids.forEach(function (kid) {
            var name = ansiClass(kid);
            if (EDITS.test(name)) { hasEdit = true; }
            if (button === null && BUTTONS.test(name)) { button = kid; }
        });
        if (hasEdit) { return; }
        if (button !== null) {
            PostMessageA(button, BM_CLICK, ptr(0), ptr(0));
            closed += 1;
        } else if (klass.indexOf('#32770') === 0) {
            PostMessageA(handle, 0x0010, ptr(0), ptr(0));
            closed += 1;
        }
    });
    return closed;
}

function work() {
    if (op === null) { return; }
    try {
        if (op.kind === 'layout') { finish(scan()); return; }
        if (op.kind === 'press') { finish(pressButton(op.candidate)); return; }
        if (op.kind === 'dismiss') {
            var target = targetWindow();
            finish({closed: dismissDialogs(target === null ? ptr(0) : target.window)});
            return;
        }
        if (op.phase === 0) {
            var target = targetWindow();
            if (target === null) { finish(null, 'no editable control'); return; }
            op.window = target.window;
            op.before = textsOf(target.window);
            target.edits.forEach(function (handle) { writeText(handle, op.candidate); });
            op.verify = ansiText(target.edits[0]);
            var button = chooseButton(target.buttons);
            op.control = button === null ? '' : ansiText(button);
            if (button !== null) {
                PostMessageA(button, BM_CLICK, ptr(0), ptr(0));
            } else {
                PostMessageA(target.edits[0], 0x0100, ptr(13), ptr(0));
            }
            op.phase = 1;
            op.stamp = Date.now();
            return;
        }
        if (op.phase === 1) {
            op.ticks = (op.ticks || 0) + 1;
            if (box !== null) {
                finish({typed: op.verify, texts: collect(op.window), box: box,
                        control: op.control, source: 'messagebox'});
                return;
            }
            var texts = collect(op.window);
            var changed = texts.join('\u0001') !== op.before.join('\u0001');
            if (changed && op.ticks > 1) {
                finish({typed: op.verify, texts: texts, control: op.control,
                        source: 'inline'});
                return;
            }
            if (op.force) {
                finish({typed: op.verify, texts: texts, control: op.control,
                        source: 'settled'});
                return;
            }
            return;
        }
    } catch (error) {
        finish(null, String(error));
    }
}

function hook(name) {
    if (!API[name]) { return; }
    try { Interceptor.attach(ptr(API[name]), function () { work(); }); } catch (error) {}
}

['GetMessageA', 'GetMessageW', 'PeekMessageA', 'PeekMessageW',
 'DispatchMessageA', 'DispatchMessageW', 'MsgWaitForMultipleObjects',
 'MsgWaitForMultipleObjectsEx', 'WaitMessage', 'NtUserGetMessage',
 'NtUserPeekMessage', 'NtUserMessageCall', 'NtUserMsgWaitForMultipleObjectsEx',
 'NtUserWaitMessage'].forEach(hook);

function capture(wide) {
    return new NativeCallback(function (owner, text, caption, style) {
        try {
            var message = wide ? text.readUtf16String() : text.readCString();
            var title = wide ? caption.readUtf16String() : caption.readCString();
            box = {text: message || '', caption: title || ''};
        } catch (error) {
            box = {text: '', caption: ''};
        }
        return 1;
    }, 'int', ['pointer', 'pointer', 'pointer', 'uint']);
}

if (API['MessageBoxA']) {
    try { Interceptor.replace(ptr(API['MessageBoxA']), capture(false)); } catch (error) {}
}
if (API['MessageBoxW'] && API['MessageBoxW'] !== API['MessageBoxA']) {
    try { Interceptor.replace(ptr(API['MessageBoxW']), capture(true)); } catch (error) {}
}
if (API['MessageBoxExA']) {
    try { Interceptor.replace(ptr(API['MessageBoxExA']), capture(false)); } catch (error) {}
}

rpc.exports = {
    request: function (kind, candidate) {
        if (op !== null) { return false; }
        op = {kind: kind, candidate: candidate, phase: 0};
        last = null;
        box = null;
        return true;
    },
    state: function () {
        return {busy: op !== null, last: last};
    },
    flush: function () {
        if (op === null) { return false; }
        op.force = true;
        return true;
    },
    reset: function () {
        var busy = op !== null;
        op = null;
        return busy;
    },
    hooks: function () {
        var names = [];
        ['GetMessageA', 'PeekMessageA', 'DispatchMessageA', 'MessageBoxA',
         'MessageBoxW', 'SetWindowTextW', 'PostMessageA'].forEach(function (name) {
            if (API[name]) { names.push(name); }
        });
        return names;
    }
};
"""

NEEDED = {
    "user32.dll": ["GetTopWindow", "GetWindow", "FindWindowExA", "FindWindowExW",
                   "GetClassNameA", "GetClassNameW", "GetWindowTextA", "GetWindowTextW",
                   "SetWindowTextA", "SetWindowTextW", "SendMessageA", "SendMessageW",
                   "PostMessageA", "PostMessageW", "GetWindowThreadProcessId",
                   "IsWindowVisible", "GetDlgCtrlID", "MessageBoxA", "MessageBoxW",
                   "MessageBoxExA", "GetMessageA", "GetMessageW", "PeekMessageA",
                   "PeekMessageW", "DispatchMessageA", "DispatchMessageW",
                   "MsgWaitForMultipleObjects", "MsgWaitForMultipleObjectsEx",
                   "WaitMessage"],
    "win32u.dll": ["NtUserGetMessage", "NtUserPeekMessage", "NtUserMessageCall",
                   "NtUserMsgWaitForMultipleObjectsEx", "NtUserWaitMessage"],
    "kernel32.dll": ["GetCurrentProcessId"],
}

_last_error: str | None = None

def last_error() -> str | None:
    return _last_error

def _same_image(reported: str, wanted: str) -> bool:
    tail = reported.replace("\\", "/").rsplit("/", 1)[-1]
    return tail.lower() == wanted.lower()

def resolve_api(pid: int) -> dict[str, int]:
    table: dict[str, int] = {}
    modules = _image_modules(pid)
    for name, functions in NEEDED.items():
        for path, base in modules:
            if Path(path).name.lower() != name:
                continue
            exports = _exports(path)
            for function in functions:
                offset = exports.get(function)
                if offset is not None:
                    table[function] = base + offset
            break
    return table

class _X11:
    def __init__(self) -> None:
        self.display = None
        self.test = None
        self.lib = None
        self.position = 0
        self.rect: tuple[int, int, int, int] | None = None
        self.window = 0
        self.windows: list[tuple[tuple[int, int, int, int], int]] = []
        self.hint = ""

    def connect(self) -> bool:
        if self.display:
            return True
        try:
            self.lib = ctypes.CDLL(ctypes.util.find_library("X11") or "libX11.so.6")
            self.test = ctypes.CDLL(ctypes.util.find_library("Xtst") or "libXtst.so.6")
        except OSError:
            return False
        self.lib.XOpenDisplay.restype = ctypes.c_void_p
        self.lib.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self.lib.XFlush.argtypes = [ctypes.c_void_p]
        self.test.XTestFakeMotionEvent.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
        self.lib.XDefaultRootWindow.restype = ctypes.c_ulong
        self.lib.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        self.lib.XQueryTree.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                        ctypes.POINTER(ctypes.c_ulong),
                                        ctypes.POINTER(ctypes.c_ulong),
                                        ctypes.POINTER(ctypes.POINTER(ctypes.c_ulong)),
                                        ctypes.POINTER(ctypes.c_uint)]
        self.lib.XGetClassHint.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
        self.lib.XFree.argtypes = [ctypes.c_void_p]
        self.lib.XClearArea.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int,
                                        ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
        self.lib.XRaiseWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.lib.XGetGeometry.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                          ctypes.POINTER(ctypes.c_ulong),
                                          ctypes.POINTER(ctypes.c_int),
                                          ctypes.POINTER(ctypes.c_int),
                                          ctypes.POINTER(ctypes.c_uint),
                                          ctypes.POINTER(ctypes.c_uint),
                                          ctypes.POINTER(ctypes.c_uint),
                                          ctypes.POINTER(ctypes.c_uint)]
        self._handler = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)(
            lambda display, event: 0)
        self.lib.XSetErrorHandler.argtypes = [ctypes.c_void_p]
        self.lib.XSetErrorHandler.restype = ctypes.c_void_p
        handle = self.lib.XOpenDisplay(None)
        if not handle:
            return False
        self.display = ctypes.c_void_p(handle)
        self.lib.XSetErrorHandler(self._handler)
        return True

    def forget(self) -> None:
        self.rect = None
        self.window = 0
        self.windows = []
        self.hint = ""

    def locate(self, hint: str) -> tuple[int, int, int, int] | None:
        if self.hint != hint:
            self.hint = hint
            self.rect = None
        if self.rect is not None:
            return self.rect
        if not self.connect():
            return None
        root = self.lib.XDefaultRootWindow(self.display)
        root_return = ctypes.c_ulong()
        parent_return = ctypes.c_ulong()
        children = ctypes.POINTER(ctypes.c_ulong)()
        count = ctypes.c_uint()
        if not self.lib.XQueryTree(self.display, ctypes.c_ulong(root),
                                   ctypes.byref(root_return), ctypes.byref(parent_return),
                                   ctypes.byref(children), ctypes.byref(count)):
            return None
        wanted = hint.lower()
        best = None
        best_area = 0
        found_rects: list[tuple[tuple[int, int, int, int], int]] = []
        try:
            for index in range(count.value):
                window = children[index]
                class_hint = (ctypes.c_void_p * 2)()
                name = ""
                if self.lib.XGetClassHint(self.display, ctypes.c_ulong(window),
                                          ctypes.byref(class_hint)):
                    label = class_hint[0]
                    name = (ctypes.cast(label, ctypes.c_char_p).value or b"").decode("latin-1").lower()
                    if label:
                        self.lib.XFree(label)
                    if class_hint[1]:
                        self.lib.XFree(class_hint[1])
                if not name or not (wanted in name or name in wanted):
                    continue
                root_ret = ctypes.c_ulong()
                x = ctypes.c_int()
                y = ctypes.c_int()
                width = ctypes.c_uint()
                height = ctypes.c_uint()
                border = ctypes.c_uint()
                depth = ctypes.c_uint()
                if not self.lib.XGetGeometry(self.display, ctypes.c_ulong(window),
                                             ctypes.byref(root_ret), ctypes.byref(x),
                                             ctypes.byref(y), ctypes.byref(width),
                                             ctypes.byref(height), ctypes.byref(border),
                                             ctypes.byref(depth)):
                    continue
                area = width.value * height.value
                if width.value >= 32 and height.value >= 32:
                    found_rects.append(((x.value, y.value, width.value, height.value), window))
                    if area > best_area:
                        best = (x.value, y.value, width.value, height.value)
                        best_area = area
                        self.window = window
        finally:
            self.lib.XFree(children)
        self.rect = best
        self.windows = found_rects
        return self.rect

    def expose(self, hint: str = "") -> bool:
        if not self.connect():
            return False
        self.locate(hint) if hint else None
        targets = [window for _rect, window in self.windows] or ([self.window] if self.window else [])
        if not targets:
            return False
        try:
            for window in targets:
                self.lib.XClearArea(self.display, ctypes.c_ulong(window), 0, 0, 0, 0, 1)
            if self.window:
                self.lib.XRaiseWindow(self.display, ctypes.c_ulong(self.window))
            self.lib.XFlush(self.display)
        except Exception:
            return False
        return True

    def nudge(self, hint: str = "") -> bool:
        if not self.connect():
            return False
        self.expose(hint)
        self.position = (self.position + 1) % 2
        rect = self.locate(hint) if hint else self.rect
        if self.windows and len(self.windows) > 1 and self.position:
            rect = self.windows[-1][0]
        if rect is None:
            grid = ((300, 300), (320, 320), (640, 480), (200, 220), (500, 400), (120, 120))
            base = grid[(self.position * 3 + int(time.time() * 4)) % len(grid)]
            x, y = base
        else:
            left, top, width, height = rect
            x = left + width // 2 + self.position
            y = top + height // 3
        try:
            self.test.XTestFakeMotionEvent(self.display, -1, int(x), int(y), 0)
            self.lib.XFlush(self.display)
        except Exception:
            return False
        return True

_x11 = _X11()

def forget_window() -> None:
    _x11.forget()

def _nudge(hint: str = "") -> bool:
    if _x11.nudge(hint):
        return True
    try:
        subprocess.run(["xdotool", "mousemove", "40,40", "mousemove", "41,41"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        return True
    except Exception:
        pass
    return False

@dataclass
class GuiSession:
    script: object
    process: object
    session: object
    layout: dict = field(default_factory=dict)
    woken: bool = False
    pid: int = 0
    hint: str = ""

    def _wait(self, kind: str, candidate: str | None = None, timeout: float = 6.0):
        script = self.script
        deadline = time.time() + timeout
        started = False
        flushed = False
        opened = time.time()
        while time.time() < deadline:
            try:
                if not started:
                    try:
                        script.exports_sync.reset()
                    except Exception:
                        pass
                    started = bool(script.exports_sync.request(kind, candidate))
                    opened = time.time()
                state = script.exports_sync.state()
            except Exception as exc:
                _note(str(exc))
                return None
            if not started:
                started = True
                continue
            if (state.get("busy") and kind == "attempt" and not flushed
                    and time.time() - opened > 0.5):
                try:
                    script.exports_sync.flush()
                    flushed = True
                except Exception:
                    pass
            if state.get("busy") and time.time() - opened > max(2.5, timeout / 3):
                try:
                    script.exports_sync.reset()
                except Exception:
                    pass
                return None
            if not state.get("busy"):
                self.woken = self.woken or _nudge(self.hint)
                return state.get("last")
            if _nudge(self.hint):
                self.woken = True
            time.sleep(0.03)
        return None

    def press(self, index: int, timeout: float = 4.0) -> dict | None:
        outcome = self._wait("press", index, timeout)
        if not outcome or outcome.get("error"):
            return None
        return outcome.get("payload")

    def dismiss(self, timeout: float = 3.0) -> dict | None:
        outcome = self._wait("dismiss", None, timeout)
        if not outcome or outcome.get("error"):
            return None
        return outcome.get("payload")

    def layout_now(self, timeout: float = 4.0) -> dict | None:
        outcome = self._wait("layout", None, timeout)
        if not outcome or outcome.get("error"):
            return None
        return outcome.get("payload")

    def alive(self) -> bool:
        try:
            if self.process is not None and self.process.poll() is not None:
                return False
            self.script.exports_sync.state()
            return True
        except Exception:
            return False

    def attempt(self, candidate: str, timeout: float = 8.0) -> dict | None:
        if not self.alive():
            return None
        self.dismiss(2.0)
        outcome = self._wait("attempt", candidate, timeout)
        if outcome and not outcome.get("error"):
            return outcome.get("payload")
        if not self.alive():
            return None
        if self.layout_now(1.5) is None:
            return None
        outcome = self._wait("attempt", candidate, timeout)
        if outcome and not outcome.get("error"):
            return outcome.get("payload")
        return None

    def close(self) -> None:
        for item in (self.session, self.process):
            if item is None:
                continue
            try:
                item.detach()
            except Exception:
                pass
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.kill()
        except Exception:
            pass

def _note(message: str) -> None:
    global _last_error
    _last_error = message

def open_session(binary_path: Path, wait_seconds: float = 20.0) -> GuiSession | None:
    _note("")
    global _last_error
    _last_error = None
    try:
        import frida
    except ImportError:
        _last_error = "frida not installed"
        return None
    binary_path = Path(binary_path)
    forget_window()
    try:
        proc = subprocess.Popen(launcher(str(binary_path)), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                cwd=str(binary_path.parent))
    except OSError as exc:
        _last_error = f"launch failed: {exc}"
        return None
    try:
        device = frida.get_local_device()
    except Exception as exc:
        _last_error = f"no frida device: {exc}"
        try:
            proc.kill()
        except OSError:
            pass
        return None
    pid = None
    deadline = time.time() + wait_seconds
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
            time.sleep(0.05)
    if pid is None:
        _last_error = "target exited before attach"
        try:
            proc.kill()
        except OSError:
            pass
        return None
    api = {}
    api_deadline = time.time() + 8.0
    while time.time() < api_deadline:
        api = resolve_api(pid)
        if "GetMessageA" in api or "GetMessageW" in api:
            break
        if proc.poll() is not None:
            break
        time.sleep(0.15)
    if "GetMessageA" not in api and "GetMessageW" not in api:
        _last_error = f"user32 not resolved ({len(api)} symbols)"
        try:
            proc.kill()
        except OSError:
            pass
        return None
    source = SCRIPT.replace("%API%", "{" + ", ".join(
        f'"{name}": "0x{address:x}"' for name, address in api.items()) + "}")
    try:
        session = frida.attach(pid)
        script = session.create_script(source)
        script.load()
    except Exception as exc:
        _last_error = f"attach failed: {exc}"
        try:
            proc.kill()
        except OSError:
            pass
        return None
    gui = GuiSession(script=script, process=proc, session=session, pid=pid,
                     hint=binary_path.name)
    payload = gui.layout_now(8.0) or {}
    if not payload.get("edit"):
        payload = _open_dialog(gui) or payload
    if not payload.get("edit"):
        _last_error = _last_error or "no editable window"
        gui.close()
        return None
    gui.layout = payload
    return gui

def _open_dialog(gui: GuiSession) -> dict | None:
    first = gui.press(-1)
    if not first:
        return None
    for index in range(int(first.get("buttons") or 0)):
        if not gui.alive():
            return None
        gui.press(index)
        time.sleep(0.6)
        payload = gui.layout_now(3.0) or {}
        if payload.get("edit"):
            return payload
    return None

def drive(binary_path: Path, candidates, budget_seconds: float = 60.0,
          waiter=None, session: GuiSession | None = None):
    own = session is None
    gui = session or open_session(Path(binary_path))
    if gui is None:
        return []
    results = []
    start = time.time()
    try:
        for candidate in candidates:
            if time.time() - start > budget_seconds:
                break
            payload = gui.attempt(str(candidate))
            if payload is None:
                continue
            texts = [str(item) for item in (payload.get("texts") or [])]
            results.append((str(candidate), texts))
            if waiter is not None and waiter(texts):
                break
    finally:
        if own:
            gui.close()
    return results
