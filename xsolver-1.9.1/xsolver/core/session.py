from __future__ import annotations

import os
import queue
import re
import select
import subprocess
import threading
import time

try:
    import termios
except ImportError:
    termios = None
from dataclasses import dataclass, field
from pathlib import Path

from xsolver.core.hostenv import IS_WINDOWS
from xsolver.core.runner import RunnerLimits

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_DEFAULT_QUIET = 0.45
_MAX_TRANSCRIPT = 32_000

@dataclass
class Exchange:
    prompt: str
    answer: str | None
    reply: str = ""

@dataclass
class Session:
    path: Path
    limits: RunnerLimits | None = None
    argv: list[str] | None = None
    exchanges: list[Exchange] = field(default_factory=list)
    output: str = ""
    _process: subprocess.Popen | None = None
    _master: int | None = None
    _pending: str = ""
    _pipe_queue: queue.Queue[bytes | None] | None = None
    _pipe_eof: bool = False
    _reader_thread: threading.Thread | None = None

    def open(self) -> None:
        from xsolver.core.runtime import RuntimeUnavailable, runtime_for

        runtime = runtime_for(self.path)
        if not runtime.executable:
            raise RuntimeUnavailable(f"{Path(self.path).name}: no runtime")
        if IS_WINDOWS:
            self._open_pipes(runtime)
            return

        import pty

        master, slave = pty.openpty()
        if termios is not None:
            try:
                attributes = termios.tcgetattr(slave)
                attributes[3] &= ~(termios.ECHO | termios.ICANON)
                termios.tcsetattr(slave, termios.TCSANOW, attributes)
            except (OSError, AttributeError, termios.error):
                pass
        environment = runtime.environment()
        if runtime.runner == "wine":
            environment.pop("DISPLAY", None)
        try:
            self._process = subprocess.Popen(
                runtime.command(self.argv),
                stdin=slave, stdout=slave, stderr=slave,
                cwd=str(Path(self.path).parent),
                env=environment, start_new_session=True, close_fds=True,
            )
        finally:
            os.close(slave)
        self._master = master

    def _open_pipes(self, runtime) -> None:
        environment = runtime.environment()
        self._process = subprocess.Popen(
            runtime.command(self.argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(Path(self.path).parent),
            env=environment,
            bufsize=0,
        )
        pipe_queue: queue.Queue[bytes | None] = queue.Queue()
        self._pipe_queue = pipe_queue
        stream = self._process.stdout
        if stream is None:
            raise RuntimeError("subprocess stdout pipe was not created")

        def read_output() -> None:
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    pipe_queue.put(chunk)
            except OSError:
                pass
            finally:
                pipe_queue.put(None)

        self._reader_thread = threading.Thread(target=read_output, daemon=True)
        self._reader_thread.start()

    def read_until_quiet(self, quiet: float = _DEFAULT_QUIET, timeout: float = 6.0) -> str:
        if self._pipe_queue is not None:
            return self._read_pipe_until_quiet(quiet, timeout)
        if self._master is None:
            return ""
        deadline = time.monotonic() + timeout
        last_data = time.monotonic()
        collected = ""
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self._master], [], [], 0.05)
            if ready:
                try:
                    chunk = os.read(self._master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                collected += chunk.decode("latin-1")
                last_data = time.monotonic()
            else:
                if collected and time.monotonic() - last_data >= quiet:
                    break
                if self._process is not None and self._process.poll() is not None and collected:
                    break
        text = _clean(collected)
        self.output = (self.output + text)[-_MAX_TRANSCRIPT:]
        self._pending += text
        return text

    def _read_pipe_until_quiet(self, quiet: float, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        last_data = time.monotonic()
        collected = bytearray()
        pipe_queue = self._pipe_queue
        if pipe_queue is None:
            return ""
        while time.monotonic() < deadline and not self._pipe_eof:
            remaining = deadline - time.monotonic()
            wait = min(0.05, remaining)
            if collected:
                wait = min(wait, max(0.0, quiet - (time.monotonic() - last_data)))
            try:
                chunk = pipe_queue.get(timeout=wait)
            except queue.Empty:
                if collected and time.monotonic() - last_data >= quiet:
                    break
                if self._process is not None and self._process.poll() is not None and pipe_queue.empty():
                    break
                continue
            if chunk is None:
                self._pipe_eof = True
                break
            collected.extend(chunk)
            last_data = time.monotonic()

        text = _clean(collected.decode("latin-1"))
        self.output = (self.output + text)[-_MAX_TRANSCRIPT:]
        self._pending += text
        return text

    def send_line(self, text: str, terminator: str = "\r") -> None:
        if self._pipe_queue is not None:
            process = self._process
            if process is None or process.stdin is None:
                return
            newline = "\r\n" if terminator == "\r" else terminator
            payload = text.encode("latin-1", "replace") + newline.encode("latin-1")
            try:
                process.stdin.write(payload)
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
            return
        if self._master is None:
            return
        payload = text.encode("latin-1", "replace") + terminator.encode("latin-1")
        try:
            os.write(self._master, payload)
        except OSError:
            return

    def answer(self, text: str, quiet: float = _DEFAULT_QUIET) -> str:
        self.send_line(text, "\r")
        first = self.read_until_quiet(quiet=quiet)
        body = _strip_echo(first, text)
        if not body.strip() and self.alive():
            self.send_line("", "\n")
            second = self.read_until_quiet(quiet=quiet)
            body = _strip_echo(second, text)
        return body

    def alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def take_prompt(self) -> str:
        value = self._pending
        self._pending = ""
        return value

    def close(self) -> None:
        process = self._process
        self._process = None
        if self._master is not None:
            try:
                os.close(self._master)
            except OSError:
                pass
            self._master = None
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.terminate()
            process.wait(timeout=2)
        except Exception:
            try:
                process.kill()
                process.wait(timeout=2)
            except Exception:
                pass
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=1)
            self._reader_thread = None
        self._pipe_queue = None
        self._pipe_eof = False

def _clean(text: str) -> str:
    return _ANSI.sub("", text).replace("\r", "").replace("\x08", "")

def _strip_echo(text: str, answer: str) -> str:
    cleaned = text.replace("^J", "\n")
    cleaned = cleaned.replace(answer, " ")
    lines = [line.strip() for line in cleaned.splitlines()]
    return "\n".join(line for line in lines if line)

@dataclass
class DialogueResult:
    steps: list[str]
    transcript: str
    finished: bool
    success: bool

def run_dialogue(path: Path, answers: list[str], limits: RunnerLimits | None = None,
                 quiet: float = _DEFAULT_QUIET) -> DialogueResult:
    from xsolver.analysis.prompts import classify

    session = Session(path=path, limits=limits)
    transcript = ""
    verdict = None
    try:
        session.open()
        session.read_until_quiet(quiet=quiet)
        for answer in answers:
            session.send_line(answer)
            reply = session.read_until_quiet(quiet=quiet)
            transcript += reply
            verdict = classify(reply)
            if verdict in ("failure", "success"):
                break
            if not session.alive():
                break
    finally:
        session.close()
    return DialogueResult(steps=list(answers), transcript=transcript,
                          finished=verdict == "success", success=verdict == "success")
