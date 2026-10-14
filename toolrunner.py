"""Shared plumbing for the external-tool wrappers (nmap/feroxbuster/ffuf/subfinder).

Each wrapper's real job is tool-specific: how to build the command line and how to
parse the tool's output into the pipeline's JSON schema. Everything around that —
checking the binary is installed, managing a temp output file, running with a
timeout and turning the two universal failures (non-zero exit, timeout) into an
error string — is identical, so it lives here once instead of in four files.
"""
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


def has_tool(binary: str) -> bool:
    """True if `binary` is on PATH. Callers format their own not-found message."""
    return shutil.which(binary) is not None


def file_missing(path: str, label: str = "file") -> str | None:
    """Return an error string if `path` is not a readable file, else None."""
    return None if Path(path).is_file() else f"{label} not found: {path}"


@contextmanager
def temp_output(suffix: str):
    """Yield a temp path for a tool to write to, and always remove it on exit —
    so every early return inside the block is cleaned up without a manual unlink."""
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = tmp.name
    try:
        yield tmp_path
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def run(cmd: list[str], *, timeout: int, label: str | None = None,
        capture: bool = False, check: bool = True):
    """Run a subprocess and return (error_or_None, completed_or_None).

    Handles the two failures every wrapper shares — a non-zero exit (when
    check=True) and a timeout. KeyboardInterrupt is left to propagate so a
    caller that treats Ctrl+C specially can catch it.
    """
    name = label or cmd[0]
    try:
        proc = subprocess.run(cmd, check=check, timeout=timeout,
                              capture_output=capture, text=capture)
        return None, proc
    except subprocess.CalledProcessError:
        return f"{name} exited with an error (see output above)", None
    except subprocess.TimeoutExpired:
        return f"{name} timed out ({timeout}s)", None
