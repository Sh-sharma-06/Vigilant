"""
behavior_sim.py - make the sandbox behave like a real person's machine over time.

Real malware often waits: "after 30 days", "once the PC has been used a while",
"only if this is not a lab VM". A sandbox that loads a file once, for a fraction
of a second, at today's date, never sees any of that. This module runs the SAME
sandbox several times, each time with:

  * a different simulated date (+0, +1 day, +1 week, +1 month, +6 months, +1 year, +3 years)
  * time.sleep() that fast-forwards the clock instead of waiting
  * an ordinary-looking host name, user name and CPU count
  * exit / abort attempts recorded and blocked, so they cannot hide a payload

Nothing here makes a file safe. It only gives dormant code more chances to show itself.
Set VIGILANT_SESSIONS=1 to run only the plain "today" session (useful as a control).
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import getpass
import os
import platform
import socket
import sys
import time
from typing import Any, Callable, Dict, List, Optional

SESSION_OFFSETS_DAYS = (0, 1, 7, 30, 180, 365, 1095)
FAKE_HOST = "DESKTOP-4H7K2LQ"
FAKE_USER = "alex"
_MAX_OFFSET = 15 * 365 * 86400.0          # never skip more than 15 years in total
_RANK = {"BENIGN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

# Originals, captured once when this module is imported.
_real_time = time.time
_real_time_ns = time.time_ns
_real_localtime = time.localtime
_real_gmtime = time.gmtime
_real_ctime = time.ctime
_real_strftime = time.strftime
_real_datetime = _dt.datetime
_real_date = _dt.date

_clock = {"active": False, "offset": 0.0}
EVENTS: List[Dict[str, Any]] = []          # exit attempts etc.; the dispatcher merges these into the telemetry


def _now() -> float:
    return _real_time() + (_clock["offset"] if _clock["active"] else 0.0)


def _fake_time() -> float:
    return _now()


def _fake_time_ns() -> int:
    return _real_time_ns() + (int(_clock["offset"] * 1_000_000_000) if _clock["active"] else 0)


def _fake_localtime(secs=None):
    return _real_localtime(_now() if secs is None else secs)


def _fake_gmtime(secs=None):
    return _real_gmtime(_now() if secs is None else secs)


def _fake_ctime(secs=None):
    return _real_ctime(_now() if secs is None else secs)


def _fake_strftime(fmt, t=None):
    return _real_strftime(fmt, _real_localtime(_now()) if t is None else t)


def _fake_sleep(seconds=0):
    """Do not wait. Move the simulated clock forward instead."""
    try:
        s = float(seconds)
    except Exception:
        s = 0.0
    if s > 0:
        _clock["offset"] = min(_clock["offset"] + s, _MAX_OFFSET)


class _WarpedDateTime(_real_datetime):
    @classmethod
    def now(cls, tz=None):
        return cls.fromtimestamp(_now(), tz)

    @classmethod
    def utcnow(cls):
        return cls.fromtimestamp(_now(), _dt.timezone.utc).replace(tzinfo=None)

    @classmethod
    def today(cls):
        return cls.fromtimestamp(_now())


class _WarpedDate(_real_date):
    @classmethod
    def today(cls):
        return cls.fromtimestamp(_now())


def _exit_recorder(name: str) -> Callable[..., None]:
    def _blocked(*args, **kwargs):
        code = args[0] if args else kwargs.get("code", 0)
        EVENTS.append({"event": "ANTI_SANDBOX_EXIT", "detail": f"{name}({code!r})"})
        raise PermissionError(f"Vigilant: blocked anti-sandbox {name}({code!r})")
    return _blocked


@contextlib.contextmanager
def warped(days: float = 0.0):
    """Run the body as if it were `days` days in the future, on an ordinary desktop."""
    undo: List[tuple] = []

    def patch(obj, attr, value):
        undo.append((obj, attr, getattr(obj, attr)))
        setattr(obj, attr, value)

    _clock["offset"] = float(days) * 86400.0
    _clock["active"] = True
    try:
        patch(time, "time", _fake_time)
        patch(time, "time_ns", _fake_time_ns)
        patch(time, "localtime", _fake_localtime)
        patch(time, "gmtime", _fake_gmtime)
        patch(time, "ctime", _fake_ctime)
        patch(time, "strftime", _fake_strftime)
        patch(time, "sleep", _fake_sleep)
        patch(_dt, "datetime", _WarpedDateTime)
        patch(_dt, "date", _WarpedDate)
        patch(socket, "gethostname", lambda: FAKE_HOST)
        patch(platform, "node", lambda: FAKE_HOST)
        patch(getpass, "getuser", lambda: FAKE_USER)
        patch(os, "getlogin", lambda: FAKE_USER)
        patch(os, "cpu_count", lambda: 8)
        patch(sys, "exit", _exit_recorder("sys.exit"))
        patch(os, "abort", _exit_recorder("os.abort"))
        low = sys.modules.get("posix") or sys.modules.get("nt")
        patch(os, "_exit", _exit_recorder("os._exit"))
        if low is not None and hasattr(low, "_exit"):
            patch(low, "_exit", _exit_recorder("posix._exit"))
        yield
    finally:
        for obj, attr, original in reversed(undo):
            setattr(obj, attr, original)
        _clock["offset"] = 0.0
        _clock["active"] = False


def drain_events() -> List[Dict[str, Any]]:
    out = list(EVENTS)
    EVENTS.clear()
    return out


def _session_days() -> tuple:
    try:
        n = int(os.environ.get("VIGILANT_SESSIONS", len(SESSION_OFFSETS_DAYS)))
    except ValueError:
        n = len(SESSION_OFFSETS_DAYS)
    return SESSION_OFFSETS_DAYS[:max(1, min(n, len(SESSION_OFFSETS_DAYS)))]


def run_sessions(run_once: Callable[[], Optional[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """Call run_once() once per simulated date and return the WORST report.
    Stops early once something is clearly malicious or an exit attempt was seen."""
    best: Optional[Dict[str, Any]] = None
    log: List[Dict[str, Any]] = []
    for days in _session_days():
        with warped(days):
            report = run_once()
        if report is None:                    # no runner attached: nothing to repeat
            return None
        verdict = str(report.get("verdict", "")).upper()
        log.append({"days_ahead": days, "verdict": verdict})
        if best is None or _RANK.get(verdict, 1) > _RANK.get(str(best.get("verdict", "")).upper(), 1):
            best = report
        if verdict == "MALICIOUS" or EVENTS:
            break
    if best is not None:
        details = best.get("technical_details")
        if not isinstance(details, dict):
            details = best["technical_details"] = {}
        details["behavior_sessions"] = log
    return best
