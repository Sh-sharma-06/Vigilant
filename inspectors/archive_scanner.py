"""
Safe Recursive Archive Scanner for 7Z, TAR, GZIP, BZ2, and XZ containers.
Defends against Archive Bombs (size/member caps) and Path Traversal (Tar/Zip Slip).
"""
from __future__ import annotations
import bz2
import gzip
import lzma
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List

MAX_MEMBERS = 100
MAX_UNCOMPRESSED = 250 * 1024 * 1024  # 250 MB
SEVERITY_RANK = {"BENIGN": 0, "UNKNOWN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


def _is_unsafe_path(name: str) -> bool:
    norm = name.replace("\\", "/")
    return norm.startswith("/") or ".." in norm.split("/") or (len(norm) > 1 and norm[1] == ":")


def scan_archive(path: str, fmt: str, dispatch_fn: Callable[[str], Dict[str, Any]]) -> Dict[str, Any]:
    p = Path(path)
    findings: List[Dict[str, Any]] = []
    worst = "BENIGN"
    scanned = 0

    def _bump(v: str):
        nonlocal worst
        if SEVERITY_RANK.get(v, 0) > SEVERITY_RANK.get(worst, 0):
            worst = v

    with tempfile.TemporaryDirectory(prefix="vigilant_arc_") as tmpdir:
        tmp = Path(tmpdir)
        extracted: List[Path] = []

        try:
            if fmt == "TAR" or (fmt in ("GZIP", "BZ2", "XZ") and tarfile.is_tarfile(str(p))):
                with tarfile.open(str(p), "r:*") as tf:
                    members = tf.getmembers()
                    if len(members) > MAX_MEMBERS:
                        findings.append({"severity": "SUSPICIOUS", "type": "ARCHIVE_TOO_MANY_FILES", "detail": f"{len(members)} members"})
                        _bump("SUSPICIOUS")
                    total_sz = 0
                    for m in members[:MAX_MEMBERS]:
                        if _is_unsafe_path(m.name):
                            findings.append({"severity": "MALICIOUS", "type": "ARCHIVE_PATH_TRAVERSAL", "detail": f"Unsafe member path: {m.name!r}"})
                            _bump("MALICIOUS")
                            continue
                        if not m.isfile():
                            continue
                        total_sz += m.size
                        if total_sz > MAX_UNCOMPRESSED:
                            findings.append({"severity": "MALICIOUS", "type": "ARCHIVE_BOMB", "detail": f"Uncompressed size exceeds {MAX_UNCOMPRESSED} bytes"})
                            _bump("MALICIOUS")
                            break
                        out = tmp / f"m_{len(extracted)}_{Path(m.name).name}"
                        src = tf.extractfile(m)
                        if src:
                            out.write_bytes(src.read())
                            extracted.append(out)

            elif fmt in ("GZIP", "BZ2", "XZ"):
                opener = {"GZIP": gzip.open, "BZ2": bz2.open, "XZ": lzma.open}[fmt]
                out = tmp / (p.stem or "decompressed.bin")
                with opener(str(p), "rb") as src, out.open("wb") as dst:
                    data = src.read(MAX_UNCOMPRESSED + 1)
                    if len(data) > MAX_UNCOMPRESSED:
                        findings.append({"severity": "MALICIOUS", "type": "ARCHIVE_BOMB", "detail": "Decompressed stream exceeds cap"})
                        _bump("MALICIOUS")
                    else:
                        dst.write(data)
                        extracted.append(out)

            elif fmt == "7Z":
                cli = shutil.which("7z") or shutil.which("7za")
                if cli:
                    res = subprocess.run([cli, "x", "-y", f"-o{tmp}", str(p)], capture_output=True, timeout=15)
                    if res.returncode != 0:
                        findings.append({"severity": "SUSPICIOUS", "type": "7Z_EXTRACT_ERROR", "detail": res.stderr.decode("utf-8", errors="replace")[:150]})
                        _bump("SUSPICIOUS")
                    else:
                        extracted = [f for f in tmp.rglob("*") if f.is_file()][:MAX_MEMBERS]
                else:
                    try:
                        import py7zr  # type: ignore
                        with py7zr.SevenZipFile(str(p), mode="r") as z:
                            for name in z.getnames():
                                if _is_unsafe_path(name):
                                    findings.append({"severity": "MALICIOUS", "type": "ARCHIVE_PATH_TRAVERSAL", "detail": f"Unsafe 7z path: {name!r}"})
                                    _bump("MALICIOUS")
                            if worst != "MALICIOUS":
                                z.extractall(path=str(tmp))
                                extracted = [f for f in tmp.rglob("*") if f.is_file()][:MAX_MEMBERS]
                    except ImportError:
                        findings.append({
                            "severity": "SUSPICIOUS",
                            "type": "7Z_UNPACKER_MISSING",
                            "detail": "7Z archive detected but neither py7zr nor 7z CLI is installed (install p7zip-full for deep scan)",
                        })
                        _bump("SUSPICIOUS")

            for member_path in extracted:
                scanned += 1
                sub = dispatch_fn(str(member_path))
                sv = str(sub.get("verdict", "BENIGN")).upper()
                if sv in ("MALICIOUS", "SUSPICIOUS"):
                    _bump(sv)
                    findings.append({
                        "severity": sv,
                        "type": f"ARCHIVE_MEMBER_{sv}",
                        "detail": f"{member_path.name}: {sub.get('summary', sv)}",
                    })

        except Exception as e:
            _bump("SUSPICIOUS")
            findings.append({"severity": "SUSPICIOUS", "type": "ARCHIVE_PARSE_ERROR", "detail": str(e)})

    conf = 0.96 if worst == "MALICIOUS" else (0.72 if worst == "SUSPICIOUS" else 0.94)
    summary = findings[0]["detail"] if findings else f"Clean {fmt} archive ({scanned} member(s) inspected)"
    return {
        "verdict": worst,
        "confidence": conf,
        "format": fmt,
        "summary": summary,
        "findings": findings,
        "features": {"format": fmt, "members_scanned": scanned},
    }
