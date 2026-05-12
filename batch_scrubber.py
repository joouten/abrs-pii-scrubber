"""batch_scrubber - Batch PII scrubbing pipeline for ABRS PII Scrubber.

v0.3.0 - Process every file in `input/`, write sanitized copies to
`output/`, move sources to `archive/`, and emit one combined audit log
at `output/audit_log.txt`.

Wraps the v0.2 `scrub()` from `pii_scrubber.py` - no PII regex logic
lives here. This file is concerned with file orchestration only.

Usage:
    python batch_scrubber.py

Folder contract:
    input/    drop source files here (any extension, any filename)
    output/   sanitized files land here (same filename as source)
              plus a combined audit_log.txt per run
    archive/  source files moved here after a successful scrub
              (filename collisions get a .YYYYMMDDTHHMMSS suffix)

Files are read with an encoding fallback chain of UTF-8 -> UTF-8-sig ->
latin-1. latin-1 cannot raise UnicodeDecodeError, so when it is reached
the script also runs a cheap NUL-byte heuristic to flag likely UTF-16
sources that decoded into garbled output.
"""

import os
import subprocess
import sys
import shutil
import time
from pathlib import Path

# Ensure pii_scrubber is importable regardless of the CWD the script is
# invoked from.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from pii_scrubber import scrub  # noqa: E402

__version__ = "0.3.0"

INPUT_DIR = _HERE / "input"
OUTPUT_DIR = _HERE / "output"
ARCHIVE_DIR = _HERE / "archive"
AUDIT_LOG_NAME = "audit_log.txt"
ENCODINGS = ("utf-8", "utf-8-sig", "latin-1")

# Heuristic threshold for "this was probably UTF-16 decoded as 8-bit":
# UTF-16 ASCII content has a NUL byte between every printable char, so
# anything above this ratio is overwhelmingly likely to be mis-decoded.
NUL_RATIO_GARBLED = 0.05


def _read_with_fallback(path: Path):
    """Return (text, encoding_used, garbled_flag) or raise on total failure."""
    last_error = None
    for enc in ENCODINGS:
        try:
            with open(path, "r", encoding=enc) as f:
                text = f.read()
        except UnicodeDecodeError as e:
            last_error = e
            continue
        garbled = False
        if enc == "latin-1" and text:
            nul_ratio = text.count("\x00") / len(text)
            if nul_ratio > NUL_RATIO_GARBLED:
                garbled = True
        return text, enc, garbled
    raise UnicodeDecodeError(  # pragma: no cover - only if all encodings fail
        "all-fallbacks", b"", 0, 1, f"unreadable: {last_error}"
    )


def _archive_target(source_name: str) -> Path:
    """Return a non-colliding path inside archive/ for `source_name`."""
    target = ARCHIVE_DIR / source_name
    if not target.exists():
        return target
    stem = target.stem
    suffix = target.suffix
    stamp = time.strftime("%Y%m%dT%H%M%S")
    return ARCHIVE_DIR / f"{stem}.{stamp}{suffix}"


def _open_in_file_manager(path: Path) -> None:
    """Open `path` in the platform's default file manager. Best-effort -
    a failure here (no GUI, xdg-open missing, headless CI) is logged but
    must not crash the batch run; the audit log is already on disk."""
    try:
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"(could not open {path} in file manager: {exc})")


def _iter_input_files():
    if not INPUT_DIR.exists():
        return
    for entry in sorted(INPUT_DIR.iterdir()):
        if not entry.is_file():
            continue
        if entry.name.startswith("."):
            continue
        if entry.name == AUDIT_LOG_NAME:
            continue
        yield entry


def _process_one(path: Path):
    """Run the full per-file pipeline. Return a dict of audit fields."""
    entry = {
        "filename": path.name,
        "status": "OK",
        "encoding": None,
        "sub": 0,
        "tenant": 0,
        "email": 0,
        "notes": [],
    }
    try:
        text, encoding, garbled = _read_with_fallback(path)
    except (OSError, UnicodeDecodeError) as exc:
        entry["status"] = "FAILED-READ"
        entry["notes"].append(f"could not decode after {', '.join(ENCODINGS)}: {exc}")
        return entry
    entry["encoding"] = encoding
    if garbled:
        entry["notes"].append(
            "WARNING: possible UTF-16 source decoded via latin-1 (high NUL-byte ratio)"
        )

    result = scrub(text)
    counts = {row["type"]: row["count"] for row in result["audit_log"]}
    entry["sub"] = counts["SUBSCRIPTION_ID"]
    entry["tenant"] = counts["TENANT_ID"]
    entry["email"] = counts["EMAIL_ADDRESS"]

    out_path = OUTPUT_DIR / path.name
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(result["sanitized_text"])
    except OSError as exc:
        entry["status"] = "FAILED-WRITE"
        entry["notes"].append(f"output write failed; source left in input/: {exc}")
        return entry

    archive_dest = _archive_target(path.name)
    try:
        shutil.move(str(path), str(archive_dest))
        if archive_dest.name != path.name:
            entry["notes"].append(f"archive collision resolved -> {archive_dest.name}")
    except OSError as exc:
        entry["status"] = "WARNING-ARCHIVE"
        entry["notes"].append(
            f"sanitized output saved but archive move failed; source still in input/: {exc}"
        )
    return entry


def _format_audit_log(entries):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S %z").strip() or time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    lines = [
        "ABRS PII SCRUBBER - BATCH AUDIT LOG",
        f"Generated: {timestamp}",
        f"Files processed: {len(entries)}",
        "",
    ]
    totals = {"sub": 0, "tenant": 0, "email": 0}
    for e in entries:
        lines.append(e["filename"])
        if e["encoding"]:
            lines.append(f"  encoding: {e['encoding']}")
        lines.append(f"  status: {e['status']}")
        lines.append(f"  SUBSCRIPTION_ID: {e['sub']} replaced")
        lines.append(f"  TENANT_ID: {e['tenant']} replaced")
        lines.append(f"  EMAIL_ADDRESS: {e['email']} replaced")
        for note in e["notes"]:
            lines.append(f"  note: {note}")
        lines.append("")
        if e["status"] in ("OK", "WARNING-ARCHIVE"):
            totals["sub"] += e["sub"]
            totals["tenant"] += e["tenant"]
            totals["email"] += e["email"]
    lines.append("TOTALS")
    lines.append(f"  SUBSCRIPTION_ID: {totals['sub']} replaced")
    lines.append(f"  TENANT_ID: {totals['tenant']} replaced")
    lines.append(f"  EMAIL_ADDRESS: {totals['email']} replaced")
    return "\n".join(lines) + "\n"


def run() -> int:
    for d in (INPUT_DIR, OUTPUT_DIR, ARCHIVE_DIR):
        d.mkdir(exist_ok=True)

    files = list(_iter_input_files())
    if not files:
        print("No files found in input/")
        return 0

    entries = [_process_one(p) for p in files]

    audit_path = OUTPUT_DIR / AUDIT_LOG_NAME
    audit_text = _format_audit_log(entries)
    with open(audit_path, "w", encoding="utf-8") as f:
        f.write(audit_text)
    _open_in_file_manager(OUTPUT_DIR)

    print(f"Processed {len(entries)} file(s).")
    print(f"Audit log: {audit_path}")
    for e in entries:
        print(
            f"  {e['filename']}: {e['status']} "
            f"(sub={e['sub']}, tenant={e['tenant']}, email={e['email']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
