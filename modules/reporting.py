import json
import os
import re
import sys
from datetime import datetime, timezone

OUTPUT_DIR = "output"
TOOL_NAME = "Honeypot Detector"
TOOL_VERSION = "1.0.0"

_COLOURS = {
    "red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
    "cyan": "\033[96m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
}


def _use_colour():
    """Colour only on a real terminal, and respect the NO_COLOR convention."""
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(text, colour):
    if not _use_colour():
        return str(text)
    return f"{_COLOURS[colour]}{text}{_COLOURS['reset']}"


def _score_colour(pct):
    if pct < 25:
        return "green"
    if pct < 50:
        return "yellow"
    return "red"


def _bar(pct, width=30):
    filled = int(round(width * pct / 100))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _table(headers, rows):
    """Plain-text table with auto column widths (no third-party libraries)."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt = "| " + " | ".join("{:<%d}" % w for w in widths) + " |"
    out = [line, fmt.format(*headers), line]
    out += [fmt.format(*[str(c) for c in row]) for row in rows]
    out.append(line)
    return "\n".join(out)


# ----------------------------------------------------------------- terminal --

def render_report(target, result, notes=None):
    """Build the human-readable report text (plain, no colour codes)."""
    lines = [
        f"{TOOL_NAME} v{TOOL_VERSION} - scan report",
        f"Target      : {target}",
        f"Generated   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Checks run  : {result.checks_run}  (triggered: {result.checks_triggered})",
        "",
        f"Honeypot likelihood : {result.likelihood_pct}%  {_bar(result.likelihood_pct)}",
        f"Verdict             : {result.verdict}",
        f"By category         : network {result.category_pct['network']}%, "
        f"host {result.category_pct['host']}%",
        "",
    ]
    if result.contributions:
        rows = [
            (c["check"], c["category"], f"+{c['points']}", c["reason"])
            for c in result.contributions
        ]
        lines.append("Why this score:")
        lines.append(_table(("Check", "Type", "Points", "Reason"), rows))
    else:
        lines.append("No honeypot indicators were triggered.")
    if notes:
        lines += ["", "Notes:"] + [f"- {n}" for n in notes]
    lines += ["", "Heuristic result only - not proof. Verify before acting on it."]
    return "\n".join(lines)


def print_report(target, result, notes=None):
    """Print the report with colour on the headline numbers."""
    text = render_report(target, result, notes)
    colour = _score_colour(result.likelihood_pct)
    for line in text.splitlines():
        if line.startswith(("Honeypot likelihood", "Verdict")):
            line = paint(line, colour)
        elif line.startswith(f"{TOOL_NAME} v"):
            line = paint(line, "bold")
        print(line)


# --------------------------------------------------------------- save files --

def _safe_name(target):
    """Turn a target into a filename-safe string (blocks path tricks like ../)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(target)).strip("._") or "target"


def save_report(target, result, findings, output_dir=OUTPUT_DIR, notes=None):
    """Write timestamped JSON + TXT reports. Returns (json_path, txt_path)."""
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = os.path.join(output_dir, f"honeypot_scan_{_safe_name(target)}_{stamp}")

    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "label": "AUTHORISED SECURITY TEST OUTPUT - handle as confidential",
        "target": str(target),
        "generated_utc": stamp,
        "result": result.to_dict(),
        "notes": list(notes or []),
        # only structured, non-sensitive indicator data - never raw file contents
        "findings": [
            {k: v for k, v in vars(f).items()} for f in findings
        ],
    }
    json_path, txt_path = base + ".json", base + ".txt"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("# AUTHORISED SECURITY TEST OUTPUT - handle as confidential\n\n")
        fh.write(render_report(target, result, notes) + "\n")
    return json_path, txt_path


# ----------------------------------------------------------------- dry-run --

def print_dry_run(target, planned_checks, ports=None):
    """Show what WOULD be checked. Sends nothing and opens no sockets.

    planned_checks: iterable of (module_name, check_name, description)
    """
    print(paint(f"{TOOL_NAME} - DRY RUN", "bold"))
    print(f"Target : {target}")
    if ports:
        print(f"Ports  : {', '.join(str(p) for p in ports)}")
    print()
    rows = [(m, c, d) for m, c, d in planned_checks]
    print(_table(("Module", "Check", "What it would do"), rows))
    print()
    print(paint("DRY RUN: no packets were sent and no checks were executed.", "cyan"))
