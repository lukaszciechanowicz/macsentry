#!/usr/bin/env python3
"""Display scan progress and save a timestamped local JSON inventory."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import unicodedata

import html_report


def safe(value):
    """Do not let untrusted inventory names inject terminal controls."""
    return "".join(" " if unicodedata.category(char).startswith("C") else char
                   for char in str(value))


def show_progress(line):
    try:
        event = json.loads(line)
        section, message = safe(event["section"]), safe(event["message"])
    except (ValueError, KeyError, TypeError):
        print(safe(line), file=sys.stderr, flush=True)
        return
    if section == "Stage":
        print(f"\n{message}", flush=True)
    else:
        print(f"  {section}: {message}", flush=True)


def show_summary(data, report, html_path):
    print("\nCollection complete")
    for key, label in (("macos", "macOS"), ("applications", "Applications"),
                       ("package_receipts", "Package receipts"),
                       ("homebrew_inventory", "Homebrew inventory"),
                       ("homebrew_vulnerabilities", "Homebrew vulnerabilities")):
        record = data.get(key, {})
        if record.get("error"):
            print(f"  {label}: {safe(record['error'])}")
        if record.get("stderr"):
            print(f"  {label} stderr: {safe(record['stderr'])}")
        if record.get("exit_code") not in (None, 0):
            print(f"  {label}: command exited {record['exit_code']} (inspect report)")
    apps = data.get("applications", {}).get("data", [])
    receipts = data.get("package_receipts", {}).get("data", [])
    if isinstance(apps, list):
        print(f"  Applications: {len(apps)} records; {sum(bool(x.get('error')) for x in apps)} metadata errors")
    if isinstance(receipts, list):
        print(f"  Package receipts: {len(receipts)} records; "
              f"{sum(bool(x.get('error') or x.get('exit_code') != 0) for x in receipts)} errors")
    for browser, result in data.get("browser_extensions", {}).items():
        profiles = result.get("profiles", [])
        print(f"  {safe(browser.title())}: {len(profiles)} profiles, "
              f"{sum(len(p.get('extensions', [])) for p in profiles)} extension records")
        for error in result.get("errors", []):
            print(f"    Coverage gap: {safe(error)}")
        if result.get("status"):
            print(f"    Coverage gap: {safe(result['status'])}")
        for profile in profiles:
            for error in profile.get("errors", []):
                print(f"    Coverage gap: {safe(error)}")
    brew = data.get("homebrew_vulnerabilities", {}).get("data")
    if isinstance(brew, dict):
        count = sum(len(f.get("vulnerabilities", [])) for f in brew.get("findings", []))
        print(f"  Homebrew: {count} open advisory records; coverage "
              f"{'complete' if brew.get('complete') is True else 'incomplete or unknown'}")
        skipped = brew.get("skipped_formulae", [])
        if skipped:
            print(f"    Skipped formulae: {', '.join(safe(x) for x in skipped)}")
    else:
        print("  Homebrew advisory coverage: not assessed")
    checks = data.get("extension_advisories", {}).get("results", [])
    print(f"  Extension advisory searches: {sum('total_results' in x for x in checks)} records searched; "
          f"{sum(x.get('status') == 'not assessed' for x in checks)} not assessed")
    print(f"  JSON report: {safe(report)}")
    print(f"  HTML report: {safe(html_path)}")
    print("  Extension keyword hits need identity and version verification; application advisories require the agent skill.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path.home() / "Library/Logs/MacSentry",
        help="directory for private scan reports (default: ~/Library/Logs/MacSentry)",
    )
    parser.add_argument("--no-interactive", action="store_true",
                        help="print the complete JSON report instead of live progress")
    args = parser.parse_args()
    collector = Path(__file__).resolve().parent.parent / "skills/macsentry/scripts/collect.py"
    report = None
    html_path = None
    html_created = False
    created = False
    complete = False
    try:
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%fZ")
        report = args.output_dir / f"scan-{timestamp}.json"
        fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        command = [sys.executable, str(collector)]
        if not args.no_interactive:
            command.append("--progress")
            print("MacSentry — local security inventory", flush=True)
        with os.fdopen(fd, "wb") as output:
            with subprocess.Popen(command, stdout=output, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8", errors="replace") as process:
                for line in process.stderr:
                    if args.no_interactive:
                        print(line, end="", file=sys.stderr, flush=True)
                    else:
                        show_progress(line.rstrip("\n"))
                status = process.wait()
        if status:
            print(f"Scan failed with exit code {status}; no report saved.", file=sys.stderr)
            return status
        with report.open(encoding="utf-8") as stream:
            data = json.load(stream)
        html_path = report.with_suffix(".html")
        html_fd = os.open(html_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        html_created = True
        with os.fdopen(html_fd, "w", encoding="utf-8") as stream:
            stream.write(html_report.render(data))
        complete = True
        if args.no_interactive:
            print(f"JSON report: {report}\nHTML report: {html_path}", file=sys.stderr)
            with report.open("rb") as stream:
                while chunk := stream.read(65536):
                    sys.stdout.buffer.write(chunk)
        else:
            show_summary(data, report, html_path)
        return 0
    except (OSError, ValueError) as error:
        print(f"scan: {error}", file=sys.stderr)
        return 1
    finally:
        if created and not complete:
            report.unlink(missing_ok=True)
        if html_created and not complete:
            html_path.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
