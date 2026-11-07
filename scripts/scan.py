#!/usr/bin/env python3
"""Display the local inventory and save a timestamped JSON report."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path.home() / "Library/Logs/MacSentry",
        help="directory for private scan reports (default: ~/Library/Logs/MacSentry)",
    )
    args = parser.parse_args()
    collector = Path(__file__).resolve().parent.parent / "skills/macsentry/scripts/collect.py"
    try:
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%fZ")
        report = args.output_dir / f"scan-{timestamp}.json"
        result = subprocess.run([sys.executable, str(collector)], capture_output=True)
        if result.stderr:
            sys.stderr.buffer.write(result.stderr)
        if result.returncode:
            print(f"Scan failed with exit code {result.returncode}; no report saved.", file=sys.stderr)
            return result.returncode
        fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(result.stdout)
        print(f"Scan report: {report}", file=sys.stderr)
        sys.stdout.buffer.write(result.stdout)
        return 0
    except OSError as error:
        print(f"scan: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
