#!/usr/bin/env python3
"""Collect local evidence; application advisory matching belongs to the skill."""

import datetime
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

import browser_extensions


def command(args, decoder=json.loads, timeout=120):
    try:
        result = subprocess.run(
            args, capture_output=True, timeout=timeout,
            env={**os.environ, "HOMEBREW_NO_AUTO_UPDATE": "1",
                 "HOMEBREW_NO_ANALYTICS": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": args, "error": str(error)}
    record = {"command": args, "exit_code": result.returncode,
              "stderr": result.stderr.decode("utf-8", errors="replace")}
    try:
        record["data"] = decoder(result.stdout)
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        record["error"] = str(error)
        record["stdout"] = result.stdout.decode("utf-8", errors="replace")
    return record


def applications():
    record = command(["/usr/sbin/system_profiler", "SPApplicationsDataType", "-json"])
    data = record.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("SPApplicationsDataType"), list):
        record["error"] = record.get("error", "Missing application inventory")
        return record
    apps = []
    for entry in data["SPApplicationsDataType"]:
        path = entry.get("path")
        app = {"name": entry.get("_name"), "path": path,
               "reported_version": entry.get("version"),
               "reported_source": entry.get("obtained_from")}
        try:
            if not path:
                raise ValueError("Application path missing")
            with (Path(path) / "Contents/Info.plist").open("rb") as stream:
                info = plistlib.load(stream)
            if not isinstance(info, dict):
                raise ValueError("Bundle metadata is not a dictionary")
            app.update(bundle_id=info.get("CFBundleIdentifier"),
                       version=info.get("CFBundleShortVersionString"),
                       build=info.get("CFBundleVersion"))
            app["app_store_receipt_present"] = (
                Path(path) / "Contents/_MASReceipt/receipt"
            ).is_file()
        except (OSError, ValueError, plistlib.InvalidFileException) as error:
            app["error"] = str(error)
        apps.append(app)
    record["data"] = apps
    return record


def receipts():
    record = command(["/usr/sbin/pkgutil", "--pkgs-plist"], plistlib.loads)
    identifiers = record.get("data")
    if not isinstance(identifiers, list):
        record["error"] = record.get("error", "Missing package receipt list")
        return record
    record["data"] = [command(
        ["/usr/sbin/pkgutil", "--pkg-info-plist", identifier], plistlib.loads,
    ) for identifier in identifiers]
    return record


def main():
    if sys.platform != "darwin":
        print("MacSentry requires macOS.", file=sys.stderr)
        return 1
    report = {
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "macos": command(["/usr/bin/sw_vers"], bytes.decode),
        "applications": applications(),
        "package_receipts": receipts(),
        "browser_extensions": browser_extensions.collect(),
    }
    brew = shutil.which("brew")
    if brew:
        report["homebrew_inventory"] = command(
            [brew, "info", "--json=v2", "--installed"])
        report["homebrew_vulnerabilities"] = command(
            [brew, "vulns", "--json"], timeout=600)
    else:
        report["homebrew_inventory"] = {"error": "Homebrew not found on PATH"}
        report["homebrew_vulnerabilities"] = {"error": "Homebrew not found on PATH"}
    print(json.dumps(report, indent=2, default=str))
    # Success means evidence was emitted, not that every command succeeded or
    # that software is safe. Each section retains its own status and errors.
    return 0


if __name__ == "__main__":
    sys.exit(main())
