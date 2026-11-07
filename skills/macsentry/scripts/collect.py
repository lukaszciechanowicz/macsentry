#!/usr/bin/env python3
"""Collect local evidence; application advisory matching belongs to the skill."""

import argparse
import datetime
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

import browser_extensions
import extension_advisories

PROGRESS = False


def progress(section, message):
    if PROGRESS:
        print(json.dumps({"section": section, "message": str(message)}), file=sys.stderr, flush=True)


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
    progress("Stage", "Discovering installed applications (system_profiler may take a while)...")
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
        progress("Application", f'{app["name"] or "unknown"} — {app.get("version") or app.get("reported_version") or "version unknown"}')
    record["data"] = apps
    return record


def receipts():
    progress("Stage", "Reading package receipts...")
    record = command(["/usr/sbin/pkgutil", "--pkgs-plist"], plistlib.loads)
    identifiers = record.get("data")
    if not isinstance(identifiers, list):
        record["error"] = record.get("error", "Missing package receipt list")
        return record
    details = []
    for identifier in identifiers:
        progress("Package receipt", identifier)
        details.append(command(["/usr/sbin/pkgutil", "--pkg-info-plist", identifier], plistlib.loads))
    record["data"] = details
    return record


def main():
    global PROGRESS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--progress", action="store_true", help="emit JSON progress events to stderr")
    PROGRESS = parser.parse_args().progress
    if sys.platform != "darwin":
        print("MacSentry requires macOS.", file=sys.stderr)
        return 1
    progress("Stage", "Starting read-only local inventory...")
    report = {
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "macos": command(["/usr/bin/sw_vers"], bytes.decode),
        "applications": applications(),
        "package_receipts": receipts(),
    }
    progress("Stage", "Reading Chrome and Firefox extension profiles...")
    report["browser_extensions"] = browser_extensions.collect(progress)
    progress("Stage", "Searching NVD for extension advisories (names or Chrome IDs are sent to NVD)...")
    report["extension_advisories"] = extension_advisories.assess(report["browser_extensions"], progress)
    brew = shutil.which("brew")
    if brew:
        progress("Stage", "Reading Homebrew inventory...")
        report["homebrew_inventory"] = command(
            [brew, "info", "--json=v2", "--installed"])
        inventory = report["homebrew_inventory"].get("data")
        if isinstance(inventory, dict):
            for kind, label in (("formulae", "formula"), ("casks", "cask")):
                for item in inventory.get(kind, []):
                    progress("Homebrew " + label, item.get("full_name") or item.get("token") or item.get("name") or "unknown")
        progress("Stage", "Checking Homebrew advisories (this may take several minutes)...")
        report["homebrew_vulnerabilities"] = command(
            [brew, "vulns", "--json"], timeout=600)
        vulnerabilities = report["homebrew_vulnerabilities"].get("data")
        if isinstance(vulnerabilities, dict):
            for finding in vulnerabilities.get("findings", []):
                for vulnerability in finding.get("vulnerabilities", []):
                    progress("Homebrew finding", f'{finding.get("formula", "unknown")} — {vulnerability.get("id", "unknown")}')
    else:
        report["homebrew_inventory"] = {"error": "Homebrew not found on PATH"}
        report["homebrew_vulnerabilities"] = {"error": "Homebrew not found on PATH"}
    print(json.dumps(report, indent=2, default=str))
    # Success means evidence was emitted, not that every command succeeded or
    # that software is safe. Each section retains its own status and errors.
    return 0


if __name__ == "__main__":
    sys.exit(main())
