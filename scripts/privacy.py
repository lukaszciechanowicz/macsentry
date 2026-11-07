#!/usr/bin/env python3
"""Apply explicitly configured telemetry preferences for the current user."""
import argparse
import configparser
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

CONFIG = Path(__file__).resolve().parent.parent / "privacy.json"
KEY = "telemetry.telemetryLevel"


def load_config(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate configuration key: {key}")
            result[key] = value
        return result

    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    required = {"homebrew_analytics", "vscode_telemetry", "firefox_telemetry", "chrome_telemetry"}
    if not isinstance(data, dict) or data.keys() != required:
        raise ValueError(f"config must contain exactly: {', '.join(sorted(required))}")
    if any(type(value) is not bool for value in data.values()):
        raise ValueError("config values must be JSON booleans")
    return data


def mask_comments(text):
    """Replace JSONC comments with whitespace, keeping character offsets intact."""
    chars = list(text)
    i = 0
    while i < len(text):
        if text[i] == '"':
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end == -1 else end
            chars[i:end] = " " * (end - i)
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise ValueError("unterminated comment in VS Code settings")
            end += 2
            for j in range(i, end):
                if text[j] not in "\r\n":
                    chars[j] = " "
            i = end
        else:
            i += 1
    # Mask trailing commas without modifying string contents.
    masked = "".join(chars)
    i = 0
    while i < len(masked):
        if masked[i] == '"':
            i += 1
            while i < len(masked):
                if masked[i] == "\\":
                    i += 2
                elif masked[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            continue
        if masked[i] == ",":
            j = i + 1
            while j < len(masked) and masked[j].isspace():
                j += 1
            if j < len(masked) and masked[j] in "}]":
                chars[i] = " "
        i += 1
    return "".join(chars)


def vscode_content(text, enabled):
    masked = mask_comments(text)
    decoder = json.JSONDecoder()
    # Validate the entire JSONC document before changing it.
    parsed = json.loads(masked)
    if not isinstance(parsed, dict):
        raise ValueError("VS Code settings must be an object")

    def skip(pos):
        while pos < len(masked) and masked[pos].isspace():
            pos += 1
        return pos

    opening = skip(0)
    pos = skip(opening + 1)
    matches = []
    last_end = None
    while masked[pos] != "}":
        key, pos = decoder.raw_decode(masked, pos)
        pos = skip(pos)
        if masked[pos] != ":":
            raise ValueError("invalid VS Code settings")
        start = skip(pos + 1)
        _, end = decoder.raw_decode(masked, start)
        if key == KEY:
            matches.append((start, end))
        last_end = end
        pos = skip(end)
        if masked[pos] == ",":
            pos = skip(pos + 1)
    if len(matches) > 1:
        raise ValueError(f"duplicate {KEY} in VS Code settings")
    value = json.dumps("all" if enabled else "off")
    if matches:
        start, end = matches[0]
        return text[:start] + value + text[end:]
    # Insert after the last value, before any trailing comma or comment.
    if last_end is None:
        return text[:opening + 1] + f'\n    "{KEY}": {value}\n' + text[opening + 1:]
    return text[:last_end] + f',\n    "{KEY}": {value}' + text[last_end:]


def write_vscode(enabled):
    path = Path.home() / "Library/Application Support/Code/User/settings.json"
    if not path.parent.is_dir():
        print("VS Code user directory not found; skipping")
        return
    original = path.read_text(encoding="utf-8") if path.exists() else "{}\n"
    updated = vscode_content(original, enabled)
    if updated == original:
        print("VS Code telemetry: unchanged")
        return
    # Preserve the original permissions and replace atomically in the same directory.
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, temp = tempfile.mkstemp(prefix=".macsentry-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(updated)
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print(f"VS Code telemetry: {'on' if enabled else 'off'}")


FIREFOX_BEGIN = "// BEGIN MacSentry telemetry"
FIREFOX_END = "// END MacSentry telemetry"
FIREFOX_PREFS = (
    "datareporting.healthreport.uploadEnabled",
    "datareporting.policy.dataSubmissionEnabled",
    "toolkit.telemetry.archive.enabled",
    "datareporting.usage.uploadEnabled",
)


def firefox_updates(enabled):
    root = Path.home() / "Library/Application Support/Firefox"
    registry = root / "profiles.ini"
    if not registry.exists():
        return []
    parser = configparser.ConfigParser(interpolation=None)
    with registry.open(encoding="utf-8") as stream:
        parser.read_file(stream)
    profiles = set()
    for section in parser.sections():
        if not section.startswith("Profile"):
            continue
        name = parser.get(section, "Path")
        relative = parser.get(section, "IsRelative")
        if relative not in ("0", "1"):
            raise ValueError(f"invalid Firefox profile path in {section}")
        profile = root / name if relative == "1" else Path(name)
        if not profile.is_dir():
            raise ValueError(f"Firefox profile directory missing: {profile}")
        profiles.add(profile / "user.js")
    updates = []
    for path in sorted(profiles):
        if path.is_symlink():
            raise ValueError(f"refusing to replace symlink: {path}")
        original = path.read_text(encoding="utf-8") if path.exists() else ""
        if original.count(FIREFOX_BEGIN) != original.count(FIREFOX_END) or original.count(FIREFOX_BEGIN) > 1:
            raise ValueError(f"invalid MacSentry block in {path}")
        if FIREFOX_BEGIN in original:
            start = original.index(FIREFOX_BEGIN)
            end = original.index(FIREFOX_END)
            if end < start:
                raise ValueError(f"invalid MacSentry block in {path}")
            original = original[:start] + original[end + len(FIREFOX_END):].lstrip("\\r\\n")
        lines = [FIREFOX_BEGIN]
        lines += [f'user_pref(\"{pref}\", {str(enabled).lower()});' for pref in FIREFOX_PREFS]
        lines.append(FIREFOX_END)
        updated = original + ("" if not original or original.endswith("\\n") else "\\n") + "\\n".join(lines) + "\\n"
        updates.append((path, updated))
    return updates


def write_firefox(updates):
    if not updates:
        print("Firefox profiles not found; skipping")
        return
    for path, content in updates:
        if path.exists() and path.read_text(encoding="utf-8") == content:
            continue
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
        fd, temp = tempfile.mkstemp(prefix=".macsentry-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
            os.chmod(temp, mode)
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    print(f"Firefox telemetry: preferences written for {len(updates)} profile(s); restart Firefox")


def write_chrome(enabled):
    if not (Path("/Applications/Google Chrome.app").exists() or
            (Path.home() / "Applications/Google Chrome.app").exists()):
        print("Google Chrome not found; skipping")
        return
    subprocess.run(["/usr/bin/defaults", "write", "com.google.Chrome",
                    "MetricsReportingEnabled", "-bool", str(enabled).lower()], check=True)
    print("Chrome telemetry: recommended policy written; restart and check chrome://policy")


def apply(path):
    config = load_config(path)
    # Parse VS Code settings before changing either control.
    settings = Path.home() / "Library/Application Support/Code/User/settings.json"
    if settings.exists():
        vscode_content(settings.read_text(encoding="utf-8"), config["vscode_telemetry"])
    firefox = firefox_updates(config["firefox_telemetry"])
    brew = shutil.which("brew")
    if brew:
        subprocess.run([brew, "analytics", "on" if config["homebrew_analytics"] else "off"], check=True)
    else:
        print("Homebrew not found; skipping")
    write_vscode(config["vscode_telemetry"])
    write_firefox(firefox)
    write_chrome(config["chrome_telemetry"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG, help="JSON config path")
    parser.add_argument("--watch", action="store_true", help="reapply after config changes until interrupted")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("macOS is required")
    previous = None
    while True:
        try:
            current = args.config.read_bytes()
            if current != previous:
                apply(args.config)
                previous = current
        except (OSError, ValueError, configparser.Error, subprocess.CalledProcessError) as exc:
            print(f"privacy: {exc}", file=sys.stderr, flush=True)
            if not args.watch:
                return 1
        if not args.watch:
            return 0
        time.sleep(2)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
