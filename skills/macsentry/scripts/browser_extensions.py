"""Read Chrome and Firefox extension metadata without running extensions."""

import configparser
import json
from pathlib import Path


def load_json(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def chrome_name(manifest, extension_path):
    name = manifest.get("name")
    if not isinstance(name, str) or not name.startswith("__MSG_") or not name.endswith("__"):
        return name
    locale = manifest.get("default_locale")
    if not locale or not extension_path:
        return name
    try:
        messages = load_json(extension_path / "_locales" / locale / "messages.json")
        key = name[6:-2].lower()
        for item, value in messages.items():
            if item.lower() == key and isinstance(value, dict):
                return value.get("message", name)
    except (OSError, ValueError, TypeError):
        pass
    return name


def chrome(root):
    result = {"profiles": [], "errors": []}
    if not root.exists():
        result["status"] = "not found"
        return result
    try:
        profiles = sorted(p for p in root.iterdir() if p.is_dir() and
                          (p.name == "Default" or p.name.startswith("Profile ")))
    except OSError as error:
        result["errors"].append(str(error))
        return result
    for profile in profiles:
        record = {"profile": str(profile), "extensions": [], "errors": []}
        result["profiles"].append(record)
        found = False
        entries = {}
        for filename in ("Preferences", "Secure Preferences"):
            path = profile / filename
            if not path.exists():
                continue
            found = True
            try:
                data = load_json(path)
                settings = data.get("extensions", {}).get("settings", {})
                if not isinstance(settings, dict):
                    raise ValueError("extension settings are not a dictionary")
                entries.update(settings)
            except (OSError, ValueError, AttributeError, TypeError) as error:
                record["errors"].append(f"{path}: {error}")
        if not found:
            record["errors"].append("No Chrome preferences found")
        for identifier, entry in sorted(entries.items()):
            if not isinstance(entry, dict):
                record["errors"].append(f"Invalid extension entry: {identifier}")
                continue
            manifest = entry.get("manifest") or {}
            if not isinstance(manifest, dict):
                record["errors"].append(f"Invalid extension manifest: {identifier}")
                continue
            install_path = entry.get("path")
            if isinstance(install_path, str):
                extension_path = Path(install_path)
                if not extension_path.is_absolute():
                    extension_path = profile / "Extensions" / extension_path
            else:
                extension_path = None
            record["extensions"].append({
                "id": identifier,
                "name": chrome_name(manifest, extension_path),
                "version": manifest.get("version"),
                "path": str(extension_path) if extension_path else None,
                "from_webstore": entry.get("from_webstore"),
                "location": entry.get("location"),
                "disable_reasons": entry.get("disable_reasons"),
                "permissions": manifest.get("permissions"),
                "host_permissions": manifest.get("host_permissions"),
                "active_permissions": entry.get("active_permissions"),
            })
    if not profiles:
        result["errors"].append("No standard Chrome profiles found")
    return result


def firefox(root):
    result = {"profiles": [], "errors": []}
    registry = root / "profiles.ini"
    if not registry.exists():
        result["status"] = "profiles.ini not found"
        return result
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with registry.open(encoding="utf-8") as stream:
            parser.read_file(stream)
        profiles = []
        for section in parser.sections():
            if not section.startswith("Profile"):
                continue
            name = parser.get(section, "Path")
            relative = parser.get(section, "IsRelative")
            if relative not in ("0", "1"):
                raise ValueError(f"Invalid IsRelative in {section}")
            profiles.append(root / name if relative == "1" else Path(name))
    except (OSError, ValueError, configparser.Error) as error:
        result["errors"].append(f"{registry}: {error}")
        return result
    if not profiles:
        result["errors"].append("No Firefox profiles registered")
    for profile in sorted(set(profiles)):
        record = {"profile": str(profile), "extensions": [], "errors": []}
        result["profiles"].append(record)
        path = profile / "extensions.json"
        try:
            data = load_json(path)
            addons = data.get("addons")
            if not isinstance(addons, list):
                raise ValueError("Missing addon inventory")
            for addon in addons:
                if not isinstance(addon, dict):
                    record["errors"].append("Invalid addon entry")
                    continue
                if addon.get("type") != "extension":
                    continue
                locale = addon.get("defaultLocale") or {}
                if not isinstance(locale, dict):
                    locale = {}
                record["extensions"].append({
                    "id": addon.get("id"), "name": locale.get("name"),
                    "version": addon.get("version"), "path": addon.get("path"),
                    "active": addon.get("active"), "user_disabled": addon.get("userDisabled"),
                    "app_disabled": addon.get("appDisabled"),
                    "blocklist_state": addon.get("blocklistState"),
                    "signed_state": addon.get("signedState"),
                    "permissions": addon.get("userPermissions"),
                    "requested_permissions": addon.get("requestedPermissions"),
                })
        except (OSError, ValueError, AttributeError, TypeError) as error:
            record["errors"].append(f"{path}: {error}")
    return result


def collect():
    support = Path.home() / "Library/Application Support"
    return {"chrome": chrome(support / "Google/Chrome"),
            "firefox": firefox(support / "Firefox")}
