#!/usr/bin/env python3
"""
Auto-generate per-game registry.json from .cpp emplace_back declarations,
then update main registry.json as a slim game index.

Usage:
    python tools/generate_registry.py
"""
import json
import os
import re
import glob

DLLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_REGISTRY = os.path.join(DLLS_DIR, "registry.json")

VK_TABLE = {
    "VK_F1": 112,  "VK_F2": 113,  "VK_F3": 114,  "VK_F4": 115,
    "VK_F5": 116,  "VK_F6": 117,  "VK_F7": 118,  "VK_F8": 119,
    "VK_F9": 120,  "VK_F10": 121, "VK_F11": 122, "VK_F12": 123,
    "VK_NUMPAD0": 96,  "VK_NUMPAD1": 97,  "VK_NUMPAD2": 98,
    "VK_NUMPAD3": 99,  "VK_NUMPAD4": 100, "VK_NUMPAD5": 101,
    "VK_NUMPAD6": 102, "VK_NUMPAD7": 103, "VK_NUMPAD8": 104,
    "VK_NUMPAD9": 105,
    "VK_SPACE": 32, "VK_RETURN": 13, "VK_TAB": 9,
    "VK_BACK": 8,   "VK_ESCAPE": 27, "VK_INSERT": 45, "VK_DELETE": 46,
    "VK_HOME": 36,  "VK_END": 35,   "VK_PRIOR": 33, "VK_NEXT": 34,
    "VK_LEFT": 37,  "VK_UP": 38,    "VK_RIGHT": 39, "VK_DOWN": 40,
}

FEATURE_RE = re.compile(
    r'm_features\.emplace_back\(\s*'
    r'"([^"]+)"\s*,\s*'   # id
    r'"([^"]+)"\s*,\s*'   # name
    r'"([^"]+)"\s*,\s*'   # description
    r'(\d+)\s*,\s*'       # is_toggle (0/1)
    r'([^)]+?)\s*\)'      # vk
)


def resolve_vk(raw: str) -> int:
    s = raw.strip()
    if s in VK_TABLE:
        return VK_TABLE[s]
    try:
        return int(s)
    except ValueError:
        return 0


def parse_features(cpp_path: str) -> list:
    with open(cpp_path, encoding="utf-8") as f:
        src = f.read()
    features = []
    for m in FEATURE_RE.finditer(src):
        fid, name, desc, toggle, vk_raw = m.groups()
        features.append({
            "id": fid,
            "name": name,
            "description": desc,
            "is_toggle": toggle == "1",
            "default_vk": resolve_vk(vk_raw),
        })
    return features


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    index = []

    for game_dir in sorted(os.listdir(DLLS_DIR)):
        if game_dir.startswith("."):
            continue
        full = os.path.join(DLLS_DIR, game_dir)
        if not os.path.isdir(full):
            continue

        versions_path = os.path.join(full, "versions.json")
        if not os.path.exists(versions_path):
            continue

        cpp_files = glob.glob(os.path.join(full, "src", "*.cpp"))
        if not cpp_files:
            continue

        ver = load_json(versions_path)
        features = []
        for cpp in sorted(cpp_files):
            features.extend(parse_features(cpp))

        game_id      = ver["game_id"]
        game_name    = ver["game_name"]
        trainer_ver  = ver["trainer_version"]
        game_ver     = ver.get("game_version", "")
        vc           = ver["version_constraint"]
        release_tag  = f"{game_name}-{game_ver}-{trainer_ver}"

        per_game_path = os.path.join(full, "registry.json")

        # Preserve existing sha256 from the per-game registry.json if present;
        # it will be filled in properly by the CI pipeline after a build.
        # Reject placeholder values like "null", "", or anything not a 64-char hex string.
        sha256 = ""
        if os.path.exists(per_game_path):
            existing = load_json(per_game_path)
            candidate = existing.get("sha256", "") or ""
            if (
                len(candidate) == 64
                and all(c in "0123456789abcdefABCDEF" for c in candidate)
            ):
                sha256 = candidate.lower()

        entry = {
            "game_id":            game_id,
            "game_name":          game_name,
            "trainer_version":    trainer_ver,
            "release_tag":        release_tag,
            "repo":               "funneco/UsMod-dlls",
            "dll_filename":       "trainer.dll",
            "sha256":             sha256,
            "version_constraint": vc,
            "features":           features,
        }
        save_json(per_game_path, entry)

        toggles = sum(1 for f in features if f["is_toggle"])
        print(f"  {game_name}: {len(features)} features ({toggles} toggles)")

        index.append({
            "game_id":   game_id,
            "game_name": game_name,
            "registry":  f"{game_name}/registry.json",
        })

    save_json(MAIN_REGISTRY, {"version": "1.0", "trainers": index})
    print(f"\nWrote main registry.json — {len(index)} trainers")


if __name__ == "__main__":
    main()
