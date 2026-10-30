#!/usr/bin/env python3
"""Pin release source files before committing/tagging; never build or publish."""
import argparse
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(
    r"^([ \t]*image:[ \t]*\$\{REDELKREPO\}/redelk-([a-z]+):)([^ \t\r\n#]+)([ \t]*)$",
    re.MULTILINE,
)
PROFILES = {
    "limited": {"base", "elasticsearch", "logstash", "kibana"},
    "full": {"base", "elasticsearch", "logstash", "kibana", "jupyter"},
}


def pin_release(root, tag, check=False):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag) or tag in {
        "latest", "master", "main", "develop", "dev"
    }:
        raise ValueError("Use an explicit release tag valid as a Docker tag, not a rolling branch tag.")

    updates = {root / "VERSION": tag + "\n"}
    for profile, expected in PROFILES.items():
        path = root / "elkserver" / f"redelk-{profile}.yml"
        content = path.read_text()
        matches = list(IMAGE.finditer(content))
        if len(matches) != len(expected) or {m[2] for m in matches} != expected:
            raise ValueError(f"{path}: expected exactly the release's own image set")
        updates[path] = IMAGE.sub(lambda m: m[1] + tag + m[4], content)

    environment = root / "elkserver/.env.tmpl"
    updates[environment], count = re.subn(
        r"^REDELKVERSION=[^\r\n]*$", f"REDELKVERSION={tag}",
        environment.read_text(), flags=re.MULTILINE,
    )
    if count != 1:
        raise ValueError("Expected exactly one REDELKVERSION in elkserver/.env.tmpl")

    # Validate every input before writing any source file.
    mismatches = [path for path, content in updates.items() if path.read_text() != content]
    if check and mismatches:
        raise ValueError("Release tag does not match source files: " + ", ".join(str(p) for p in mismatches))
    if not check:
        for path in mismatches:
            path.write_text(updates[path])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="Exact GitHub release tag, including any v prefix")
    parser.add_argument("--check", action="store_true", help="Validate without writing files")
    args = parser.parse_args()
    try:
        pin_release(ROOT, args.tag, args.check)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
