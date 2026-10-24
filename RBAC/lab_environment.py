#!/usr/bin/env python3
"""Create and remove a disposable local RBAC-audit test environment.

This does not create cloud resources. It creates a small Linux-like filesystem
tree that can be passed to rbac_auditor.py with --root.
"""

from __future__ import annotations

import argparse
import shutil
import tempfile
from pathlib import Path


MARKER = ".rbac-auditor-lab"


def write_file(path: Path, content: str, mode: int = 0o644) -> None:
    """Create a fixture file and apply Linux-style permissions when supported."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(mode)
    except OSError:
        # Windows may not support all Unix permission bits; the auditor still
        # works for account, group, and sudo-rule checks in the fixture.
        pass


def create_lab(destination: Path | None = None) -> Path:
    """Create a disposable fixture containing several intentional findings."""
    if destination is None:
        destination = Path(tempfile.mkdtemp(prefix="rbac-auditor-lab-"))
    else:
        destination = destination.resolve()
        if destination.exists() and any(destination.iterdir()):
            raise FileExistsError(f"Refusing to use a non-empty directory: {destination}")
        destination.mkdir(parents=True, exist_ok=True)

    # Finding 1: an unexpected account with UID 0.
    write_file(
        destination / "etc" / "passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "ccdc:x:1000:1000:CCDC:/home/ccdc:/bin/bash\n"
        "backupadmin:x:0:0:Backup:/home/backupadmin:/bin/bash\n",
    )

    # Finding 2: an unexpected user in a group that grants administrative access.
    write_file(
        destination / "etc" / "group",
        "sudo:x:27:ccdc\n"
        "docker:x:998:ccdc\n"
        "users:x:100:ccdc\n",
    )

    # Finding 3: an unrestricted sudo rule.
    write_file(
        destination / "etc" / "sudoers",
        "root ALL=(ALL:ALL) ALL\n"
        "ccdc ALL=(ALL) NOPASSWD: ALL\n",
        0o644,
    )

    # Finding 4: an overly permissive cloud credential file.
    write_file(
        destination / "home" / "ccdc" / ".aws" / "credentials",
        "[default]\naws_access_key_id = LAB_NOT_A_REAL_KEY\n"
        "aws_secret_access_key = LAB_NOT_A_REAL_SECRET\n",
        0o644,
    )

    # Finding 5: a private key with group/other access.
    write_file(
        destination / "home" / "ccdc" / "lab-access.pem",
        "-----BEGIN PRIVATE KEY-----\nLAB_ONLY\n-----END PRIVATE KEY-----\n",
        0o644,
    )

    write_file(destination / "etc" / "shadow", "root:*:20000:0:99999:7:::\n", 0o644)
    write_file(destination / MARKER, "This directory is safe to delete with lab_environment.py.\n")
    return destination


def delete_lab(destination: Path) -> None:
    """Delete only a directory containing this tool's safety marker."""
    destination = destination.resolve()
    marker = destination / MARKER
    if not destination.is_dir() or not marker.is_file():
        raise ValueError(
            f"Refusing to delete {destination}; expected a marked RBAC lab directory."
        )
    shutil.rmtree(destination)


def main() -> int:
    """Parse commands for creating or deleting the disposable lab fixture."""
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)

    create = actions.add_parser("create", help="Create a vulnerable local fixture")
    create.add_argument("--path", type=Path, help="Optional empty directory to use")

    remove = actions.add_parser("delete", help="Delete a marked lab fixture")
    remove.add_argument("path", type=Path)

    args = parser.parse_args()
    if args.action == "create":
        path = create_lab(args.path)
        # Print only the path so shell command substitution works cleanly.
        print(path)
        return 0

    delete_lab(args.path)
    print(f"Deleted lab: {args.path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
