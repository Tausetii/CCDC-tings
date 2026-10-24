#!/usr/bin/env python3
"""Read-only Linux and cloud-credential authorization auditor."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DEFAULT_PRIVILEGED_GROUPS = {
    "sudo", "wheel", "admin", "docker", "lxd", "libvirt", "disk", "shadow"
}


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    evidence: dict


def add(findings: list[Finding], severity: str, category: str,
        message: str, **evidence: object) -> None:
    """Append one normalized finding to the report's finding list."""
    findings.append(Finding(severity, category, message, evidence))


def rooted(root: Path, path: str) -> Path:
    """Map an absolute Linux path into an optional test filesystem root."""
    return root / path.lstrip("/")


def read_lines(path: Path) -> list[str]:
    """Read a text file, returning an empty list if it cannot be read."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (FileNotFoundError, PermissionError, OSError):
        return []


def parse_passwd(path: Path) -> list[dict]:
    """Parse /etc/passwd entries into simple dictionaries for auditing."""
    users = []
    for line in read_lines(path):
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) >= 7:
            try:
                users.append({
                    "name": fields[0],
                    "uid": int(fields[2]),
                    "gid": int(fields[3]),
                    "home": fields[5],
                    "shell": fields[6],
                })
            except ValueError:
                continue
    return users


def parse_groups(path: Path) -> dict[str, list[str]]:
    """Parse /etc/group and return each group with its supplementary members."""
    groups: dict[str, list[str]] = {}
    for line in read_lines(path):
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) >= 4:
            groups[fields[0]] = [x for x in fields[3].split(",") if x]
    return groups


def iter_files(path: Path, max_files: int = 5000) -> Iterable[Path]:
    """Yield regular files below a directory, with a safety limit."""
    if not path.exists():
        return
    count = 0
    try:
        for item in path.rglob("*"):
            if item.is_file():
                yield item
                count += 1
                if count >= max_files:
                    return
    except (PermissionError, OSError):
        return


def check_accounts(root: Path, baseline: dict, findings: list[Finding]) -> None:
    """Find unexpected UID 0 accounts and users absent from the baseline."""
    users = parse_passwd(rooted(root, "/etc/passwd"))
    allowed_uid0 = set(baseline.get("allowed_uid0", ["root"]))
    allowed_users = set(baseline.get("allowed_users", []))

    for user in users:
        # UID 0 grants root-level authority regardless of the account name.
        if user["uid"] == 0 and user["name"] not in allowed_uid0:
            add(findings, "critical", "local_accounts",
                f"Unexpected UID 0 account: {user['name']}", user=user["name"])

        if allowed_users and user["name"] not in allowed_users and user["uid"] >= 1000:
            add(findings, "medium", "local_accounts",
                f"User is not present in the baseline: {user['name']}",
                user=user["name"], uid=user["uid"])


def check_groups(root: Path, baseline: dict, findings: list[Finding]) -> None:
    """Find unexpected members of groups that commonly grant elevated access."""
    groups = parse_groups(rooted(root, "/etc/group"))
    privileged = set(baseline.get("privileged_groups", DEFAULT_PRIVILEGED_GROUPS))
    allowed_members = set(baseline.get("allowed_privileged_users", ["root"]))

    for group_name in privileged:
        # Group membership can provide administrative access without sudo.
        for user in groups.get(group_name, []):
            if user not in allowed_members:
                add(findings, "high", "group_membership",
                    f"Unexpected member of privileged group {group_name}: {user}",
                    group=group_name, user=user)


def check_sudoers(root: Path, baseline: dict, findings: list[Finding]) -> None:
    """Find broad sudo rules, including NOPASSWD rules, outside the allowlist."""
    paths = [rooted(root, "/etc/sudoers")]
    paths.extend(iter_files(rooted(root, "/etc/sudoers.d")))
    allowed = set(baseline.get("allowed_sudo_patterns", []))

    for path in paths:
        for number, line in enumerate(read_lines(path), start=1):
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            if "NOPASSWD" in clean or re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)", clean):
                # Allowlisted rules are expected competition configuration.
                if not any(fnmatch.fnmatch(clean, pattern) for pattern in allowed):
                    add(findings, "high", "sudoers", "Broad sudo rule detected",
                        file=str(path), line=number, rule=clean)


def check_sensitive_permissions(root: Path, findings: list[Finding]) -> None:
    """Flag sensitive files and directories accessible by non-owners."""
    sensitive = [
        rooted(root, "/etc/shadow"),
        rooted(root, "/etc/sudoers"),
        rooted(root, "/root/.ssh"),
    ]
    for path in sensitive:
        if not path.exists():
            continue
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            continue
        if mode & 0o077:
            # The low two octal digits represent group and other permissions.
            add(findings, "high", "file_permissions",
                f"Sensitive path is accessible by other users: {path}",
                path=str(path), mode=oct(mode))


def check_cloud_credentials(root: Path, findings: list[Finding]) -> None:
    """Find common cloud credential/key files with overly broad permissions."""
    home = rooted(root, "/home")
    candidates = [
        rooted(root, "/root/.aws/credentials"),
        rooted(root, "/root/.config/gcloud"),
        rooted(root, "/root/.azure"),
    ]
    candidates.extend(iter_files(home))

    key_names = {"credentials", "config", "*.pem", "*.key", "*.p12"}
    seen: set[Path] = set()
    for path in candidates:
        # Avoid reporting the same file more than once when scanning home paths.
        if path in seen or not path.exists() or not path.is_file():
            continue
        seen.add(path)
        if path.name not in {"credentials", "config"} and not any(
            fnmatch.fnmatch(path.name, pattern) for pattern in key_names
        ):
            continue
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            continue
        if mode & 0o077:
            add(findings, "high", "cloud_credentials",
                f"Possible credential file is too permissive: {path}",
                path=str(path), mode=oct(mode))


def check_capabilities(findings: list[Finding]) -> None:
    """Check file capabilities when getcap is available on the live system."""
    try:
        result = subprocess.run(["getcap", "-r", "/"], text=True,
                                capture_output=True, timeout=20)
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return
    for line in result.stdout.splitlines():
        # Capabilities can grant powerful access without setuid; review each one.
        if line.strip():
            add(findings, "medium", "file_capabilities",
                "File capability detected; verify it is expected", result=line.strip())


def audit(root: Path, baseline: dict, include_live_checks: bool = True) -> dict:
    """Run all checks and return a JSON-serializable report dictionary."""
    findings: list[Finding] = []
    check_accounts(root, baseline, findings)
    check_groups(root, baseline, findings)
    check_sudoers(root, baseline, findings)
    check_sensitive_permissions(root, findings)
    check_cloud_credentials(root, findings)
    # Commands such as getcap inspect the live host and are skipped for fixtures.
    if include_live_checks and root == Path("/"):
        check_capabilities(findings)

    counts = {level: sum(f.severity == level for f in findings)
              for level in ("critical", "high", "medium", "low")}
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": os.uname().nodename,
        "findings": [asdict(f) for f in findings],
        "summary": {"total": len(findings), **counts},
    }


def print_human(report: dict) -> None:
    """Print a short operator-friendly version of a JSON audit report."""
    summary = report["summary"]
    print(f"RBAC audit complete: {summary['total']} finding(s)")
    print("  " + "  ".join(f"{k.title()}: {summary[k]}"
                          for k in ("critical", "high", "medium", "low")))
    for item in report["findings"]:
        evidence = ", ".join(f"{k}={v}" for k, v in item["evidence"].items())
        print(f"[{item['severity'].upper()}] {item['message']}" +
              (f" ({evidence})" if evidence else ""))


def exit_code(report: dict) -> int:
    """Convert finding severity into a shell-friendly status code."""
    if report["summary"]["critical"]:
        return 2
    if report["summary"]["high"]:
        return 2
    if report["summary"]["medium"] or report["summary"]["low"]:
        return 1
    return 0


def main() -> int:
    """Parse command-line options, run the audit, and print or save its report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="baseline.json")
    parser.add_argument("--root", default="/", help="Alternate filesystem root for testing")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--output", help="Write the JSON report to a file")
    args = parser.parse_args()

    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    report = audit(Path(args.root), baseline)
    serialized = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(serialized + "\n", encoding="utf-8")
    if args.json:
        print(serialized)
    else:
        print_human(report)
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
