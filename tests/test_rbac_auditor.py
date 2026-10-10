import json
from pathlib import Path

from rbac_auditor import audit, exit_code


def make_tree(tmp_path: Path, passwd: str, group: str, sudoers: str = "") -> Path:
    (tmp_path / "etc" / "sudoers.d").mkdir(parents=True)
    (tmp_path / "home").mkdir()
    (tmp_path / "etc" / "passwd").write_text(passwd)
    (tmp_path / "etc" / "group").write_text(group)
    (tmp_path / "etc" / "sudoers").write_text(sudoers)
    return tmp_path


def test_detects_uid0_and_privileged_group(tmp_path):
    root = make_tree(
        tmp_path,
        "root:x:0:0:root:/root:/bin/bash\nattacker:x:0:0::/home/attacker:/bin/bash\n",
        "sudo:x:27:attacker\n",
    )
    report = audit(root, {"allowed_uid0": ["root"], "allowed_privileged_users": ["root"]}, False)
    assert report["summary"]["critical"] == 1
    assert report["summary"]["high"] == 1
    assert exit_code(report) == 2


def test_clean_minimal_tree(tmp_path):
    root = make_tree(
        tmp_path,
        "root:x:0:0:root:/root:/bin/bash\n",
        "sudo:x:27:\n",
    )
    report = audit(root, {"allowed_uid0": ["root"], "allowed_privileged_users": ["root"]}, False)
    assert report["summary"]["total"] == 0
    assert exit_code(report) == 0
