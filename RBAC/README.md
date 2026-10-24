# CCDC RBAC Auditor

Read-only Linux authorization and cloud-credential audit tool for an authorized CCDC environment.

## Run

```bash
sudo python3 rbac_auditor.py --baseline baseline.json
sudo python3 rbac_auditor.py --baseline baseline.json --json --output report.json
```

Exit codes:

- `0`: no findings
- `1`: medium or low findings
- `2`: high or critical findings

## Baseline workflow

Edit `baseline.json` after confirming the expected competition configuration. Add legitimate privileged users and intentionally broad sudo rules to the allowlists. Keep the file protected and root-owned on the target system.

The tool checks UID 0 accounts, privileged group membership, broad sudo rules, sensitive file permissions, cloud credential/key file permissions, and live file capabilities when `getcap` is installed.

It does not change accounts, permissions, services, or cloud resources.

## Local lab environment

`lab_environment.py` creates a disposable Linux-like filesystem fixture with intentionally bad accounts, group membership, sudo rules, and fake credential files. It does not contact AWS, Azure, GCP, or any other cloud provider.

```bash
LAB=$(python3 lab_environment.py create)
python3 rbac_auditor.py --root "$LAB" --baseline baseline.json
python3 lab_environment.py delete "$LAB"
```

The delete command only removes directories containing the tool's `.rbac-auditor-lab` safety marker.

## Caution

Run only on systems and cloud accounts you are authorized to administer. Review findings before taking remediation actions; `docker`, `lxd`, and some cloud roles can be intentionally privileged.
