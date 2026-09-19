# Water Sector Detection Rules

Self-directed detection engineering portfolio focused on threats to the UK water sector.
Each rule is mapped to MITRE ATT&CK and tied to a publicly documented threat actor.

| Rule | Type | Threat | ATT&CK |
|------|------|--------|--------|
| `sigma/volt_typhoon_ntdsutil_ifm.yml` | Sigma | Volt Typhoon (critical infrastructure pre-positioning) | T1003.003 |
| `sigma/ransomware_shadow_copy_deletion.yml` | Sigma | Black Basta and other ransomware | T1490 |
| `yara/ransomware_inhibit_recovery.yar` | YARA | Ransomware binaries | T1490 |

The Sigma and YARA rules for T1490 detect the same technique at two layers:
the Sigma rule catches the behaviour when it runs, the YARA rule catches the
file before it runs.

## Testing
- Sigma: converted to Splunk queries with `sigma convert -t splunk --without-pipeline sigma/`
- YARA: `yara yara/ransomware_inhibit_recovery.yar tests/` (matches `test_positive.bin`, not `test_negative.bin`)
