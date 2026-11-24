# Security policy

AgentShield is security software; please report vulnerabilities privately.

- Contact: via https://www.vandeblaak.com (contact form) — mention "AgentShield security".
- Please include affected version (`agentshield --version`), OS, and reproduction steps with
  **fictional** credentials only.
- Do not open public issues for unfixed vulnerabilities.

## Scope highlights

In scope: hook bypasses that make AgentShield report a decision it did not apply, IPC authentication
bypass, redaction failures (secrets reaching the database, GUI, reports or logs), policy-layer escalation
(a project policy weakening user/preset policy), audit-log tamper evidence defeats that are not
documented, installer changes to unrelated Claude Code settings.

Known, documented limitations (not vulnerabilities): an attacker with full rights of the same OS user
can disable or rewrite AgentShield and its logs; AgentShield only sees what Claude Code hooks expose;
the hash chain is tamper-evident, not tamper-proof. See `docs/THREAT_MODEL.md`.
