# Windows service/MSI roadmap

## Реализовано

- .NET Framework 4.8 x64 и full LUID/handle hardening.
- Shared Core, typed verdict, PowerfulOnly и FGT001–FGT010.
- Event 4624 ingestion, bounded queue, bookmark и reconciliation.
- LocalSystem ServiceBase host с retry/health/safe shutdown.
- Manifest Operational, Authz Security и optional JSONL.
- WiX 7 per-machine MSI, native rollback-aware actions и interactive properties.
- Unit tests, release scripts, CI/release/manual lab workflows.

## Открытые gates

1. Disposable MSI install/repair/upgrade/uninstall execution.
2. Windows Server 2019 domain lab.
3. Legitimate admin и две distinct forged sessions.
4. Real Event 4624 correlation.
5. PowerfulOnly и failure-mode evidence.
6. Production certificate/code signing.

До закрытия первых пяти gates реализация не должна заявляться как
лабораторно подтверждённый Golden Ticket detector release.
