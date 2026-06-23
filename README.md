# FindGT — Golden Ticket membership anomaly detector

> Russian version: [README.ru.md](README.ru.md). **Both READMEs must be kept in sync** — see [AGENT.md](AGENT.md).

FindGT inspects Windows **Kerberos logon sessions** and compares the group membership
**claimed by each session token** against the **authoritative membership** the domain
controller reports for that user. A Golden Ticket forges a TGT with arbitrary group SIDs
(e.g. `Domain Admins`, `Enterprise Admins`, `Schema Admins`); those forged groups appear
in the session token but **not** in the authoritative source — which is what FindGT flags.

> Research / PoC tool. A large amount of token/session code is derived from
> [GhostPack/Koh](https://github.com/GhostPack/Koh).

## How it works

1. Enumerate logon sessions (LSA) and keep the **Kerberos** ones.
2. For each session, read the **domain group SIDs** (`S-1-5-21-*`) from the session token.
3. Compute the **authoritative** membership for the same user:
   - **Primary — Kerberos S4U2Self** (`KERB_S4U_LOGON` via `LsaLogonUser`). The machine
     account asks the KDC for a ticket-to-self impersonating the user; the KDC builds a
     **fresh PAC from current AD state**, independent of the user's (possibly forged) TGT.
   - **Fallback — LDAP** recursive group walk (cycle-protected, depth-capped at 64).
4. **Diff** the two sets and report:
   - in token **but not** authoritative → **suspicious** (possible forgery, red),
   - authoritative **but not** in token → informational (yellow),
   - a member SID that is a **user**, not a group → highlighted.

Because S4U2Self queries the DC fresh with the _machine's_ identity, a Golden Ticket in the
user's session cannot influence the authoritative answer.

## Components

| Project                | Purpose                                                                                                      | TFM                       |
| ---------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------- |
| **FindGT**             | Main tool: session scan, membership diff, Spectre.Console report, NRPC secure-channel + S4U diagnostics.     | .NET Framework 4.7.2, x64 |
| **LsaSecretExtractor** | Extracts the machine-account secret / NT hash from LSA (registry decrypt) to a file, for NRPC bootstrapping. | .NET Framework 4.8        |

## Requirements

- Windows, **domain-joined** host.
- **Administrator** — the tool elevates to **SYSTEM** (needed for S4U logon and token access).
- .NET Framework 4.7.2+ (4.8 for LsaSecretExtractor), x64.
- Visual Studio 2022 / MSBuild; NuGet packages restored.

## Build

```text
# packages.config project: restore with nuget.exe (dotnet restore does not handle packages.config)
nuget restore FindGT.sln
msbuild FindGT.sln /p:Configuration=Release /p:Platform=x64 /m
```

## Usage

```text
FindGT [OPTIONS] [COMMAND]

OPTIONS:
  -v, --verbose   Show every group per session, not only discrepancies
      --html      Save the report as an HTML file in the current directory
  -h, --help      Show help

COMMANDS:
  test-s4u <upn> [realm]                   S4U2Self membership for one user
  test-securechannel <nthash-file> [dc]    Establish & verify a Netlogon secure channel
  test-securechannel-raw <file> [dc]       Brute-force the machine-secret derivation
  test-crypto                              Self-test MD4 / AES-CFB8
```

Default (no command) = scan all Kerberos sessions and print **only discrepancies**.

LsaSecretExtractor:

```text
LsaSecretExtractor --out <path> [--encoding hex|base64|raw] [--secret <name>] [--nthash]
```

## Output

One Spectre.Console table per session: **SID | Name | Comment**, colour-coded
(red = suspicious, yellow = missing-from-token, green = match, shown with `--verbose`).
`--html` exports a styled, self-contained UTF-8 HTML document to the current folder.

## Implemented

- [x] Machine-account secret extraction (LSA registry decrypt) — `LsaSecretExtractor`.
- [x] NRPC Netlogon secure channel (AES) — established & verified against a live DC.
- [x] S4U2Self authoritative membership (`KERB_S4U_LOGON`).
- [x] Token-vs-authoritative diff, Golden-Ticket oriented.
- [x] LDAP fallback (recursive, cycle-protected).
- [x] Spectre.Console report + `--html`; Spectre.Console.Cli command line with auto-help.

## Roadmap / TODO

- [ ] **Option B** — fully self-contained raw-Kerberos S4U2Self + U2U (independent of local
      LSASS). Detailed plan: [Docs/OptionB-RawKerberos-S4U2Self.md](Docs/OptionB-RawKerberos-S4U2Self.md).
- [ ] Validate the "suspicious" (red) path against a real forged ticket in a lab.
- [ ] Secret hardening — DPAPI/CredMan storage, restrictive ACLs, field masking.
- [ ] Broader coverage — cross-domain ExtraSids, multiple DCs, more session types.
- [ ] Structured per-run log file.

> Note: NRPC `NetrLogonSamLogonEx` was evaluated as a membership source but **cannot** return
> an arbitrary user's groups without that user's credentials (no S4U at the Netlogon level), so
> S4U2Self (Kerberos) is the membership mechanism.

## Acknowledgments & License

Derived in part from [GhostPack/Koh](https://github.com/GhostPack/Koh). Free and open-source,
provided **as-is, without warranty**. For **authorized** security testing only.
