# AGENT.md — working agreement for the FindGT repository

Guidance for AI agents (and contributors) working in this repo. Read this before changing anything.

## 🔴 Hard rule: keep BOTH READMEs in sync

**No significant change may be made without updating BOTH README files in the same change:**

- [README.md](README.md) — English
- [README.ru.md](README.ru.md) — Russian

Both files MUST carry the **same information** and differ only in language. "Significant" means:
a new/removed feature, a CLI/option change, a new project, changed requirements or build steps,
or anything a user would need to know. Pure internal refactors that don't change behaviour or
usage don't require a README edit — but when in doubt, update both.

## What this project is

FindGT detects Golden-Ticket group forgery by comparing each Kerberos session token's domain
groups against **authoritative** membership (Kerberos **S4U2Self** primary, **LDAP** fallback)
and reporting the diff with Spectre.Console. See the READMEs for the full description.

## Toolset & environment

| Item                   | Value                                                                                                                                                                                                                                         |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Build engine           | MSBuild from VS 2022: `C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe`                                                                                                                            |
| Solution / build       | `FindGT.sln`, `/p:Configuration=Release /p:Platform=x64 /m`                                                                                                                                                                                   |
| FindGT TFM             | .NET Framework **4.7.2**, **x64**, C# **langversion 7.3**, `AllowUnsafeBlocks`, `AutoGenerateBindingRedirects`                                                                                                                                |
| LsaSecretExtractor TFM | .NET Framework **4.8**, AnyCPU (`Prefer32Bit=false`), manifest `requireAdministrator`                                                                                                                                                         |
| Packages               | **packages.config** (classic, NOT PackageReference): Spectre.Console + Spectre.Console.Cli **0.49.1**, System.Memory 4.6.0 (+ System.Buffers / System.Numerics.Vectors / System.Runtime.CompilerServices.Unsafe), System.DirectoryServices.\* |
| NuGet restore          | `nuget.exe` (download from dist.nuget.org). **`dotnet restore` does NOT restore packages.config projects.**                                                                                                                                   |
| Runtime                | Windows, **domain-joined**, run **elevated** (the tool self-elevates to SYSTEM).                                                                                                                                                              |

## Project layout (FindGT)

- `Membership/` — providers + comparison: `IMembershipProvider`, `S4UMembershipProvider` (primary),
  `LdapMembershipProvider` (fallback), `MembershipComparer`, `SidUtil`.
- `Reporting/` — output: `SessionReport`, `SpectreReporter`, `Ui`.
- `Cli/` — command line: `Commands` (Spectre.Console.Cli commands), `AppRunner` (orchestration).
- `Kerberos/` — (planned) raw-Kerberos "Option B".
- `Docs/` — design docs (e.g. the Option B plan).
- Core: `S4U.cs`, `Nrpc.cs`, `Md4.cs`, `Interop.cs`, `Helpers.cs`, `Find.cs`, `Creds.cs`.

## Conventions & gotchas

- **C# 7.3 only** in FindGT (langversion 7.3). No records, target-typed `new`, `is not`,
  switch expressions, file-scoped namespaces, or nullable reference types.
- **`FindGT` is both a namespace AND a class.** Never use the fully-qualified form
  `FindGT.Membership.X` (the compiler binds `FindGT` to the class → error CS0426). Use a
  `using FindGT.Membership;` / `using FindGT.Reporting;`, or the relative `Membership.X` /
  `Reporting.X` from inside the `FindGT.*` namespaces.
- **Adding a NuGet package:** `nuget.exe install <id> -OutputDirectory packages`, then add a
  `<Reference>` with `HintPath` in `FindGT.csproj` and an entry in `packages.config`. Keep
  binding redirects (handled by `AutoGenerateBindingRedirects`).
- **Spectre.Console markup:** escape all dynamic text with `Markup.Escape(...)`. Route every
  message (operational and report) through `AnsiConsole` / `Reporting.Ui` so the `--html`
  recording captures it. Call `Ui.BeginRecord()` BEFORE the first output when `--html` is set.
- **Console encoding:** `Console.OutputEncoding = UTF8` is set in `Main` for Cyrillic output.
- **Elevation:** anything touching tokens/LSA needs SYSTEM; `AppRunner.EnsureSystem()` handles it.
  To test elevated and still capture output, run via an elevated `cmd /c "exe ... > out.txt 2>&1"`.

## Security

- **Never commit secrets.** `secrets/` and `*.nthash` are gitignored. The machine NT hash and any
  saved registry hives are sensitive — keep them out of the repo and delete temp artifacts.
- This is an **offensive-security research / PoC** tool, for **authorized** testing only.

## Definition of done for a change

1. `get_errors` is clean on the touched files.
2. `msbuild FindGT.sln /p:Configuration=Release /p:Platform=x64` succeeds (all projects).
3. If behaviour/usage changed: verified on the domain stand (elevated).
4. **Both READMEs updated** (EN + RU, same information).
