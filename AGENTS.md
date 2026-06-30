# AGENTS.md — repository governance for FindGT

This file defines how AI agents and human contributors should interact with this repository.
It is intentionally process-oriented: keep it current when the development workflow, build method,
documentation model, or repository constraints change.

## Scope and intent

- This file applies to both AI agents and human contributors.
- It defines repository interaction rules, review expectations, documentation obligations,
  sanitization constraints, and change validation requirements.
- Keep repo-specific guidance high-level and durable. Add a few extra warnings only when they
  materially reduce repeated mistakes.

## Canonical documentation source

- [README.md](README.md) is the canonical source of truth when README language variants diverge.
- [README.ru.md](README.ru.md), [README.el.md](README.el.md), and any future
  `README.<lang>.md` files must preserve the same meaning, coverage, links, checklist states,
  and user-relevant behavior descriptions.
- If a significant user-visible change is made, update all README language files in the same change.

Significant changes include:

- feature additions or removals,
- CLI or option changes,
- build, runtime, or environment requirement changes,
- new projects or removed projects,
- changes to security assumptions or operator workflow,
- anything a user would reasonably need to know before building or running the tool.

## README parity process

- Keep all README language files synchronized with the canonical [README.md](README.md).
- Maintain [README_EQUIVALENCE.md](README_EQUIVALENCE.md) whenever multilingual semantics change.
- Parity includes:
  - the same major section set and order,
  - the same user-facing meaning,
  - the same diagram set and fallback links,
  - the same external evidence links where applicable,
  - the same roadmap and checklist states.
- Do not let one language variant silently become more optimistic, more complete, or more outdated
  than the canonical README.

## Adding a new README language

When adding a new `README.<lang>.md` file:

1. Start from canonical [README.md](README.md), not from another translation.
2. Add the new language file in the same change where the language is introduced.
3. Keep the same major sections, diagrams, links, and checklist states as the canonical README.
4. Update cross-references so README files point to [AGENTS.md](AGENTS.md) and the language set remains coherent.
5. Update [README_EQUIVALENCE.md](README_EQUIVALENCE.md) to include the new language in the compliance checklist.
6. Verify that the new language does not add or remove technical claims compared with canonical [README.md](README.md).

## Documentation freshness

- Documentation must remain operationally accurate.
- If the build method, framework, packaging model, runtime assumptions, or deployment expectations
  change, update the README set and this file as needed in the same change.
- If a repo-specific constraint becomes obsolete, remove or rewrite it instead of letting stale
  process guidance accumulate.

## Repo-specific technical constraints

- Respect the current documented build flow in the README set. Do not assume the repository uses
  a modern SDK-style or `dotnet restore` / `dotnet build` workflow unless the repository is actually migrated.
- Before changing build or dependency behavior, verify the current project model and keep the
  README set aligned with the real build path.
- Expect this repository's security-sensitive behavior to be tied to Windows, domain-joined
  testing, elevated execution, and environment-specific validation when changes touch sessions,
  tokens, LSA, Kerberos, or related flows.
- Stack constraints that materially affect edits should remain documented here at a high level.
  Example: if the active codebase still relies on older language or project-system constraints,
  do not introduce newer assumptions without updating the repository deliberately.
- If a recurring gotcha repeatedly breaks changes, document it briefly in the relevant process
  section rather than creating a disconnected dump of trivia.

## Sanitization and secrets policy

- Never commit secrets, credential artifacts, machine-account material, extracted hashes, registry hives,
  or similar sensitive data.
- Never commit personal environment identifiers from a live environment in examples or docs.
- Use fictitious placeholders for examples unless public branding is intentionally being referenced:
  - user: `testuser`
  - domain/realm: `CONTOSO.COM`
  - domain controllers: `DC01.contoso.com`, `DC02.contoso.com`
- Public attribution, public branding, and public demo references may remain when they are clearly intentional.
- If sanitization policy changes, update the README set and this file together.

## Change process

- Prefer the smallest change that solves the problem at the right abstraction level.
- Read the current surrounding documentation before changing policy or user-facing behavior.
- If a change affects build flow, user workflow, or environment expectations, update docs in the same change.
- If a change affects multilingual user-facing content, fix the canonical README first, then sync other languages,
  then update [README_EQUIVALENCE.md](README_EQUIVALENCE.md).
- When repository conventions or workflow assumptions change, update this file as part of the same work.

## Validation expectations

- Run targeted validation for the touched scope whenever available.
- Keep touched files free of editor and language-service errors.
- If code behavior changes, validate with the current documented build path and any narrow runtime
  check that is practical in the environment.
- Do not treat a README-only diff as complete if the change also altered actual behavior.

## Definition of done

A change is not complete until all applicable items below are true:

1. Touched files are free of relevant errors.
2. The current documented build flow still matches reality, or the documentation was updated in the same change.
3. User-visible behavior changes are reflected in canonical [README.md](README.md) and synchronized across all README language files.
4. [README_EQUIVALENCE.md](README_EQUIVALENCE.md) is updated when multilingual semantics changed.
5. Sanitization and secret-handling rules were respected.
6. This file was updated if repository interaction rules, documentation process, or durable technical constraints changed.
