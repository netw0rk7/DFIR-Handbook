# Contributing

Thank you for helping improve the DFIR Handbook.

## Before You Start

- Open an issue for substantial structural or methodological changes.
- Do not submit real case data, credentials, personal information, customer
  names, internal hostnames, public attacker IP addresses, or live malware.
- Use `.example` names and the documentation address blocks listed in the
  README.
- Prefer authoritative sources and maintained tools over custom wrappers.
- Do not present a single artifact or heuristic as proof without stating its
  limitations and corroboration requirements.

## Content Guidelines

1. Write in clear English and define uncommon acronyms on first use.
2. Separate collection, examination, analysis, and reporting guidance.
3. State required authorization, evidence-preservation risks, and destructive
   side effects near relevant commands.
4. Link to primary documentation for tools, standards, and platform behavior.
5. Treat tool output as evidence to validate, not an infallible conclusion.
6. Use UTC in timelines unless a section explicitly explains time-zone
   conversion.

## Pull Requests

1. Create a focused branch.
2. Make the smallest coherent change.
3. Run `python3 tools/validate_repository.py`.
4. Review rendered Markdown and verify every new link.
5. Explain the source, validation method, and limitations of technical changes.

By contributing, you agree that your contribution is licensed under the
Apache License 2.0.
