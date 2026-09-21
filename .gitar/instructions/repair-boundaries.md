# Automated pull request repair boundaries

Gitar auto-apply is enabled for ready-for-review pull requests. Apply only a
small, deterministic repair when the intended behavior is clear from the
existing code, tests, and pull request.

- Keep each repair within the changed feature's scope and run the relevant
  existing validation after changing files.
- Do not change trust classes, activation defaults, authority, policy floors,
  required controls, publisher claim metadata, or security-sensitive behavior.
- Do not edit workflow, release, dependency, credential, or repository-access
  configuration as an automatic repair.
- Do not invent product behavior, matcher semantics, safe variants, test cases,
  public attribution, or upstream references. Explain the missing decision when
  one is required.

## Declarative extension submissions

When a pull request changes `contributions/command-sources/`, portable command
fixtures, or the extension trust map:

1. Check that the source filename, fixture filename, fixture source binding,
   and external trust-map entry agree.
2. When those authored inputs are valid, synchronize only deterministic
   projections with `scripts/prepare_extension_contribution.py` and include its
   generated descriptor, native program, catalog, and package-resource updates.
3. Run `hol-guard extensions handoff` for the source and fixture, then the
   relevant existing extension validation.

Never change a submitted command matcher, permission, rule, safe variant,
trust class, or claimant ID to make a check pass. Report the exact failed
contract when the contributor must make that decision.
