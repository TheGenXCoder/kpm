# Contributing to KPM

Thanks for considering a contribution. This is a security tool, so the bar for changes is higher than typical open-source projects. Read this first.

## Quick start

```bash
git clone https://github.com/TheGenXCoder/kpm.git
cd kpm
go build ./cmd/kpm/
go test ./internal/kpm/ -count=1
```

## What makes a good contribution

- **Bug fixes with tests.** If you found a bug, write a failing test first, then fix it.
- **Documentation improvements.** README, blog posts, examples. If you got confused, others will too.
- **Test coverage for untested paths.** The `internal/backend` package has room for improvement.
- **Platform support.** Windows support is on the roadmap. Contributions welcome.
- **Performance improvements** with benchmarks proving the improvement.

## What needs discussion before a PR

Open an issue before doing any of the following. We want to talk through the design.

- **New commands.** The command surface is already wide; each new command adds to what users have to learn.
- **Changes to the security model.** The threat model in `SECURITY.md` is deliberate. Propose changes as an issue first.
- **New cryptographic primitives.** We use Go stdlib where possible. New dependencies on crypto libraries need justification.
- **Template syntax changes.** Existing users' templates must continue to work.
- **Breaking changes.** Pre-1.0 we can break things, but we want to batch breaking changes rather than dribble them out.

## Code style

- **Follow existing patterns.** Read the code before adding to it.
- **`[]byte` for secrets, `string` only as a last resort.** See `internal/kpm/zero.go`.
- **Zero secrets after use.** Use `defer ZeroBytes(value)` or equivalent.
- **No `fmt.Println` for anything touching secrets.** Even "just for debugging."
- **Audit everything on the server side.** Every operation produces an audit event.
- **No secret values in error messages.** Ever.
- **Prefer explicit flags over magic.** If a behavior needs to be opt-in, make it a flag.

## Testing requirements

Every PR must:

1. **Pass `go test ./...`** with no new failures.
2. **Maintain or improve test coverage** for the affected package.
3. **Include tests for new code paths.** Not just happy paths — error cases too.
4. **Include security-relevant tests for security-relevant changes.** If you touched anything in `encrypt.go`, `client.go`, `registry.go`, or the shell-init flow, you need adversarial tests.

Run the full integration suite against your changes before submitting:

```bash
# Requires Docker
bash tests/run-tests.sh
```

## Commit messages

Use [conventional commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `test:` tests only
- `docs:` documentation only
- `refactor:` code restructuring with no behavior change
- `chore:` tooling, dependencies, build

Scope optional but helpful: `feat(cli): ...`, `fix(crypto): ...`.

Commit messages should explain **why**, not just what. The diff shows what.

## Pull requests

- **Keep PRs focused.** One logical change per PR. Don't bundle refactoring with feature work.
- **Write a clear description.** What problem does this solve? What alternatives did you consider?
- **Reference the issue** if one exists. Link to the design discussion.
- **Sign your commits** (recommended). `git commit -s` or configure `user.signingkey`.

## Code review

Security-sensitive changes require review from a maintainer. Non-security changes may be merged faster. Expect 1-5 business days for initial response.

Review focuses on:

1. Does it solve the stated problem?
2. Does it introduce new risks?
3. Does it maintain the invariants in `SECURITY.md`?
4. Is it tested?
5. Is the code understandable by someone who isn't you?

## Security-sensitive areas

Extra care required when changing:

- `internal/kpm/client.go` — HTTP + auth layer
- `internal/kpm/encrypt.go` — AES-GCM session encryption
- `internal/kpm/listener.go` — UDS decrypt listener
- `internal/kpm/session.go` — session persistence
- `internal/kpm/zero.go` — memory zeroing
- Anything that touches `[]byte` containing secret material
- Anything that touches the audit event format or policy evaluation

Changes in these areas need:

- Adversarial tests added or updated
- Security implications documented in the PR description
- A second reviewer if the change is non-trivial

## Not sure?

Open an issue. Ask. "Is this a good idea?" is a valid question, and getting a "yes" before you spend a weekend on a PR is better than getting a "no" after.
