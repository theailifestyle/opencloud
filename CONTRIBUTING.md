# Contributing

Open Cloud is a single Linux server that deploys apps from public Git repositories. Changes should keep a fresh install working from this tree, with no machine-specific hostnames, addresses, or secret paths committed.

## Development

- Python 3. The console, deployer, gateway, and watch service use the standard library. The console image also installs `segno` (pinned by hash) for two-step login QR codes.
- Shell scripts are bash.

Run the unit tests from a checkout:

```bash
python3 -m unittest discover -s tests
```

`tests/e2e.sh` needs a running local install (`OC_TLS=internal`), Docker, and sudo. It is not part of the unit run.

Check the shell scripts and scan for secrets:

```bash
bash -n install.sh opencloud compose-env.sh tests/e2e.sh tests/e2e-external.sh
shellcheck install.sh opencloud compose-env.sh
gitleaks detect --no-git --source .
```

`tests/e2e.sh` is a long script full of checks that shellcheck warns about (variables are expanded later by `eval`). `bash -n` is the check that matters there. `.gitleaks.toml` skips `tests/` because those files contain only synthetic fixtures, including the public RFC 6238 test vector.

## What not to commit

- `.env`, anything under a secrets directory, passwords, tokens, or private keys
- Hostnames, IP addresses, or paths that belong to one install. Those belong in `.env` on the server. `.env.example` uses placeholders (`example.com`, `203.0.113.10`, `/srv/opencloud`).
- Runtime data (`apps/`, `data/`, backups, certificates)

## Docs

Guides live in `docs/`. Update the guide that already covers a topic instead of adding a second copy. The front page is `README.md`.

## Pull requests

Describe what changed and how you checked it. A behavior change needs a unit test. Do not weaken the deployer's fixed action list or the rule that only the edge publishes ports.
