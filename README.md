# Misconfig agent runtime

Misconfig launches Codex or Claude inside a named infrastructure session. Each
session has a frozen scope, signed rules, a remote stop, and redacted action
receipts. Existing AWS profiles and kubeconfig files stay on the device.

This repository is independent from the hosted control plane and console.

## Current commands

```text
misconfig setup
misconfig profile create
misconfig profile list
misconfig run
misconfig status
misconfig uninstall --yes
misconfig doctor
misconfig version
```

`misconfig hook` is an internal native-adapter entry point. Do not invoke it
manually.

## Install a release

Release archives are self-contained. Installing one does not require Go, Git,
or a source checkout. Select the archive matching macOS or Linux and the
machine architecture, verify it against `checksums.txt`, then extract it:

```sh
sha256sum -c checksums.txt
tar -xzf misconfig_VERSION_OS_ARCH.tar.gz
sudo ./install.sh
```

macOS provides `shasum -a 256 -c checksums.txt` in place of `sha256sum`.
`checksums.txt` covers every archive and the exact `manifest.json`; it is the
subject intended for release signing. Until detached signatures are published,
obtain it through the same trusted release channel as the archive.

Enroll without putting the short-lived token in shell history or the process
argument list:

```sh
printf '%s' "$MISCONFIG_ENROLLMENT_TOKEN" | misconfig setup \
  --control https://sessions.misconfig.cloud \
  --tenant TENANT \
  --actor EMAIL \
  --token-file -
unset MISCONFIG_ENROLLMENT_TOKEN
```

The extracted `uninstall.sh --yes` removes runtime state and the installed
binary. Pass `--keep-state` only when intentionally preserving local state.

## Build the current development runtime

Go 1.25 or newer is required by the current module.

```sh
go test -race ./...
go build -o ./bin/misconfig ./cmd/misconfig
```

Maintainers can build the versioned macOS/Linux matrix reproducibly:

```sh
make release RELEASE_VERSION=0.1.0
make verify-release
```

The release command embeds the explicit version, strips host paths and build
IDs, fixes archive metadata to `SOURCE_DATE_EPOCH`, and emits `manifest.json`
plus `checksums.txt`. It refuses to overwrite an existing release by default.

## Enrol one device

An operator obtains a short-lived founder-staging enrollment token out of band.
The token is read from a protected file, stdin, or
`MISCONFIG_ENROLLMENT_TOKEN`; it is never accepted on the command line.

```sh
./bin/misconfig setup \
  --control https://sessions.misconfig.cloud \
  --tenant tenant-founder-staging \
  --tenant-name "Misconfig founder staging" \
  --actor you@example.com \
  --device "work-mac" \
  --token-file /path/to/enrollment-token
```

On macOS the returned device credential is stored in Keychain. Other current
development builds use a mode-0600 local secret file. Policy verification uses
the Ed25519 public key pinned during enrollment.

## Create a session profile

Without a rules file the safe default holds every infrastructure action for
approval. Codex 0.152 cannot pause a native hook for an external approval, so
that decision is rendered as a deny; Claude renders it as its native `ask`.

```sh
./bin/misconfig profile create \
  --name "AWS production reads" \
  --agent codex \
  --workspace "$PWD" \
  --provider aws \
  --account 123456789012 \
  --environment production \
  --resource-prefix arn:aws: \
  --enforcement hook_enforced \
  --credential-mode attach \
  --policy-ttl 300 \
  --rules ./examples/aws-read-only-rules.json
```

Example rules file for an intentionally read-only acceptance session:

```json
[
  {
    "id": "allow-aws-inventory-read",
    "effect": "allow",
    "providers": ["aws"],
    "operations": ["aws.sts.GetCallerIdentity", "aws.ec2.DescribeInstances"],
    "resource_prefixes": ["arn:aws:"],
    "reason": "approved read-only acceptance scope"
  }
]
```

Unmatched actions fail closed. Deny and stop rules take precedence over allow
rules.

## Launch an agent

Extra arguments after `--` are passed to the native CLI:

```sh
./bin/misconfig run --profile "AWS production reads" -- exec \
  --sandbox workspace-write \
  -c sandbox_workspace_write.network_access=true \
  -c approval_policy='never' \
  "Run aws sts get-caller-identity once, report the account, then stop."
```

The parent runtime fetches and verifies the initial signed policy, then starts
the native agent with session-scoped hooks. Synchronous pre/post hooks perform
no network calls. They read only atomically refreshed local state, make a
deterministic decision, and append a local receipt. The parent refreshes policy
and remote-stop state and replays receipts asynchronously.

Codex is launched with `--dangerously-bypass-hook-trust` because this wrapper
constructs the exact absolute hook command itself. That flag bypasses Codex's
hook-source trust prompt; it does not grant Misconfig broader infrastructure
authority or replace the selected Codex sandbox and approval mode.

## Inspect or remove

```sh
./bin/misconfig profile list
./bin/misconfig status
./bin/misconfig status --json
./bin/misconfig uninstall --yes
```

Uninstall stops active sessions from this device, removes its local credential,
and deletes its local Misconfig state. Hosted session receipts remain retained.

## Current enforcement boundary

Attach mode is a bypassable local guardrail. A process or user holding the same
AWS or Kubernetes credential outside the governed agent can still act directly.
Credential-brokered and typed execution are separate future enforcement levels;
the console must not label this release as either one.
