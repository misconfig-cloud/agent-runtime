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
misconfig profile migrate
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
machine architecture. Verify the signed checksum manifest, verify only the
archive you downloaded, then extract it:

```sh
VERSION=0.1.4
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac
ARCHIVE="misconfig_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/misconfig-cloud/agent-runtime/releases/download/v${VERSION}"

curl --fail --location --remote-name "${BASE_URL}/${ARCHIVE}"
curl --fail --location --remote-name "${BASE_URL}/checksums.txt"
curl --fail --location --remote-name "${BASE_URL}/checksums.txt.sigstore.json"

cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/misconfig-cloud/agent-runtime/.github/workflows/release.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

grep "  ${ARCHIVE}$" checksums.txt | shasum -a 256 -c -
tar -xzf "${ARCHIVE}"
sudo ./install.sh
```

`checksums.txt` covers every archive, `manifest.json`, `compatibility.json`, and
the SPDX 2.3 `sbom.spdx.json`. Each published checksum manifest has a Sigstore
bundle signed by the tag-only GitHub Actions workflow. Every release artifact
also has GitHub build provenance. Verify it with:

```sh
gh attestation verify "${ARCHIVE}" -R misconfig-cloud/agent-runtime
```

The release workflow, source commit, SBOM, adapter compatibility statement,
and archive digest are therefore inspectable before installation. A signature
proves release origin and integrity; it does not replace review of the scoped
rules and credentials used by a governed session.

Pin the expected release during an install or upgrade:

```sh
sudo ./install.sh --require-version "${VERSION}" --yes
```

Installation stages and verifies the new binary in the destination directory,
then replaces the old binary atomically. If post-install verification fails,
the previous runtime is restored.

Pair the device through the authenticated browser flow. The runtime previews
every local change before it opens the one-time approval page:

```sh
misconfig setup --control https://console.misconfig.cloud
```

An operator-issued enrollment token remains available as a recovery path. Read
it from a protected file or stdin; never place it on the command line.

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
make release RELEASE_VERSION=1.2.3
make verify-release
```

The release command embeds the explicit version, strips host paths and build
IDs, fixes archive metadata to `SOURCE_DATE_EPOCH`, and emits `manifest.json`,
`compatibility.json`, an SPDX 2.3 SBOM, and `checksums.txt`. Compatibility is
stated per exact native-client version and distinguishes live acceptance from
fixture-only coverage. The builder refuses to overwrite a release by default.
Version tags are the only public release trigger. The workflow uses keyless
GitHub OIDC signing and GitHub artifact attestations; there is no long-lived
release signing key.

## Enrol one device

The default flow creates a short-lived code, opens the authenticated console,
and waits for the signed-in tenant to approve the exact device:

```sh
./bin/misconfig setup --control https://console.misconfig.cloud
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
  --resource-prefix aws://123456789012 \
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
    "resource_prefixes": ["aws://123456789012"],
    "reason": "approved read-only acceptance scope"
  }
]
```

Unmatched actions fail closed. Deny and stop rules take precedence over allow
rules.

The account-bound `aws://ACCOUNT_ID` value is the provider-neutral scope used
by the signed session contract. Do not use an ARN prefix for brokered AWS
credentials. The admitted AWS adapter will reject a scope it cannot translate
into an exact STS session policy before requesting credentials.

Profiles are immutable. If a profile was signed by an older runtime contract,
launch returns an explicit successor-required error instead of changing its
digest. Create a successor with the current adapter while retaining the old
profile and its session history:

```sh
misconfig profile migrate --profile PROFILE_ID
```

The command prints the new profile ID. Use that ID for the next launch.

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

Session profiles, signed policies, action envelopes, receipts, and credential
connection APIs treat provider identifiers as opaque values. The official
runtime currently registers the AWS credential-process adapter as a compiled
adapter; it is not part of policy evaluation or session identity.

An unfamiliar provider can use attach-mode governance without a runtime
adapter. Brokered credentials additionally require a trusted adapter compiled
and registered in the runtime binary so provider material can be isolated and
presented in its native format. This release intentionally does not load
adapter executables from disk. Independently installed adapters require a
future authenticated subprocess protocol with pinned binary identity, an
environment allowlist, typed material schemas, and explicit secret-output
rules; until that contract exists, an unknown adapter fails closed.

Attach mode is a bypassable local guardrail. A process or user holding the same
AWS or Kubernetes credential outside the governed agent can still act directly.
The compiled AWS renderer is not a released brokered provider: the control-plane
prototype refuses issuance until an admitted AWS adapter can enforce and echo
the complete signed authorization ceiling. Typed execution remains a separate
enforcement level, and attach-mode profiles must not be presented as
credential-brokered.
