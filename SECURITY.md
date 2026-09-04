# Security

Report vulnerabilities privately to contact@misconfig.cloud.

## Current trust boundary

- Native Codex and Claude hooks are local, bypassable guardrails.
- Synchronous pre/post hooks never depend on the network. Missing, malformed,
  expired, incorrectly signed, or identity-mismatched state fails closed.
- The parent runtime refreshes remote session state and signed policies outside
  the hook deadline. Remote stop cancels the launched agent process.
- Device credentials and customer infrastructure credentials are never sent to
  hook stdout or embedded in agent configuration.
- Raw provider output and transcripts are not uploaded. Receipts contain
  bounded action metadata and a digest of supported structured results.
- Codex Bash output in the currently supported native hook version has no
  trustworthy exit code. It is retained as observed activity, never invented
  as verified success.
- Release archives contain no enrollment token or customer credential. The
  release manifest pins source identity, platform, byte size, and SHA-256 for
  every artifact plus the compatibility manifest and SPDX SBOM. Installation
  is verified and atomic, with rollback to the previous binary on failed
  post-install verification. Public releases carry a keyless Sigstore bundle
  over `checksums.txt` and GitHub build provenance over every shipped artifact.
  Customers must verify both the bundle and the selected archive checksum.

## What this release does not claim

Attach mode cannot prevent use of the same AWS, Kubernetes, or SaaS credential
outside the governed process. Hard enforcement requires short-lived brokered
credentials or an exact typed execution capability with independent provider
verification. Neither claim may be inferred from a successful native-hook test.

The runtime does not perform generic TLS interception, store long-lived cloud
credentials, retain chain-of-thought, or treat a model statement as provider
proof.
