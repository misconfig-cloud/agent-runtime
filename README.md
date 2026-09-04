# Misconfig agent runtime

The local enforcement runtime for governed Codex and Claude infrastructure
sessions.

The runtime will own browser login, device identity, agent discovery, immutable
session profiles, native hook evaluation, signed policy caching, local receipt
spooling and short-lived credential overlays. It never uploads long-lived
customer credentials.

Current foundation commands:

```sh
go run ./cmd/misconfig version
go run ./cmd/misconfig doctor
```

This repository is an early foundation and is not yet an enforcement release.
Attach-mode discovery remains bypassable until credential brokering is shipped.
