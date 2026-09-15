# Changelog

## Unreleased

- Send container identity hashes (full container id, image id, registry image digest) and a per-machine service inventory (Active Directory, databases, caches, queues, …) on machine telemetry events; contract v1.2. Services come from container images and ports, network banners, the local host's listeners, and AD domain-controller roles / SPNs.
- Carry incoming interfaces and software through the dedup merge so an existing machine's inventory is refreshed instead of silently dropped.
- Enroll over SSH with a temporary code approved on another computer.
- Select browser login locally and Device Authorization over SSH with `kite-collector enroll`.
- Save certificate-based enrollment without retaining the device access token.
