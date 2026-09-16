# Changelog

## Unreleased

- The one-line installer prefers `kite-collector-osquery` wherever it is published: a default re-run now replaces a plain `kite-collector` with the bundle (`KITE_OSQUERY=no` keeps the plain collector).
- CLI and dashboard counts read "1 machine" / "2 machines" instead of "1 machines" or "1 machine(s)".
- The one-line installer now registers the background service itself and ends with a single next step: `sudo kite-collector enroll`. A flag-less `kite-collector install` on a terminal signs in too, so it registers, enrolls, and starts in one command; `--no-enroll` keeps the old register-only behavior for scripts.
- Send container identity hashes (full container id, image id, registry image digest) and a per-machine service inventory (Active Directory, databases, caches, queues, …) on machine telemetry events; contract v1.2. Services come from container images and ports, network banners, the local host's listeners, and AD domain-controller roles / SPNs.
- Carry incoming interfaces and software through the dedup merge so an existing machine's inventory is refreshed instead of silently dropped.
- Enroll over SSH with a temporary code approved on another computer.
- Select browser login locally and Device Authorization over SSH with `kite-collector enroll`.
- Save certificate-based enrollment without retaining the device access token.
