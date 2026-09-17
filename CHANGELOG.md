# Changelog

## Unreleased

- Every OTLP log record now carries its own Ed25519 signature: `kite.record.signature`, the signing agent's `kite.record.signer.fingerprint` (the identity fingerprint), and `kite.record.signature.alg`. The signature covers the record's canonical form so a receiver can verify each record after the batch has been unwrapped, split, or stored; telemetry contract v1.3 (additive). Verifier: `internal/telemetry/recordsig`.
- `kite-collector doctor` (alias `check`) now records its connectivity outcome on the enrolled identity, so `kite-collector status` stops reporting "no connection check has run yet" after a check from the CLI. Previously only the dashboard's "Run check" button set that stamp.
- Packages and the one-line installer keep `/usr/local/bin/kite-collector` valid as a symlink to `/usr/bin/kite-collector` on every install, so a shell that cached the old path keeps working instead of failing with "No such file or directory". A binary-method copy left there by an earlier run of the installer is replaced so it no longer shadows the package.
- The deb/rpm packages now enable the `kite-collector` systemd unit on install (started once the host is enrolled), so apt/dnf alone registers the service. The one-line installer only passes `--no-enroll` to releases that know the flag, so a newer script against an older release no longer fails registration.
- Timestamps the CLI prints (`status`, `doctor`, `scan` tables, the HTML report) and the dashboard renders now name the host's IANA time zone, for example `2026-09-16 11:52:03 America/Los_Angeles`, instead of UTC or a `PDT`/`MST` abbreviation. JSON, CSV, and export files keep RFC 3339.
- `kite-collector scan --source <name>` now enables the named discovery sources; the flag was parsed and then ignored. A name that is not a registered source prints a warning.
- The one-line installer prefers `kite-collector-osquery` wherever it is published: a default re-run now replaces a plain `kite-collector` with the bundle (`KITE_OSQUERY=no` keeps the plain collector).
- CLI and dashboard counts read "1 machine" / "2 machines" instead of "1 machines" or "1 machine(s)".
- The one-line installer now registers the background service itself and ends with a single next step: `sudo kite-collector enroll`. A flag-less `kite-collector install` on a terminal signs in too, so it registers, enrolls, and starts in one command; `--no-enroll` keeps the old register-only behavior for scripts.
- Send container identity hashes (full container id, image id, registry image digest) and a per-machine service inventory (Active Directory, databases, caches, queues, …) on machine telemetry events; contract v1.2. Services come from container images and ports, network banners, the local host's listeners, and AD domain-controller roles / SPNs.
- Carry incoming interfaces and software through the dedup merge so an existing machine's inventory is refreshed instead of silently dropped.
- Enroll over SSH with a temporary code approved on another computer.
- Select browser login locally and Device Authorization over SSH with `kite-collector enroll`.
- Save certificate-based enrollment without retaining the device access token.
