# osquery embed payload (RFC-0156)

This directory is the `go:embed` root for the self-contained Windows installer
variant (`kite-collector-osquery_windows_amd64.exe`). Everything in it except
this file is **build output**, staged by:

```bash
bash scripts/stage-osquery-embed.sh
```

which downloads the pinned osquery MSI (`scripts/osquery-pin.env`), verifies
its SHA256 fail-closed, harvests the payload with `msiextract`, and writes:

```
manifest.json                  # pin + per-file digests, read at install time
osquery/osqueryd/osqueryd.exe  # the daemon registered as the kite-osqueryd service
osquery/certs/certs.pem        # upstream TLS roots
osquery/osquery.conf           # our config (configs/osquery/)
osquery/osquery.flags          # our behavioral flags (configs/osquery/)
osquery/packs/*.conf           # Windows-relevant community packs
```

The staged tree is gitignored — a ~55 MB third-party binary does not belong in
source control, and committing it would defeat the whole point of pinning it by
checksum.

This README is committed on purpose: `//go:embed osquerypayload/payload` fails
at compile time when a pattern matches nothing, so keeping one always-present
file lets `go vet -tags osquery_bundle ./...` and IDE tooling load the package
in an unstaged checkout. An unstaged build still cannot install anything —
`installer.VerifyBundle()` fails closed on the missing `manifest.json`.

Only the `osquery/` subtree is covered by `manifest.json`; this file and the
manifest itself are not self-referential.
