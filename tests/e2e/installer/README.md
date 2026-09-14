# installer e2e: the `curl | sh` one-liner

Checks [`installers/installer.sh`](../../../installers/installer.sh) the way
users run it:

```sh
curl -fsSL https://raw.githubusercontent.com/VulnerTrack/kite-collector/main/installers/installer.sh | sh
```

Each leg is a stock distro container. It installs only a downloader, then pipes
the served script into `sh` and asserts on what the script left behind.

```sh
make test-installer                              # all legs, local fixture release
LEGS="debian alpine" ./tests/e2e/installer/run.sh
make test-installer-live                         # real latest release (post-release smoke)
```

## How local mode works

| step | where | what |
|------|-------|------|
| guards | host | `sh -n` and `shellcheck -s sh` on the installer and battery. Drift greps tie the installer's asset names, APT paths and suite to `.goreleaser.yaml`, `README.md`, `apt-ftparchive.conf` and `nfpm-osquery.yaml`. |
| build | host | `go build` of the collector as `OLD_VERSION` (1.0.0) and `NEW_VERSION` (1.1.0), packaged as deb and rpm through `packaging/deb/nfpm-collector.yaml`, with goreleaser's release asset names. |
| assemble | `debian:12` | [`fixture.sh`](fixture.sh) writes `checksums.txt`, `releases/latest/download/`, a tampered release, a stand-in `kite-collector-osquery` deb per version, and a signed APT archive from `scripts/publish-apt-repo.sh` with a throwaway key. |
| serve | `busybox httpd` | Serves the tree on a private docker network. The installer finds it through `KITE_RELEASES_URL` and `KITE_APT_URL`. |
| legs | one container each | [`battery.sh`](battery.sh), run with the image's own `sh`. |

Base images and distro package indexes still come from the internet. Kite
artifacts never do.

## What each leg asserts

| leg | image | method | extra coverage |
|-----|-------|--------|----------------|
| debian | debian:12 | apt | Default flavor is the osquery bundle. Source line and keyring match the README, one source entry after re-runs, and an unserved pinned version is refused with a hint. |
| ubuntu | ubuntu:24.04 | apt | Runs as a non-root user through `sudo`. A plain install stays plain on default re-runs, and `KITE_OSQUERY=yes`/`no` swap the flavor both ways. |
| fedora | fedora:44 | rpm | dnf5, with the osquery.io hint. |
| almalinux | almalinux:9 | rpm | dnf4. |
| opensuse | opensuse/leap:15.6 | rpm | zypper with `--allow-unsigned-rpm`. |
| alpine | alpine:3.22 | binary | busybox `wget` and ash, no curl. Refuses tampered checksums, bad env values, an unknown arch, unreachable or unknown releases, and non-root without sudo. Scripts truncated at 25/50/75% and just before `main` install nothing. Rootless install into a writable `KITE_INSTALL_DIR`. |
| arch | archlinux:latest | binary | Prints the `pacman -S osquery` hint. |

Every leg also does a pinned install of `OLD_VERSION`, an unpinned upgrade to
`NEW_VERSION`, and an idempotent re-run. It checks package-manager ownership of
`/usr/bin/kite-collector` (apt/rpm) and that no temp dirs or staging files are
left behind.

The osquery bundle in local mode is a stand-in with the real package's
`Conflicts`/`Replaces`/`Provides`. The installer only decides which package
apt gets. The real bundle's payload is covered by `make test-deb-osquery`, and
the live Debian leg installs the real bundle from the published archive.

## Live mode

`MODE=live` builds nothing. It serves only the working-tree installer and lets
it install from GitHub Releases and `vulnertrack.github.io/kite-collector`.
The debian, fedora and alpine legs assert the installed version equals the
latest release, which is read from its `checksums.txt`.

Not covered here: macOS, FreeBSD and OpenBSD (no docker runtime), and service
start under systemd (these containers have no systemd as PID 1; see
`tests/e2e/snap-install` for that pattern).
