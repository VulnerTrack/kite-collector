# Signed pacman repository

Vendor binary repo for `kite-collector`, sibling of `packaging/apt`.
Clients install with `pacman -S kite-collector` instead of building the
AUR PKGBUILD. The package itself is still defined by
[apps/kite-collector-aur](../../../kite-collector-aur/PKGBUILD).

The published tree is stateless: `os/` is the pool, regenerated every run
by `scripts/publish-pacman-repo.sh` the same way `publish-apt-repo.sh`
regenerates `pool/` + `dists/`. Both archives share GitHub Pages
(`https://vulnertrack.github.io/kite-collector/`) and the same signing key
(`repository.key`).

## Client install

```sh
curl -fsSL https://vulnertrack.github.io/kite-collector/repository.key \
  | sudo pacman-key --add -
sudo pacman-key --finger KEYID          # verify out of band
sudo pacman-key --lsign-key KEYID

sudo tee -a /etc/pacman.conf <<'EOF'

[vulnertrack]
SigLevel = Required TrustedOnly
Server = https://vulnertrack.github.io/kite-collector/os/$arch
EOF

sudo pacman -Syu kite-collector
```

`Required TrustedOnly` is the right `SigLevel`. Do not use `Never` or
`TrustAll`.

## Maintainer publish

Arch only (`repo-add`, `vercmp`, `bsdtar`, `makepkg`). Reuses
`GPG_PRIVATE_KEY` / `APT_SIGN_KEY` from the APT repo.

```sh
# 1. build a signed package from the AUR PKGBUILD
cd ../kite-collector-aur
makepkg --cleanbuild --syncdeps --sign

# 2. index it onto the published os/ tree
cd ../kite-collector
./scripts/publish-pacman-repo.sh \
  --out public \
  --pkg-dir ../kite-collector-aur \
  --pool-from /tmp/gh-pages \
  --sign-key "$APT_SIGN_KEY"
```

From the AUR directory the wrapper does both steps:

```sh
./packaging/pacman/publish.sh --out public --pool-from /tmp/gh-pages --sign-key "$APT_SIGN_KEY"
```

Layout written under `--out`:

```
os/x86_64/kite-collector-*.pkg.tar.zst{,.sig}
os/x86_64/vulnertrack.db.tar.zst{,.sig}
os/aarch64/…
repository.key
vulnertrack.pacman.conf
```

`--keep 3` (default) is a serving window, not an archive: GitHub Release
assets keep every version. Same bound as the APT pool, and the same
reason — GitHub Pages is not an artifact store.

Do not `git add` `packaging/` when pushing the AUR-shaped repo to
`aur.archlinux.org`. Explicitly add `PKGBUILD`, `.SRCINFO`, the unit, the
drop-in, and the `.install` file.
