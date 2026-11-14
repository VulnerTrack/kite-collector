# Installed package provenance

Debian/Ubuntu software inventory now includes `source_package`, `source_version`,
`homepage` and the package summary. The binary name and version retain their
existing values. Dpkg records marked as removed or configuration-only are not
included in new scans. The parser also accepts older three-column fixtures.

For Perl modules listed by `cpan -l`, Kite locates the module file using the
CPAN script's Perl interpreter and queries `dpkg-query -S` for its native owner.
It checks that the owner is in the installed native inventory and attaches
`package_owner` with its own version, source identity, architecture, file path
and `dpkg-query-search` evidence. The module name, version and CPE remain intact.

File lookups do not load the inspected modules or evaluate their version code.
Queries use batches of at most 100 modules, with a 60-second deadline for the
whole optional enrichment. Shadowed module copies, ambiguous owners, interpreter wrappers,
missing commands and unowned files leave ownership unknown without discarding
the module. This first ownership adapter supports Debian/Ubuntu; it does not
infer CPAN distributions or owners for other operating systems.

The additive SQLite migration runs automatically when Kite opens its database.
Both storage paths and inventory event chunks preserve the new fields. Existing
receivers can ignore them. To use them for resolution, install the cmdb_lens v8
product migration and worker, then publish Kite and let a fresh inventory reach
the server. No new Kite configuration variable is required.

Field and ownership-query semantics are documented in
[dpkg-query](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html).

## Alpine and RPM sources

Alpine inventory now prefers `apk query --installed` JSON on APK 3. On APK 2,
it keeps `apk list --installed` and enriches matching name/version/architecture
records from the bounded, read-only installed database. Missing or unsupported
metadata leaves the list inventory intact. `origin` is recorded as
`source_package`, not `vendor`; abuild's package build version is kept in
`source_version`. URL, license and description accompany the structured records.

RPM inventory includes `SOURCERPM`, URL, license and summary. The source filename
supplies its own name/version/release, even when the binary subpackage has a
different version. Existing binary name/version/vendor fields remain unchanged.
Legacy collector output remains readable. These fields use the existing SQLite
columns and inventory transport, so no additional Kite database migration or
configuration is required.

The cmdb_lens v9 resolver uses the source identity and removes only the package
revision when looking up the upstream release. It still needs current catalog
proof and does not assert that a distro-patched build is vulnerable.

See [APK metadata](https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-package.5.scd),
[abuild's metadata generation](https://github.com/alpinelinux/abuild/blob/master/abuild.in)
and [RPM tags](https://rpm.org/docs/latest/manual/tags.html).
