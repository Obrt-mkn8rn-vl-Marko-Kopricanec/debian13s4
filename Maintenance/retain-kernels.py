"""Remove one obsolete automatic Debian kernel image, retaining boot choices."""

from functools import cmp_to_key
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


POLICY = Path("/usr/local/lib/debian13s4/maintenance/policy.conf")
TRUSTED_UID = 0
KEEP = 3
IMAGE = re.compile(
    r"linux-image-(?P<release>[1-9][0-9]*\.[0-9]+\.[0-9]+"
    r"(?:-[0-9]+|\+deb13)-(?P<flavour>(?:cloud-|rt-)?(?:amd64|arm64)))\Z"
)


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise RuntimeError("noncanonical kernel maintenance path")
    leaf = True
    while True:
        info = path.lstat()
        kind = stat.S_ISDIR if directory or not leaf else stat.S_ISREG
        if info.st_uid != TRUSTED_UID or info.st_mode & 0o022 or not kind(info.st_mode):
            raise RuntimeError("untrusted kernel maintenance path: " + str(path))
        if path == path.parent:
            return
        path, leaf = path.parent, False


def configured(package):
    import apt_pkg
    return (package.is_installed and
            package._pkg.current_state == apt_pkg.CURSTATE_INSTALLED and
            package._pkg.inst_state == apt_pkg.INSTSTATE_OK)


def select(cache, running):
    import apt_pkg
    if cache.broken_count or cache.dpkg_journal_dirty or cache.get_changes():
        raise RuntimeError("kernel cleanup requires a clean package state")
    images = [p for p in cache if p.is_installed and IMAGE.fullmatch(p.name)]
    current = [p for p in images if IMAGE.fullmatch(p.name)["release"] == running]
    if not current or any(not configured(p) for p in images):
        raise RuntimeError("running/installed kernel identities are unverifiable")
    flavour = IMAGE.fullmatch(current[0].name)["flavour"]
    meta = cache.get("linux-image-" + flavour)
    if meta is None or not configured(meta):
        raise RuntimeError("missing configured kernel metapackage")
    protected = {p.name for p in current} | {meta.name}
    for group in {IMAGE.fullmatch(p.name)["flavour"] for p in images}:
        versions = {p.installed.version for p in images if IMAGE.fullmatch(p.name)["flavour"] == group}
        latest = set(sorted(versions, key=cmp_to_key(apt_pkg.version_compare), reverse=True)[:KEEP])
        protected.update(p.name for p in images
                         if IMAGE.fullmatch(p.name)["flavour"] == group and p.installed.version in latest)
    candidates = [p for p in images if p.name not in protected and p.is_auto_installed and
                  p.is_auto_removable and p._pkg.selected_state == apt_pkg.SELSTATE_INSTALL and
                  not p.essential and p.installed.priority not in ("required", "important")]
    candidates.sort(key=cmp_to_key(lambda a, b: apt_pkg.version_compare(a.installed.version, b.installed.version)))
    retained = {name: cache[name].installed.version for name in protected}
    for package in candidates:
        # No resolver: a removal needing reverse dependencies or any other
        # transaction is deferred rather than broadening the removal scope.
        package.mark_delete(auto_fix=False, purge=False)
        changes = cache.get_changes()
        if (not cache.broken_count and cache.install_count == 0 and cache.delete_count == 1 and
                len(changes) == 1 and changes[0].name == package.name and changes[0].marked_delete):
            return package.name, retained
        cache.clear()
    return None, retained


def audit():
    result = subprocess.run(["/usr/bin/dpkg", "--audit"], capture_output=True, timeout=10, check=True)
    if result.stdout or result.stderr:
        raise RuntimeError("kernel cleanup requires an empty dpkg audit")


def transact(cache, running, apply):
    name, retained = select(cache, running)
    if name is None:
        return 0, {"removed": None, "pending": False}
    if not apply:
        return 0, {"selected": name, "retained": sorted(retained)}
    # The caller holds SystemLock from cache creation through postconditions.
    # Native commit drops/reacquires only the inner dpkg lock when required.
    if not cache.commit(allow_unauthenticated=False):
        raise RuntimeError("native kernel removal failed")
    cache.open()
    audit()
    if cache.dpkg_journal_dirty or cache.broken_count:
        raise RuntimeError("kernel removal left incomplete package state")
    if name in cache and cache[name].is_installed:
        raise RuntimeError("native kernel removal did not remove its target")
    for identity, version in retained.items():
        if identity not in cache or not configured(cache[identity]) or cache[identity].installed.version != version:
            raise RuntimeError("kernel removal changed a retained boot choice")
    next_name, _ = select(cache, running)
    cache.clear()
    return (75 if next_name else 0), {"removed": name, "pending": next_name is not None}


def main():
    if sys.argv[1:] not in (["--plan"], ["--apply"]):
        raise RuntimeError("expected --plan or --apply")
    apply = sys.argv[1] == "--apply"
    if apply and os.geteuid() != TRUSTED_UID:
        raise RuntimeError("kernel removal requires the trusted owner")
    trusted(POLICY)
    if os.environ.get("APT_CONFIG") != str(POLICY):
        raise RuntimeError("unexpected kernel APT profile")
    import apt
    import apt_pkg
    config = apt_pkg.config
    if (not config.find_b("APT::Protect-Kernels", False) or
            config.find("APT::NeverAutoRemove::KernelCount") or
            config.value_list("APT::VersionedKernelPackages") != ["linux-image"] or
            config.find_b("Debug::NoLocking", True) or
            config.find("Dir::Etc::parts") or config.find("Dir::Etc::main")):
        raise RuntimeError("unverified kernel protection configuration")
    status = Path(config.find_file("Dir::State::status"))
    trusted(status)
    trusted(status.parent, directory=True)
    extended = Path(config.find_file("Dir::State::extended_states"))
    trusted(extended.parent, directory=True)
    if extended.exists() or extended.is_symlink():
        trusted(extended)
    # --plan only reads native caches; it never enters a package-system lock or
    # commit. Production --apply takes the native lock BEFORE loading the cache.
    if apply:
        with apt_pkg.SystemLock():
            audit()
            result, message = transact(apt.Cache(memonly=True), os.uname().release, True)
    else:
        result, message = transact(apt.Cache(memonly=True), os.uname().release, False)
    print(json.dumps(message, sort_keys=True))
    return result


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print("debian13s4 kernel retention: " + str(error), file=sys.stderr)
        sys.exit(1)
