"""Assemble the deterministic, offline-capable starting script."""

import argparse
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def assets():
    result = {
        "lib/repair.sh": ((ROOT / "Recovery/repair.sh").read_bytes(), "0755"),
        "lib/tasks.list": (b"prerequisites:\nnetwork:prerequisites\nhardening:prerequisites\nretention:prerequisites\nmaintenance:prerequisites\ndotnet:prerequisites\n", "0644"),
    }
    for name in ("apply.sh", "verify.sh", "common.sh", "debian.sources"):
        result[f"lib/tasks/prerequisites/{name}"] = (
            (ROOT / "Tasks/prerequisites" / name).read_bytes(), "0644")
    for name in ("debian13s4-repair.service", "debian13s4-repair.timer",
                 "debian13s4-resume.service"):
        result[f"units/{name}"] = ((ROOT / "Recovery" / name).read_bytes(), "0644")
    for name in ("common.sh", "update.sh", "policy.conf", "needrestart.conf", "restart-policy.pl", "retain-kernels.py",
                 "debian13s4-maintenance.service", "debian13s4-maintenance.timer"):
        result[f"lib/maintenance/{name}"] = (
            (ROOT / "Maintenance" / name).read_bytes(), "0755" if name == "update.sh" else "0644")
    for name in ("apply.sh", "verify.sh"):
        result[f"lib/tasks/maintenance/{name}"] = (
            (ROOT / "Tasks/maintenance" / name).read_bytes(), "0644")
    for name in ("common.sh", "update.sh", "verify-payload.pl", "policy.conf", "preferences",
                 "microsoft-2025.asc", "debian13s4-dotnet.service", "debian13s4-dotnet.timer"):
        result[f"lib/dotnet/{name}"] = (
            (ROOT / "Dotnet" / name).read_bytes(), "0755" if name == "update.sh" else "0644")
    result["lib/dotnet/sources.sources"] = (
        (ROOT / "Tasks/prerequisites/debian.sources").read_bytes() + b"\n" +
        (ROOT / "Dotnet/microsoft.sources").read_bytes(), "0644")
    for name in ("apply.sh", "verify.sh"):
        result[f"lib/tasks/dotnet/{name}"] = (
            (ROOT / "Tasks/dotnet" / name).read_bytes(), "0644")
    for name in ("common.sh", "repair.sh", "verify.py", "network.conf",
                 "debian13s4-network.service", "debian13s4-network.timer"):
        result[f"lib/network/{name}"] = (
            (ROOT / "Network" / name).read_bytes(), "0755" if name == "repair.sh" else "0644")
    for name in ("apply.sh", "verify.sh"):
        result[f"lib/tasks/network/{name}"] = (
            (ROOT / "Tasks/network" / name).read_bytes(), "0644")
    for name in ("common.sh", "repair.sh", "journal.py", "clean-cache.py", "apt.conf", "journal.conf",
                 "debian13s4-retention.service", "debian13s4-retention.timer"):
        result[f"lib/retention/{name}"] = (
            (ROOT / "Retention" / name).read_bytes(), "0755" if name == "repair.sh" else "0644")
    for name in ("apply.sh", "verify.sh"):
        result[f"lib/tasks/retention/{name}"] = (
            (ROOT / "Tasks/retention" / name).read_bytes(), "0644")
    for name in ("common.sh", "repair.sh", "verify.py", "kernel.conf",
                 "debian13s4-hardening.service", "debian13s4-hardening.timer"):
        result[f"lib/hardening/{name}"] = (
            (ROOT / "Hardening" / name).read_bytes(), "0755" if name == "repair.sh" else "0644")
    for name in ("apply.sh", "verify.sh"):
        result[f"lib/tasks/hardening/{name}"] = (
            (ROOT / "Tasks/hardening" / name).read_bytes(), "0644")
    return result


def assemble():
    bundle = assets()
    identity = hashlib.sha256()
    for name, (data, mode) in bundle.items():
        identity.update(name.encode() + b"\0" + mode.encode() + b"\0" + data + b"\0")
    pieces = [(ROOT / "Bootstrap/bootstrap.sh").read_text(),
              f"\nS4B_BUNDLE_ID={identity.hexdigest()}\n",
              "S4B_FILES=(" + " ".join(bundle) + ")\n",
              "S4B_MODES=(" + " ".join(mode for _, mode in bundle.values()) + ")\n",
              "\ns4b_write_bundle() {\n    local relative\n",
              '    for relative in "${S4B_FILES[@]}"; do\n',
              '        mkdir -p -- "$S4B_STAGE/${relative%/*}" || return 1\n',
              "    done\n"]
    checks = []
    for name, (data, _) in bundle.items():
        text = data.decode("utf-8")
        if not text.endswith("\n"):
            raise ValueError(f"Bundled file lacks final newline: {name}")
        delimiter = "S4_PAYLOAD_" + hashlib.sha256(data).hexdigest()
        if delimiter in text.splitlines():
            raise ValueError(f"Payload delimiter collision: {name}")
        pieces.append(f'    cat > "$S4B_STAGE/{name}" <<\'{delimiter}\' || return 1\n')
        pieces.extend((text, delimiter + "\n"))
        checks.append(hashlib.sha256(data).hexdigest() + "  " + name + "\n")
    pieces.extend(('    cat > "$S4B_STAGE/files.sha256" <<\'S4_CHECKSUMS\' || return 1\n',
                   "".join(checks), "S4_CHECKSUMS\n}\n\n",
                   'if [[ ${BASH_SOURCE[0]} == "$0" ]]; then\n',
                   "    set -Eeuo pipefail\n    PATH=$S4B_PATH\n    export PATH\n",
                   "    umask 077\n    s4b_main \"$@\"\nfi\n"))
    return "".join(pieces).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / "setup.sh"
    data = assemble()
    if args.check:
        if not target.is_file() or target.read_bytes() != data:
            parser.exit(1, "setup.sh differs from its production sources; regenerate with pack.py\n")
    else:
        target.write_bytes(data)
        target.chmod(0o755)


if __name__ == "__main__":
    main()
