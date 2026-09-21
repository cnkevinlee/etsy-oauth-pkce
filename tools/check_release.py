"""Audit allowlisted source and distributions. Reports locations/rules, never matched values."""
from __future__ import annotations

import argparse
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

RULES = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "credential-pair": re.compile(r"\b[A-Za-z0-9]{24,}:[A-Za-z0-9]{10,}\b"),
    "account-id-literal": re.compile(r'''(?i)(?:user_id|shop_id|receipt_id|listing_id)["']?\s*[:=]\s*["']?\d{4,}\b'''),
    "token-shape": re.compile(r"\b\d+\.[A-Za-z0-9_-]{30,}\b"),
    "credential-literal": re.compile(r'''(?i)(?:access_token|refresh_token|api_key|shared_secret|code_verifier)["']?\s*[:=]\s*["'][A-Za-z0-9_.:/+\-=]{24,}["']'''),
    "proxy-userinfo": re.compile(r"https?://[^\s/@:]+:[^\s/@]{24,}@"),
    "callback-code": re.compile(r"[?&]code=[A-Za-z0-9_-]{24,}"),
    "personal-home": re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+/"),
    "internal-link": re.compile(r"https?://[^\s/]*(?:feishu\.cn|larksuite\.com|claude\.ai)/"),
}
MAX_FILE_BYTES = 2 * 1024 * 1024


class ReleaseError(Exception):
    pass


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or not path.parts or any(ord(c) < 32 for c in name):
        raise ReleaseError("invalid file path (value omitted)")
    return path.as_posix()


def manifest(raw: str) -> set[str]:
    names = [safe_name(line.strip()) for line in raw.splitlines() if line.strip() and not line.startswith("#")]
    if len(names) != len(set(names)) or not names:
        raise ReleaseError("empty or duplicate release file list")
    return set(names)


def scan(name: str, data: bytes, private_terms: tuple[str, ...] = ()) -> list[str]:
    if len(data) > MAX_FILE_BYTES:
        return [f"{name}:1:size-limit"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{name}:1:unexpected-binary"]
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for rule, pattern in RULES.items():
            if pattern.search(line):
                findings.append(f"{name}:{number}:{rule}")
        if any(term.lower() in line.lower() for term in private_terms):
            findings.append(f"{name}:{number}:private-project-reference")
    return findings


def require_clean(findings: list[str]) -> None:
    if findings:
        raise ReleaseError("\n".join(findings))


def check_tree(root: Path, private_terms: tuple[str, ...] = ()) -> dict[str, bytes]:
    allowed = manifest((root / "release-files.txt").read_text())
    files = {}
    for path in root.rglob("*"):
        name = path.relative_to(root).as_posix()
        if name == ".git" or name.startswith(".git/"):
            continue
        if path.is_symlink():
            raise ReleaseError(f"{name}:1:symlink")
        if path.is_file():
            if name not in allowed:
                raise ReleaseError(f"{name}:1:not-allowlisted")
            files[name] = path.read_bytes()
    if set(files) != allowed:
        raise ReleaseError("release manifest contains missing files")
    require_clean([finding for name, data in files.items() for finding in scan(name, data, private_terms)])
    return files


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    if result.returncode:
        raise ReleaseError("Git inspection failed (details omitted)")
    return result.stdout


def check_history(root: Path, private_terms: tuple[str, ...] = ()) -> None:
    """Scan every reachable commit and blob; old private files cannot hide behind deletion."""
    scanned = set()
    for commit in git(root, "rev-list", "--all").decode().splitlines():
        allowed = manifest(git(root, "show", f"{commit}:release-files.txt").decode())
        require_clean(scan("git-commit", git(root, "cat-file", "commit", commit), private_terms))
        for entry in git(root, "ls-tree", "-rz", commit).split(b"\0"):
            if not entry:
                continue
            info, raw_name = entry.split(b"\t", 1)
            mode, kind, oid = info.decode().split()
            name = safe_name(raw_name.decode())
            if name not in allowed or mode not in {"100644", "100755"} or kind != "blob":
                raise ReleaseError(f"{name}:1:unexpected-history-entry")
            if oid not in scanned:
                require_clean(scan(name, git(root, "cat-file", "blob", oid), private_terms))
                scanned.add(oid)


def archive_files(path: Path) -> dict[str, bytes]:
    files = {}
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                name = safe_name(member.filename)
                if member.is_dir():
                    continue
                if member.file_size > MAX_FILE_BYTES or (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ReleaseError("invalid wheel member")
                if name in files:
                    raise ReleaseError("duplicate archive member")
                files[name] = archive.read(member)
    else:
        with tarfile.open(path, "r:gz") as archive:
            roots = set()
            for member in archive.getmembers():
                full = PurePosixPath(safe_name(member.name))
                roots.add(full.parts[0])
                if member.isdir():
                    continue
                if not member.isfile() or member.size > MAX_FILE_BYTES or len(full.parts) < 2:
                    raise ReleaseError("invalid source distribution member")
                name = full.relative_to(full.parts[0]).as_posix()
                if name in files:
                    raise ReleaseError("duplicate archive member")
                files[name] = archive.extractfile(member).read()
            if len(roots) != 1:
                raise ReleaseError("source distribution must have one root")
    return files


def check_artifact(path: Path, root: Path, private_terms: tuple[str, ...] = ()) -> dict[str, bytes]:
    source = {name: (root / name).read_bytes() for name in manifest((root / "release-files.txt").read_text())}
    files = archive_files(path)
    # Both member names and the bytes of copied source must match; metadata is checked separately.
    if path.suffix == ".whl":
        expected = {name.removeprefix("src/"): data for name, data in source.items() if name.startswith("src/")}
        metadata = {"METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD", "licenses/LICENSE"}
        version = __import__("tomllib").loads(source["pyproject.toml"].decode())["project"]["version"]
        prefix = f"etsy_oauth_pkce-{version}.dist-info/"
        generated = {prefix + name for name in metadata}
        expected[prefix + "licenses/LICENSE"] = source["LICENSE"]
        required = {prefix + name for name in ("METADATA", "WHEEL", "entry_points.txt", "RECORD")}
    else:
        expected = {name: data for name, data in source.items()
                    if name.startswith(("src/", "tests/")) or name in {"README.md", "LICENSE", "pyproject.toml", "MANIFEST.in"}}
        generated = {"PKG-INFO", "setup.cfg"} | {"src/etsy_oauth_pkce.egg-info/" + name for name in
                     ("PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "top_level.txt")}
        required = {"PKG-INFO"}
    unexpected = set(files) - set(expected) - generated
    missing = (set(expected) | required) - set(files)
    if unexpected or missing:
        raise ReleaseError("archive member mismatch: " + ", ".join(sorted(unexpected | missing)))
    for name, data in expected.items():
        if files[name] != data:
            raise ReleaseError(f"{name}:1:source-content-mismatch")
    require_clean([finding for name, data in files.items() for finding in scan(name, data, private_terms)])
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--artifacts", type=Path, nargs="*")
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    try:
        if args.artifacts is None:
            files = check_tree(args.root)
            print(f"source: {len(files)} allowlisted files checked")
        else:
            if not args.artifacts:
                raise ReleaseError("no artifacts supplied")
            for path in args.artifacts:
                files = check_artifact(path, args.root)
                print(f"{path.name}: {len(files)} members checked")
        if args.history:
            check_history(args.root)
            print("reachable Git history checked")
    except (ReleaseError, OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        if isinstance(exc, ReleaseError):
            parser.exit(1, f"{exc}\n")
        parser.exit(1, "release inspection failed (details omitted)\n")


if __name__ == "__main__":
    main()
