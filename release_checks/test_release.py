import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_release import ReleaseError, archive_files, check_history, check_tree, manifest, scan


class ReleaseChecks(unittest.TestCase):
    def test_scanner_reports_location_without_the_secret(self):
        secret = "SYNTHETIC_" + "x" * 40
        for data in (
            ('access_token = "123.' + secret + '"').encode(),
            ('https://localhost/cb?code=' + secret).encode(),
            ('http://user:' + secret + '@proxy.example').encode(),
            ('-----BEGIN ' + 'PRIVATE KEY-----').encode(),
            ('/ho' + 'me/alice/private/').encode(),
        ):
            findings = scan("example.txt", data)
            self.assertTrue(findings)
            self.assertNotIn(secret, str(findings))
            self.assertTrue(all(value.startswith("example.txt:1:") for value in findings))

    def test_manifest_rejects_traversal_and_duplicates(self):
        for text in ("../private.txt", "/absolute", "a\na\n", ""):
            with self.assertRaises(ReleaseError):
                manifest(text)

    def test_tree_rejects_unknown_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "release-files.txt").write_text("release-files.txt\nREADME.md\n")
            (root / "README.md").write_text("safe")
            self.assertEqual(len(check_tree(root)), 2)
            (root / "extra.txt").write_text("not public")
            with self.assertRaisesRegex(ReleaseError, "not-allowlisted"):
                check_tree(root)
            (root / "extra.txt").unlink()
            (root / "README.md").unlink()
            (root / "README.md").symlink_to(root / "release-files.txt")
            with self.assertRaisesRegex(ReleaseError, "symlink"):
                check_tree(root)

    def test_archive_traversal_and_links_are_rejected_without_extracting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wheel = root / "bad.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("../private", "fake")
            with self.assertRaises(ReleaseError):
                archive_files(wheel)
            sdist = root / "bad.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                member = tarfile.TarInfo("root/link")
                member.type = tarfile.SYMTYPE
                member.linkname = "../private"
                archive.addfile(member)
            with self.assertRaises(ReleaseError):
                archive_files(sdist)

    def test_deleted_private_file_is_still_detected_in_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)

            git("init", "-b", "main")
            git("config", "user.name", "Synthetic Test")
            git("config", "user.email", "test@example.invalid")
            git("config", "commit.gpgsign", "false")
            (root / "release-files.txt").write_text("release-files.txt\nREADME.md\n")
            (root / "README.md").write_text("safe")
            (root / "private.txt").write_text("synthetic private content")
            git("add", ".")
            git("commit", "-m", "synthetic old commit")
            git("rm", "private.txt")
            git("commit", "-m", "remove file")
            with self.assertRaisesRegex(ReleaseError, "unexpected-history-entry"):
                check_history(root)

class ArtifactChecks(unittest.TestCase):
    def test_wheel_rejects_added_files_and_modified_source(self):
        from check_release import check_artifact
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src/etsy_oauth_pkce").mkdir(parents=True)
            (root / "src/etsy_oauth_pkce/__init__.py").write_text('value = "synthetic"\n')
            (root / "LICENSE").write_text("synthetic license")
            (root / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n')
            (root / "release-files.txt").write_text("release-files.txt\nLICENSE\npyproject.toml\nsrc/etsy_oauth_pkce/__init__.py\n")
            prefix = "etsy_oauth_pkce-0.1.0.dist-info/"
            members = {"etsy_oauth_pkce/__init__.py": 'value = "synthetic"\n', prefix + "licenses/LICENSE": "synthetic license"}
            members.update({prefix + name: "" for name in ("METADATA", "WHEEL", "entry_points.txt", "RECORD")})
            wheel = root / "synthetic.whl"

            def write(values):
                with zipfile.ZipFile(wheel, "w") as archive:
                    for name, value in values.items():
                        archive.writestr(name, value)

            write(members)
            check_artifact(wheel, root)
            write({**members, "credentials.json": "synthetic"})
            with self.assertRaisesRegex(ReleaseError, "member mismatch"):
                check_artifact(wheel, root)
            write({**members, "etsy_oauth_pkce/__init__.py": "tampered"})
            with self.assertRaisesRegex(ReleaseError, "source-content-mismatch"):
                check_artifact(wheel, root)
