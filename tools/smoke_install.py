"""Exercise an installed package with an isolated home and no live account/network."""
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python", type=Path, help="Python inside a fresh wheel-installed virtualenv")
    args = parser.parse_args()
    executable = str(args.python.absolute())
    with tempfile.TemporaryDirectory() as temp:
        env = {"PATH": os.defpath, "HOME": temp, "ETSY_OAUTH_HOME": temp,
               "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C.UTF-8"}

        def run(arguments):
            return subprocess.run(arguments, cwd=temp, env=env, capture_output=True, text=True)

        result = run([executable, "-I", "-c",
                      "from pathlib import Path; import sys, etsy_oauth_pkce as p; "
                      "assert Path(p.__file__).is_relative_to(Path(sys.prefix)); "
                      "assert p.EtsySession and p.FileTokenStore; print(p.__version__)"])
        assert result.returncode == 0, "installed import failed"
        console = str(Path(executable).parent / "etsy-oauth")
        assert run([console, "--help"]).returncode == 0, "console entry point failed"
        result = run([executable, "-I", "-m", "etsy_oauth_pkce", "--home", temp, "status"])
        assert result.returncode == 1 and json.loads(result.stdout)["authorized"] is False
        result = run([executable, "-I", "-m", "etsy_oauth_pkce", "--home", temp, "doctor", "--offline"])
        assert result.returncode == 1 and "skipped (--offline)" in result.stdout
        assert not (Path(temp) / "token.json").exists()
        assert not (Path(temp) / "credentials.json").exists()
    print("installed import, console, unauthorized status and offline doctor passed")


if __name__ == "__main__":
    main()
