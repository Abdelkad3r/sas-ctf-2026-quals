#!/usr/bin/env python3
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile


DEFAULT_ARCHIVE = pathlib.Path(__file__).with_name(
    "gav-task-d062b20a609d88406428af565e738b99.tgz"
)


def run(command: list[str], cwd: pathlib.Path) -> str:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def main() -> None:
    archive = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ARCHIVE
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="gav-task-solve-"))
    try:
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(workdir)

        repo = workdir / "sources"
        log = run(["git", "log", "--oneline", "--all"], repo)
        for line in log.splitlines():
            commit = line.split(maxsplit=1)[0]
            try:
                compose = run(["git", "show", f"{commit}:docker-compose.yaml"], repo)
            except subprocess.CalledProcessError:
                continue

            match = re.search(r"FLAG:\s*(SAS\{[^}]+\})", compose)
            if match and "REDACTED" not in match.group(1):
                print(match.group(1))
                return

        raise SystemExit("flag not found in git history")
    finally:
        shutil.rmtree(workdir)


if __name__ == "__main__":
    main()
