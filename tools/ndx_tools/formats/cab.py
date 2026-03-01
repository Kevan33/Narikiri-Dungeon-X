import subprocess
import sys
from pathlib import Path

import ndx_tools.project.paths as ndx_paths

_IS_LINUX = sys.platform.startswith("linux")
_EXE = ndx_paths.binaries / "CabArc.exe"
_CMD_EXTRACT = [_EXE]
_CMD_EXTRACT += ["-o", "-p"]
_CMD_MAKE = [_EXE]
_CMD_MAKE += ["-m", "LZX:15", "-i", "4392", "-s", "8"]


def _check_wibo() -> None:
    try:
        subprocess.run(["wibo"])
    except FileNotFoundError:
        print("ERROR: wibo does not appear to be accessible")
        print("To install it, please download it and put it in your PATH:")
        print(
            "  wget https://github.com/decompals/wibo/releases/download/1.0.0/wibo-x86_64 && chmod +x wibo-x86_64 && sudo mv wibo-x86_64 /usr/bin/wibo"
        )
        sys.exit(-1)


if _IS_LINUX:
    _check_wibo()
    _CMD_EXTRACT = ["wibo"] + _CMD_EXTRACT
    _CMD_MAKE = ["wibo"] + _CMD_MAKE


def extract_cab(input: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        _CMD_EXTRACT + ["X", str(input), str(output) + "\\"],
        stdout=subprocess.DEVNULL,
    )


def make_cab(input: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        _CMD_MAKE + ["N", str(output), str(input) + "*"],
        stdout=subprocess.DEVNULL,
    )


def make_cab_list(inputs: list[Path], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)

    files = [str(x) for x in inputs]
    subprocess.run(
        _CMD_MAKE + ["N", str(output)] + files,
        stdout=subprocess.DEVNULL,
    )
