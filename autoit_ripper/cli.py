import argparse
import logging
import sys
from pathlib import Path, PureWindowsPath

from .autoit_unpack import AutoItVersion, extract


def main() -> int:
    logging.basicConfig()
    log = logging.getLogger()

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="input binary")
    parser.add_argument("output_dir", help="output directory")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--ea",
        default="guess",
        choices=["EA05", "EA06", "JB01", "guess"],
        help="extract a specific version of AutoIt script (default: %(default)s)",
    )

    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    with open(args.file, "rb") as f:
        file_data = f.read()

    data = None
    if args.ea in ("EA05", "guess"):
        data = extract(data=file_data, version=AutoItVersion.EA05)
    if not data and args.ea in ("EA06", "guess"):
        data = extract(data=file_data, version=AutoItVersion.EA06)
    if not data and args.ea in ("JB01", "guess"):
        data = extract(data=file_data, version=AutoItVersion.JB01)

    if data:
        output = Path(args.output_dir)
        if not output.is_dir():
            log.info("The output directory doesn't exist, creating it")
            output.mkdir()

        for filename_w, content in data:
            # We need to convert the nasty Windows path into a nice, unix one
            filename = PureWindowsPath(filename_w)
            log.info(f"Storing result in {(output / filename.name).as_posix()}")
            (output / filename.name).write_bytes(content)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
