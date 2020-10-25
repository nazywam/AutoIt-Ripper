import argparse
import logging
import sys
from os.path import basename
from pathlib import Path
from typing import Optional

from autoit_unpack import unpack_ea05, unpack_ea06

logging.basicConfig()
log = logging.getLogger()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="input binary")
    parser.add_argument("output", help="output directory")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--ea",
        default="guess",
        choices=["EA05", "EA06", "guess"],
        help="extract a specific version of AutoIt script (default: %(default)s)",
    )

    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.WARNING)

    if args.ea in ("EA05", "guess"):
        data = unpack_ea05(args.file)
    if not data and args.ea in ("EA06", "guess"):
        data = unpack_ea06(args.file)

    if data:
        output = Path(args.output)
        if not output.is_dir():
            log.debug("The output directory doesn't exist, creating it")
            output.mkdir()

        for filename, content in data:
            # better safe than sorry ¯\_(ツ)_/¯
            filename = basename(filename)
            (output / filename).write_bytes(content)


if __name__ == "__main__":
    main()
