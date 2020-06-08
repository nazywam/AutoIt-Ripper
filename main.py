from autoit_unpack import unpack_ea05, unpack_ea06
from typing import Optional
import sys
import argparse
import logging

logging.basicConfig()
log = logging.getLogger()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="input binary")
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
        if data:
            print(data)
    if args.ea in ("EA06", "guess"):
        data = unpack_ea06(args.file)
        if data:
            print(data)


if __name__ == "__main__":
    sys.exit(main())
