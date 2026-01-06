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

    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    with open(args.file, "rb") as f:
        file_data = f.read()

    scripts = extract(data=file_data)
    log.info(f"Found {len(scripts)} AutoIt scripts in the executable")

    if scripts:
        output = Path(args.output_dir)
        if not output.is_dir():
            log.info("The output directory doesn't exist, creating it")
            output.mkdir()

        for filename_w, content in scripts:
            # We need to convert the nasty Windows path into a nice, unix one
            filename = PureWindowsPath(filename_w)
            log.info(f"Storing result in {(output / filename.name).as_posix()}")
            (output / filename.name).write_bytes(content)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
