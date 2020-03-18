import lief  # type: ignore
from autoit_unpack import parse_all
from typing import Optional
import sys
import argparse
import logging

logging.basicConfig()
log = logging.getLogger()


def get_script_resource(pe: lief.PE) -> Optional[lief.PE.ResourceDirectory]:
    for child in pe.resources.childs:
        for grandchild in child.childs:
            if grandchild.has_name and grandchild.name == "SCRIPT":
                return grandchild
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="input binary")
    parser.add_argument("--verbose", '-v', action="store_true")

    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.WARNING)

    pe = lief.parse(args.file)
    if not pe:
        log.error("Failed to parse the input file")
        return 1

    if not pe.has_resources:
        log.error("The input file has no resources") 
        return 1

    script_resource = get_script_resource(pe)
    if script_resource is None:
        log.error("Couldn't find the script resource")
        return 1

    script_data = list(script_resource.childs)[0].content
    parsed_data = parse_all(bytes(script_data))
    if not parsed_data:
        log.error("Couldn't decode the autoit script")
        return 1

    print(parsed_data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
