import argparse
from pathlib import Path

from ndx_tools.formats.cab import extract_cab

__SCRIPT_CMD = "cab"
__SCRIPT_DESC = "Cab tools"


def add_arguments_to_parser(parser: argparse.ArgumentParser):
    parser.add_argument(
        "--extract",
        help="path to a cab file",
        type=Path,
    )
    parser.add_argument(
        "--pack",
        help="path to a folder",
        type=Path,
    )
    parser.add_argument(
        "--output",
        help="path to output",
        type=Path,
    )


def process_arguments(args: argparse.Namespace):
    if args.extract is not None:
        extract_cab(args.extract, args.output)


def add_subparser(subparser: argparse._SubParsersAction):
    parser = subparser.add_parser(
        __SCRIPT_CMD, help=__SCRIPT_DESC, description=__SCRIPT_DESC
    )
    add_arguments_to_parser(parser)
    parser.set_defaults(func=process_arguments)


parser = argparse.ArgumentParser(description=__SCRIPT_DESC)
add_arguments_to_parser(parser)

if __name__ == "__main__":
    args = parser.parse_args()
    process_arguments(args)
