#!/usr/bin/env python3

from core.banner import show_banner
from core.cli import create_parser
from core.dispatcher import dispatch


def main():
    show_banner()

    parser = create_parser()
    args = parser.parse_args()

    dispatch(args)


if __name__ == "__main__":
    main()
