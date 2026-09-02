import argparse


def create_parser():

    parser = argparse.ArgumentParser(
        prog="Nexora",
        description="Professional Cybersecurity Reconnaissance Framework"
    )

    parser.add_argument(
        "command",
        choices=[
            "scan",
            "dns",
            "whois",
            "headers",
            "sslscan",
            "technology",
            "full"
        ],
        help="Command to execute"
    )

    parser.add_argument(
        "target",
        help="Target domain or IP"
    )

    return parser
