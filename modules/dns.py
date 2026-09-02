import socket


def get_a_records(target):
    """
    Returns IPv4 addresses associated with the target.
    """

    try:

        addresses = socket.gethostbyname_ex(target)[2]

        return list(dict.fromkeys(addresses))

    except socket.gaierror:

        return []


def get_mx_records(target):
    """
    Attempts to retrieve MX records using nslookup.
    """

    import subprocess

    try:

        result = subprocess.run(
            ["nslookup", "-type=MX", target],
            capture_output=True,
            text=True,
            timeout=10
        )

        records = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if "mail exchanger" in line.lower():

                parts = line.split("=")

                if len(parts) > 1:

                    records.append(
                        parts[-1].strip()
                    )

        return records

    except Exception:

        return []


def get_ns_records(target):
    """
    Attempts to retrieve nameserver records.
    """

    import subprocess

    try:

        result = subprocess.run(
            ["nslookup", "-type=NS", target],
            capture_output=True,
            text=True,
            timeout=10
        )

        records = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if "nameserver" in line.lower():

                parts = line.split("=")

                if len(parts) > 1:

                    records.append(
                        parts[-1].strip()
                    )

        return records

    except Exception:

        return []


def run_dns(target, results=None):
    """
    Performs DNS enumeration.

    Results are optionally stored inside
    the central Results object.
    """

    print("\n" + "=" * 55)
    print("                    DNS ENUMERATION")
    print("=" * 55)

    print(f"\nTarget : {target}")

    print("\n[*] Resolving DNS records...\n")

    # A records
    a_records = get_a_records(target)

    print("A Records")
    print("-" * 35)

    if a_records:

        for record in a_records:

            print(
                f"[+] {record}"
            )

    else:

        print(
            "[-] No A records found."
        )

    # MX records
    mx_records = get_mx_records(target)

    print("\nMX Records")
    print("-" * 35)

    if mx_records:

        for record in mx_records:

            print(
                f"[+] {record}"
            )

    else:

        print(
            "[-] No MX records found."
        )

    # NS records
    ns_records = get_ns_records(target)

    print("\nNS Records")
    print("-" * 35)

    if ns_records:

        for record in ns_records:

            print(
                f"[+] {record}"
            )

    else:

        print(
            "[-] No NS records found."
        )

    print("\n" + "=" * 55)
    print("                 DNS SCAN COMPLETE")
    print("=" * 55)

    # Store results
    if results is not None:

        results.add(
            "dns",
            {
                "a_records": a_records,
                "mx_records": mx_records,
                "ns_records": ns_records
            }
        )

    return {
        "a_records": a_records,
        "mx_records": mx_records,
        "ns_records": ns_records
    }
