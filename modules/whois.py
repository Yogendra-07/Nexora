import whois


def run_whois(target, results=None):
    """
    Performs WHOIS lookup for a domain.

    Results are optionally stored inside
    the central Results object.
    """

    print("\n" + "=" * 55)
    print("                    WHOIS LOOKUP")
    print("=" * 55)

    target = (
        target
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
    )

    print(f"\nTarget : {target}")

    print("\n[*] Performing WHOIS lookup...\n")

    try:

        data = whois.whois(target)

    except Exception as error:

        print("\n[-] WHOIS lookup failed.")
        print(f"    Reason: {error}")

        if results is not None:

            results.add(
                "whois",
                {
                    "error": str(error)
                }
            )

        return None

    # Extract information
    registrar = data.registrar
    creation_date = data.creation_date
    expiration_date = data.expiration_date
    updated_date = data.updated_date
    status = data.status
    name_servers = data.name_servers

    print("Domain Information")
    print("-" * 35)

    print(
        f"Registrar       : "
        f"{registrar or 'Not Available'}"
    )

    print(
        f"Creation Date   : "
        f"{creation_date or 'Not Available'}"
    )

    print(
        f"Expiration Date : "
        f"{expiration_date or 'Not Available'}"
    )

    print(
        f"Updated Date    : "
        f"{updated_date or 'Not Available'}"
    )

    print("\nDomain Status")
    print("-" * 35)

    if status:

        if isinstance(status, list):

            for item in status:

                print(f"[+] {item}")

        else:

            print(f"[+] {status}")

    else:

        print("[-] Not Available")

    print("\nName Servers")
    print("-" * 35)

    if name_servers:

        if isinstance(name_servers, (list, tuple)):

            for server in name_servers:

                print(f"[+] {server}")

        else:

            print(f"[+] {name_servers}")

    else:

        print("[-] Not Available")

    print("\n" + "=" * 55)
    print("                 WHOIS COMPLETE")
    print("=" * 55)

    # Store structured results
    if results is not None:

        results.add(
            "whois",
            {
                "registrar": registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "updated_date": updated_date,
                "status": status,
                "name_servers": name_servers
            }
        )

    return data
