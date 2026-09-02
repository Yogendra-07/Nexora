from services.results import Results
from services.report import save_json_report
from services.html_report import generate_html_report
from services.intelligence import generate_summary


def dispatch(args):
    """
    Main command dispatcher for Nexora.
    """

    # =================================================
    # COMMAND INFORMATION
    # =================================================

    print("=" * 50)
    print(f"Command : {args.command}")
    print(f"Target  : {args.target}")
    print("=" * 50)

    # =================================================
    # CENTRAL RESULTS OBJECT
    # =================================================

    results = Results(args.target)

    # =================================================
    # FULL RECONNAISSANCE
    # =================================================

    if args.command == "full":

        print("\n" + "=" * 55)
        print("              FULL RECONNAISSANCE")
        print("=" * 55)

        # -------------------------------------------------
        # 1. TCP PORT SCAN
        # -------------------------------------------------

        print("\n[1/6] TCP PORT SCAN")

        from modules.portscan import run_scan

        run_scan(
            args.target,
            results
        )

        # -------------------------------------------------
        # 2. DNS
        # -------------------------------------------------

        print("\n[2/6] DNS RECONNAISSANCE")

        from modules.dns import run_dns

        run_dns(
            args.target,
            results
        )

        # -------------------------------------------------
        # 3. WHOIS
        # -------------------------------------------------

        print("\n[3/6] WHOIS RECONNAISSANCE")

        from modules.whois import run_whois

        run_whois(
            args.target,
            results
        )

        # -------------------------------------------------
        # 4. HTTP HEADERS
        # -------------------------------------------------

        print("\n[4/6] HTTP HEADER ANALYSIS")

        from modules.headers import run_headers

        run_headers(
            args.target,
            results
        )

        # -------------------------------------------------
        # 5. SSL/TLS
        # -------------------------------------------------

        print("\n[5/6] SSL/TLS ANALYSIS")

        from modules.sslscan import run_sslscan

        run_sslscan(
            args.target,
            results
        )

        # -------------------------------------------------
        # 6. TECHNOLOGY DETECTION
        # -------------------------------------------------

        print("\n[6/6] TECHNOLOGY DETECTION")

        from modules.technology import run_technology

        run_technology(
            args.target,
            results
        )

    # =================================================
    # INDIVIDUAL COMMANDS
    # =================================================

    elif args.command == "scan":

        from modules.portscan import run_scan

        print("\nStarting TCP Port Scan...\n")

        run_scan(
            args.target,
            results
        )

    elif args.command == "dns":

        from modules.dns import run_dns

        print("\nStarting DNS Reconnaissance...\n")

        run_dns(
            args.target,
            results
        )

    elif args.command == "whois":

        from modules.whois import run_whois

        print("\nStarting WHOIS Reconnaissance...\n")

        run_whois(
            args.target,
            results
        )

    elif args.command == "headers":

        from modules.headers import run_headers

        print("\nStarting HTTP Header Analysis...\n")

        run_headers(
            args.target,
            results
        )

    elif args.command == "sslscan":

        from modules.sslscan import run_sslscan

        print("\nStarting SSL/TLS Analysis...\n")

        run_sslscan(
            args.target,
            results
        )

    elif args.command == "technology":

        from modules.technology import run_technology

        print("\nStarting Technology Detection...\n")

        run_technology(
            args.target,
            results
        )

    else:

        print("\nUnknown command.")
        return

    # =================================================
    # INTELLIGENCE ENGINE
    # =================================================

    print("\n" + "=" * 55)
    print("             NEXORA INTELLIGENCE")
    print("=" * 55)

    try:

        summary = generate_summary(
            results
        )

        results.add(
            "intelligence",
            summary
        )

        print("\nExecutive Summary:")
        print(
            summary.get(
                "executive_summary",
                "No summary available."
            )
        )

        priorities = summary.get(
            "priority_actions",
            []
        )

        if priorities:

            print("\nPriority Actions:")

            for index, action in enumerate(
                priorities,
                start=1
            ):

                print(
                    f"  {index}. {action}"
                )

    except Exception as error:

        print(
            f"\n[!] Intelligence analysis failed: {error}"
        )

    # =================================================
    # REPORT GENERATION
    # =================================================

    print("\n" + "=" * 55)
    print("             REPORT GENERATION")
    print("=" * 55)

    # -------------------------------------------------
    # JSON
    # -------------------------------------------------

    try:

        save_json_report(
            results
        )

        print("[+] JSON report generated.")

    except Exception as error:

        print(
            f"[!] JSON report generation failed: {error}"
        )

    # -------------------------------------------------
    # HTML
    # -------------------------------------------------

    try:

        html_file = generate_html_report(results)

    except Exception as error:

        print(
            f"[!] HTML report generation failed: {error}"
        )

    # =================================================
    # FINISHED
    # =================================================

    print("\n" + "=" * 55)
    print("              NEXORA COMPLETE")
    print("=" * 55)
