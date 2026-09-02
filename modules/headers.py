import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security":
        "HSTS",

    "Content-Security-Policy":
        "CSP",

    "X-Content-Type-Options":
        "X-Content-Type-Options",

    "X-Frame-Options":
        "X-Frame-Options",

    "Referrer-Policy":
        "Referrer-Policy",

    "Permissions-Policy":
        "Permissions-Policy"
}


def run_headers(target, results=None):
    """
    Performs HTTP header analysis.

    Results are optionally stored inside
    the central Results object.
    """

    print("\n" + "=" * 55)
    print("                 HTTP HEADER ANALYSIS")
    print("=" * 55)

    # Build URL
    if not target.startswith(("http://", "https://")):
        url = "https://" + target
    else:
        url = target

    print(f"\nTarget : {url}")

    print("\n[*] Requesting HTTP headers...\n")

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent":
                    "Nexora/0.1 Security Scanner"
            }
        )

    except requests.exceptions.SSLError as error:

        print("\n[-] TLS/SSL error.")
        print(f"    Reason: {error}")

        return

    except requests.exceptions.Timeout:

        print("\n[-] Request timed out.")

        return

    except requests.exceptions.ConnectionError:

        print("\n[-] Could not connect to target.")

        return

    except requests.exceptions.RequestException as error:

        print("\n[-] HTTP request failed.")
        print(f"    Reason: {error}")

        return

    print("Connection Information")
    print("-" * 35)

    print(
        f"Status Code : {response.status_code}"
    )

    print(
        f"Final URL   : {response.url}"
    )

    print("\nServer Information")
    print("-" * 35)

    server = response.headers.get(
        "Server"
    )

    powered_by = response.headers.get(
        "X-Powered-By"
    )

    if server:

        print(
            f"[+] Server      : {server}"
        )

    else:

        print(
            "[-] Server      : Not disclosed"
        )

    if powered_by:

        print(
            f"[+] Powered By  : {powered_by}"
        )

    else:

        print(
            "[-] Powered By  : Not disclosed"
        )

    print("\nSecurity Headers")
    print("-" * 35)

    present_headers = []
    missing_headers = []

    for header, display_name in SECURITY_HEADERS.items():

        if header in response.headers:

            print(
                f"[+] {display_name}"
            )

            present_headers.append(
                header
            )

        else:

            print(
                f"[-] {display_name} MISSING"
            )

            missing_headers.append(
                header
            )

    print("\n" + "=" * 55)
    print("                HEADER ANALYSIS COMPLETE")
    print("=" * 55)

    # Store structured results
    if results is not None:

        results.add(
            "headers",
            {
                "status_code":
                    response.status_code,

                "final_url":
                    response.url,

                "server":
                    server,

                "powered_by":
                    powered_by,

                "security_headers_present":
                    present_headers,

                "security_headers_missing":
                    missing_headers,

                "all_headers":
                    dict(response.headers)
            }
        )

    print()

    return response.headers
