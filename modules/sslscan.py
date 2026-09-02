import socket
import ssl
from datetime import datetime


def run_sslscan(target, results=None):
    """
    Performs basic SSL/TLS analysis on port 443.
    """

    print("\n" + "=" * 55)
    print("                    SSL/TLS SCANNER")
    print("=" * 55)

    # Clean target
    hostname = (
        target
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
    )

    print(f"\nTarget : {hostname}")
    print("Port   : 443")

    print("\n[*] Connecting to TLS service...\n")

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as tls_socket:

                # TLS version
                tls_version = tls_socket.version()

                # Cipher
                cipher = tls_socket.cipher()

                # Certificate
                certificate = tls_socket.getpeercert()

    except socket.timeout:

        print("[-] Connection timed out.")
        return None

    except ssl.SSLError as error:

        print("[-] TLS error.")
        print(f"    Reason: {error}")
        return None

    except socket.gaierror:

        print("[-] Could not resolve target.")
        return None

    except ConnectionRefusedError:

        print("[-] Connection refused.")
        return None

    except OSError as error:

        print("[-] Connection failed.")
        print(f"    Reason: {error}")
        return None

    # Extract certificate information
    subject = {}

    for item in certificate.get(
        "subject",
        ()
    ):

        for key, value in item:

            subject[key] = value

    issuer = {}

    for item in certificate.get(
        "issuer",
        ()
    ):

        for key, value in item:

            issuer[key] = value

    common_name = subject.get(
        "commonName",
        "Not Available"
    )

    issuer_name = issuer.get(
        "commonName",
        "Not Available"
    )

    organization = issuer.get(
        "organizationName",
        "Not Available"
    )

    # Certificate dates
    not_before = certificate.get(
        "notBefore"
    )

    not_after = certificate.get(
        "notAfter"
    )

    days_remaining = None

    if not_after:

        try:

            expiry_date = datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z"
            )

            days_remaining = (
                expiry_date - datetime.utcnow()
            ).days

        except ValueError:

            days_remaining = None

    # Subject Alternative Names
    san_list = []

    for entry in certificate.get(
        "subjectAltName",
        ()
    ):

        if len(entry) == 2:

            san_list.append(
                entry[1]
            )

    # Display results
    print("TLS Information")
    print("-" * 35)

    print(
        f"TLS Version : "
        f"{tls_version or 'Not Available'}"
    )

    if cipher:

        print(
            f"Cipher      : {cipher[0]}"
        )

        print(
            f"Cipher Bits : {cipher[2]}"
        )

    else:

        print(
            "Cipher      : Not Available"
        )

    print("\nCertificate")
    print("-" * 35)

    print(
        f"Common Name : {common_name}"
    )

    print(
        f"Issuer      : {issuer_name}"
    )

    print(
        f"Organization: {organization}"
    )

    print(
        f"Valid From  : "
        f"{not_before or 'Not Available'}"
    )

    print(
        f"Valid Until : "
        f"{not_after or 'Not Available'}"
    )

    if days_remaining is not None:

        print(
            f"Days Left   : {days_remaining}"
        )

    print("\nSubject Alternative Names")
    print("-" * 35)

    if san_list:

        for name in san_list:

            print(
                f"[+] {name}"
            )

    else:

        print(
            "[-] No SAN information available."
        )

    print("\n" + "=" * 55)
    print("                  SSL/TLS COMPLETE")
    print("=" * 55)

    # Store results
    if results is not None:

        results.add(
            "ssl",
            {
                "tls_version":
                    tls_version,

                "cipher":
                    cipher[0] if cipher else None,

                "cipher_bits":
                    cipher[2] if cipher else None,

                "certificate": {
                    "common_name":
                        common_name,

                    "issuer":
                        issuer_name,

                    "organization":
                        organization,

                    "valid_from":
                        not_before,

                    "valid_until":
                        not_after,

                    "days_remaining":
                        days_remaining,

                    "subject_alternative_names":
                        san_list
                }
            }
        )

    return {
        "tls_version": tls_version,
        "cipher": cipher,
        "certificate": certificate
    }
