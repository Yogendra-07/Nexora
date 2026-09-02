def analyze_headers(header_data):
    """
    Analyze HTTP security headers and
    generate security findings.
    """

    findings = []

    if not header_data:
        return findings

    missing_headers = header_data.get(
        "security_headers_missing",
        []
    )

    # Content Security Policy
    if "Content-Security-Policy" in missing_headers:

        findings.append(
            {
                "title":
                    "Missing Content Security Policy",

                "severity":
                    "MEDIUM",

                "category":
                    "HTTP Security",

                "description":
                    "The target does not appear to "
                    "provide a Content-Security-Policy "
                    "response header.",

                "recommendation":
                    "Consider implementing an "
                    "appropriate Content-Security-Policy "
                    "based on the application's "
                    "requirements."
            }
        )

    # HSTS
    if "Strict-Transport-Security" in missing_headers:

        findings.append(
            {
                "title":
                    "Missing HTTP Strict Transport Security",

                "severity":
                    "MEDIUM",

                "category":
                    "HTTP Security",

                "description":
                    "The target does not appear to "
                    "provide an HSTS response header.",

                "recommendation":
                    "If the application is intended to "
                    "operate exclusively over HTTPS, "
                    "consider enabling HSTS."
            }
        )

    # X-Content-Type-Options
    if "X-Content-Type-Options" in missing_headers:

        findings.append(
            {
                "title":
                    "Missing X-Content-Type-Options",

                "severity":
                    "LOW",

                "category":
                    "HTTP Security",

                "description":
                    "The target does not appear to "
                    "provide the X-Content-Type-Options "
                    "header.",

                "recommendation":
                    "Consider configuring "
                    "X-Content-Type-Options: nosniff."
            }
        )

    # X-Frame-Options
    if "X-Frame-Options" in missing_headers:

        findings.append(
            {
                "title":
                    "Missing X-Frame-Options",

                "severity":
                    "LOW",

                "category":
                    "HTTP Security",

                "description":
                    "The target does not appear to "
                    "provide an X-Frame-Options header.",

                "recommendation":
                    "Consider using an appropriate "
                    "framing policy such as "
                    "DENY or SAMEORIGIN."
            }
        )

    # Referrer Policy
    if "Referrer-Policy" in missing_headers:

        findings.append(
            {
                "title":
                    "Missing Referrer-Policy",

                "severity":
                    "LOW",

                "category":
                    "HTTP Security",

                "description":
                    "The target does not appear to "
                    "provide a Referrer-Policy header.",

                "recommendation":
                    "Consider configuring an explicit "
                    "Referrer-Policy appropriate for "
                    "the application."
            }
        )

    # Permissions Policy
    if "Permissions-Policy" in missing_headers:

        findings.append(
            {
                "title":
                    "Missing Permissions-Policy",

                "severity":
                    "LOW",

                "category":
                    "HTTP Security",

                "description":
                    "The target does not appear to "
                    "provide a Permissions-Policy header.",

                "recommendation":
                    "Consider restricting unnecessary "
                    "browser capabilities using "
                    "Permissions-Policy."
            }
        )

    return findings


def analyze_ssl(ssl_data):
    """
    Analyze TLS information and generate
    security findings.
    """

    findings = []

    if not ssl_data:
        return findings

    tls_version = ssl_data.get(
        "tls_version"
    )

    days_remaining = (
        ssl_data
        .get("certificate", {})
        .get("days_remaining")
    )

    # Older TLS versions
    if tls_version in [
        "TLSv1",
        "TLSv1.1"
    ]:

        findings.append(
            {
                "title":
                    f"Legacy TLS Version Detected: "
                    f"{tls_version}",

                "severity":
                    "HIGH",

                "category":
                    "TLS",

                "description":
                    f"The target negotiated "
                    f"{tls_version}, which is an "
                    f"older TLS version.",

                "recommendation":
                    "Use modern TLS configurations, "
                    "preferably TLS 1.2 or TLS 1.3."
            }
        )

    # Certificate expiration
    if days_remaining is not None:

        if days_remaining < 0:

            findings.append(
                {
                    "title":
                        "TLS Certificate Expired",

                    "severity":
                        "HIGH",

                    "category":
                        "TLS",

                    "description":
                        "The TLS certificate appears "
                        "to have expired.",

                    "recommendation":
                        "Renew the certificate and "
                        "verify the deployment."
                }
            )

        elif days_remaining <= 30:

            findings.append(
                {
                    "title":
                        "TLS Certificate Expiring Soon",

                    "severity":
                        "MEDIUM",

                    "category":
                        "TLS",

                    "description":
                        f"The TLS certificate has "
                        f"approximately "
                        f"{days_remaining} days "
                        f"remaining.",

                    "recommendation":
                        "Plan certificate renewal "
                        "before expiration."
                }
            )

    return findings


def analyze_all(results):
    """
    Analyze the complete Results object.
    """

    findings = []

    data = results.get_all()

    # Header findings
    findings.extend(
        analyze_headers(
            data.get("headers", {})
        )
    )

    # TLS findings
    findings.extend(
        analyze_ssl(
            data.get("ssl", {})
        )
    )

    return findings
