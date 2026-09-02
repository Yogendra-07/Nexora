from datetime import datetime


def generate_summary(results):
    """
    Nexora Security Intelligence Engine.

    Analyzes collected reconnaissance results,
    generates security findings, calculates a
    security score, and produces an executive summary.
    """

    data = results.get_all()

    findings = []

    score = 100

    # =================================================
    # TCP PORT ANALYSIS
    # =================================================

    port_data = data.get(
        "port_scan",
        {}
    )

    open_ports = port_data.get(
        "open_ports",
        []
    )

    if open_ports:

        # Common externally exposed services
        risky_ports = {
            21: "FTP",
            23: "Telnet",
            25: "SMTP",
            445: "SMB",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB"
        }

        for port in open_ports:

            if port in risky_ports:

                service = risky_ports[port]

                severity = "HIGH"

                score -= 15

                finding = {
                    "title":
                        f"Potentially risky {service} service exposed",

                    "severity":
                        severity,

                    "category":
                        "Network Exposure",

                    "description":
                        f"TCP port {port} ({service}) "
                        "is publicly reachable.",

                    "recommendation":
                        "Verify that the service is required "
                        "and restrict access using firewall "
                        "rules or network segmentation."
                }

                findings.append(
                    finding
                )

    # =================================================
    # HTTP SECURITY HEADER ANALYSIS
    # =================================================

    header_data = data.get(
        "headers",
        {}
    )

    missing_headers = header_data.get(
        "security_headers_missing",
        []
    )

    if missing_headers:

        # CSP is particularly important
        if "Content-Security-Policy" in missing_headers:

            score -= 8

            findings.append(
                {
                    "title":
                        "Content Security Policy missing",

                    "severity":
                        "MEDIUM",

                    "category":
                        "Web Security",

                    "description":
                        "The Content-Security-Policy "
                        "security header was not detected.",

                    "recommendation":
                        "Implement a restrictive Content "
                        "Security Policy appropriate for "
                        "the application's resources."
                }
            )

        # HSTS
        if "Strict-Transport-Security" in missing_headers:

            score -= 6

            findings.append(
                {
                    "title":
                        "HSTS header missing",

                    "severity":
                        "MEDIUM",

                    "category":
                        "Transport Security",

                    "description":
                        "HTTP Strict Transport Security "
                        "was not detected.",

                    "recommendation":
                        "Enable HSTS after confirming the "
                        "site is fully HTTPS-compatible."
                }
            )

        # X-Frame-Options
        if "X-Frame-Options" in missing_headers:

            score -= 4

            findings.append(
                {
                    "title":
                        "Clickjacking protection missing",

                    "severity":
                        "LOW",

                    "category":
                        "Web Security",

                    "description":
                        "X-Frame-Options was not detected.",

                    "recommendation":
                        "Configure X-Frame-Options or use "
                        "frame-ancestors in CSP."
                }
            )

        # X-Content-Type-Options
        if "X-Content-Type-Options" in missing_headers:

            score -= 3

            findings.append(
                {
                    "title":
                        "MIME-sniffing protection missing",

                    "severity":
                        "LOW",

                    "category":
                        "Web Security",

                    "description":
                        "X-Content-Type-Options was not detected.",

                    "recommendation":
                        "Set X-Content-Type-Options to "
                        "'nosniff'."
                }
            )

        # Referrer Policy
        if "Referrer-Policy" in missing_headers:

            score -= 2

            findings.append(
                {
                    "title":
                        "Referrer-Policy missing",

                    "severity":
                        "LOW",

                    "category":
                        "Privacy",

                    "description":
                        "A Referrer-Policy header was not detected.",

                    "recommendation":
                        "Configure an appropriate Referrer-Policy "
                        "to control referrer information."
                }
            )

        # Permissions Policy
        if "Permissions-Policy" in missing_headers:

            score -= 2

            findings.append(
                {
                    "title":
                        "Permissions-Policy missing",

                    "severity":
                        "LOW",

                    "category":
                        "Browser Security",

                    "description":
                        "Permissions-Policy was not detected.",

                    "recommendation":
                        "Define a Permissions-Policy that "
                        "restricts unnecessary browser features."
                }
            )

    # =================================================
    # SSL / TLS ANALYSIS
    # =================================================

    ssl_data = data.get(
        "ssl",
        {}
    )

    tls_version = ssl_data.get(
        "tls_version"
    )

    if tls_version:

        # Deprecated TLS versions
        if tls_version in (
            "TLSv1",
            "TLSv1.1"
        ):

            score -= 20

            findings.append(
                {
                    "title":
                        "Deprecated TLS version detected",

                    "severity":
                        "HIGH",

                    "category":
                        "TLS Security",

                    "description":
                        f"The server negotiated {tls_version}, "
                        "which is deprecated.",

                    "recommendation":
                        "Disable deprecated TLS protocols "
                        "and require TLS 1.2 or newer."
                }
            )

    certificate = ssl_data.get(
        "certificate",
        {}
    )

    days_remaining = certificate.get(
        "days_remaining"
    )

    if days_remaining is not None:

        if days_remaining < 0:

            score -= 25

            findings.append(
                {
                    "title":
                        "TLS certificate has expired",

                    "severity":
                        "HIGH",

                    "category":
                        "Certificate Security",

                    "description":
                        "The TLS certificate appears to "
                        "have expired.",

                    "recommendation":
                        "Renew the TLS certificate immediately."
                }
            )

        elif days_remaining < 30:

            score -= 10

            findings.append(
                {
                    "title":
                        "TLS certificate expires soon",

                    "severity":
                        "MEDIUM",

                    "category":
                        "Certificate Security",

                    "description":
                        f"The certificate has approximately "
                        f"{days_remaining} days remaining.",

                    "recommendation":
                        "Renew the certificate before expiration."
                }
            )

    # =================================================
    # TECHNOLOGY ANALYSIS
    # =================================================

    technology_data = data.get(
        "technology",
        {}
    )

    technologies = technology_data.get(
        "technologies",
        []
    )

    # We don't automatically mark a technology
    # as vulnerable merely because it was detected.
    # Technology detection is informational.

    if technologies:

        findings.append(
            {
                "title":
                    "Web technologies identified",

                "severity":
                    "INFO",

                "category":
                    "Technology Discovery",

                "description":
                    "Nexora identified: "
                    + ", ".join(technologies),

                "recommendation":
                    "Keep identified technologies "
                    "updated and monitor them for "
                    "known security vulnerabilities."
            }
        )

    # =================================================
    # SCORE NORMALIZATION
    # =================================================

    score = max(
        0,
        min(
            100,
            score
        )
    )

    # =================================================
    # SEVERITY COUNTS
    # =================================================

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in findings:

        severity = finding.get(
            "severity",
            "INFO"
        )

        if severity in severity_counts:

            severity_counts[severity] += 1

    # =================================================
    # RATING
    # =================================================

    if score >= 90:

        rating = "Excellent"

    elif score >= 75:

        rating = "Good"

    elif score >= 60:

        rating = "Moderate"

    elif score >= 40:

        rating = "Poor"

    else:

        rating = "Critical"

    # =================================================
    # EXECUTIVE SUMMARY
    # =================================================

    target = data.get(
        "target",
        "Unknown"
    )

    if severity_counts["HIGH"] > 0:

        executive_summary = (
            f"Nexora identified "
            f"{severity_counts['HIGH']} high-severity "
            "security issue(s) affecting "
            f"{target}. Immediate review of the "
            "identified findings is recommended."
        )

    elif severity_counts["MEDIUM"] > 0:

        executive_summary = (
            f"Nexora identified several areas for "
            f"security improvement on {target}, "
            "including medium-severity findings. "
            "Remediation should be prioritized "
            "based on exposure and business impact."
        )

    elif findings:

        executive_summary = (
            f"Nexora completed the assessment of "
            f"{target}. No high-severity issues were "
            "identified, although some lower-risk "
            "security improvements may be appropriate."
        )

    else:

        executive_summary = (
            f"Nexora completed the assessment of "
            f"{target} without generating security "
            "findings from the available checks."
        )

    # =================================================
    # PRIORITY ACTIONS
    # =================================================

    priority_actions = []

    for finding in findings:

        if finding.get("severity") in (
            "HIGH",
            "MEDIUM"
        ):

            recommendation = finding.get(
                "recommendation"
            )

            if recommendation:

                priority_actions.append(
                    recommendation
                )

    # Remove duplicates
    priority_actions = list(
        dict.fromkeys(
            priority_actions
        )
    )

    # =================================================
    # SECURITY SCORE DATA
    # =================================================

    security_score = {
        "score": score,
        "rating": rating,
        "severity_summary": severity_counts
    }

    # Store score
    results.add(
        "security_score",
        security_score
    )

    # Store findings
    for finding in findings:

        results.add_finding(
            finding
        )

    # =================================================
    # FINAL INTELLIGENCE OBJECT
    # =================================================

    intelligence = {

        "generated_at":
            datetime.now().isoformat(),

        "executive_summary":
            executive_summary,

        "priority_actions":
            priority_actions,

        "findings_count":
            len(findings),

        "severity_summary":
            severity_counts,

        "assessment":
            rating
    }

    return intelligence
