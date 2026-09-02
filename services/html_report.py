import os
import html
from datetime import datetime


def generate_html_report(results):
    """
    Generate a professional HTML security report
    using Nexora's centralized Results object.
    """

    # -------------------------------------------------
    # OUTPUT DIRECTORY
    # -------------------------------------------------

    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    # -------------------------------------------------
    # GET ALL RESULTS
    # -------------------------------------------------

    data = results.get_all()

    target = data.get("target", "Unknown")

    timestamp = data.get(
        "timestamp",
        datetime.now().isoformat()
    )

    port_scan = data.get("port_scan", {})
    dns_data = data.get("dns", {})
    whois_data = data.get("whois", {})
    headers_data = data.get("headers", {})
    ssl_data = data.get("ssl", {})
    technology_data = data.get("technology", {})
    findings = data.get("findings", [])
    security_score = data.get("security_score", {})
    intelligence = data.get("intelligence", {})

    # -------------------------------------------------
    # SECURITY SCORE
    # -------------------------------------------------

    score = security_score.get("score", 100)

    rating = security_score.get(
        "rating",
        "Unknown"
    )

    # Intelligence engine uses severity_summary
    severity_counts = security_score.get(
        "severity_summary",
        {}
    )

    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)
    info = severity_counts.get("INFO", 0)

    # -------------------------------------------------
    # EXECUTIVE INTELLIGENCE
    # -------------------------------------------------

    executive_summary = intelligence.get(
        "executive_summary",
        "No executive summary was generated."
    )

    priority_actions = intelligence.get(
        "priority_actions",
        []
    )

    # -------------------------------------------------
    # ESCAPE VALUES
    # -------------------------------------------------

    safe_target = html.escape(str(target))
    safe_timestamp = html.escape(str(timestamp))
    safe_rating = html.escape(str(rating))
    safe_summary = html.escape(
        str(executive_summary)
    )

    # -------------------------------------------------
    # SCORE STATUS
    # -------------------------------------------------

    if score >= 90:
        score_class = "excellent"
    elif score >= 75:
        score_class = "good"
    elif score >= 60:
        score_class = "moderate"
    elif score >= 40:
        score_class = "poor"
    else:
        score_class = "critical"

    # -------------------------------------------------
    # OPEN PORTS
    # -------------------------------------------------

    open_ports = port_scan.get(
        "open_ports",
        []
    )

    ports_html = ""

    if open_ports:

        for port in open_ports:

            ports_html += f"""
            <span class="port">
                {html.escape(str(port))}/tcp
            </span>
            """

    else:

        ports_html = """
        <span class="muted">
            No open ports detected.
        </span>
        """

    # -------------------------------------------------
    # FINDINGS
    # -------------------------------------------------

    findings_html = ""

    if findings:

        for finding in findings:

            severity = finding.get(
                "severity",
                "INFO"
            )

            title = html.escape(
                str(
                    finding.get(
                        "title",
                        "Unnamed Finding"
                    )
                )
            )

            category = html.escape(
                str(
                    finding.get(
                        "category",
                        "General"
                    )
                )
            )

            description = html.escape(
                str(
                    finding.get(
                        "description",
                        "No description available."
                    )
                )
            )

            recommendation = html.escape(
                str(
                    finding.get(
                        "recommendation",
                        "No recommendation available."
                    )
                )
            )

            severity_class = severity.lower()

            findings_html += f"""
            <div class="finding {severity_class}">

                <div class="finding-header">

                    <div>
                        <div class="finding-title">
                            {title}
                        </div>

                        <div class="finding-category">
                            {category}
                        </div>
                    </div>

                    <span class="badge {severity_class}">
                        {html.escape(str(severity))}
                    </span>

                </div>

                <div class="finding-description">
                    {description}
                </div>

                <div class="recommendation">

                    <strong>Recommendation</strong>

                    <p>
                        {recommendation}
                    </p>

                </div>

            </div>
            """

    else:

        findings_html = """
        <div class="no-findings">
            ✓ No security findings were generated.
        </div>
        """

    # -------------------------------------------------
    # PRIORITY ACTIONS
    # -------------------------------------------------

    actions_html = ""

    if priority_actions:

        for index, action in enumerate(
            priority_actions,
            start=1
        ):

            actions_html += f"""
            <div class="action">

                <div class="action-number">
                    {index}
                </div>

                <div>
                    {html.escape(str(action))}
                </div>

            </div>
            """

    else:

        actions_html = """
        <div class="muted">
            No high or medium priority actions generated.
        </div>
        """

    # -------------------------------------------------
    # TECHNOLOGIES
    # -------------------------------------------------

    technologies = technology_data.get(
        "technologies",
        []
    )

    technologies_html = ""

    if technologies:

        for technology in technologies:

            technologies_html += f"""
            <span class="technology">
                {html.escape(str(technology))}
            </span>
            """

    else:

        technologies_html = """
        <span class="muted">
            No technologies identified.
        </span>
        """

    # -------------------------------------------------
    # SECURITY HEADERS
    # -------------------------------------------------

    present_headers = headers_data.get(
        "security_headers_present",
        []
    )

    missing_headers = headers_data.get(
        "security_headers_missing",
        []
    )

    header_html = ""

    if present_headers:

        for header in present_headers:

            header_html += f"""
            <div class="header-row present">

                <span>
                    {html.escape(str(header))}
                </span>

                <strong>
                    PRESENT
                </strong>

            </div>
            """

    if missing_headers:

        for header in missing_headers:

            header_html += f"""
            <div class="header-row missing">

                <span>
                    {html.escape(str(header))}
                </span>

                <strong>
                    MISSING
                </strong>

            </div>
            """

    if not header_html:

        header_html = """
        <div class="muted">
            No HTTP security-header data available.
        </div>
        """

    # -------------------------------------------------
    # SSL / TLS
    # -------------------------------------------------

    certificate = ssl_data.get(
        "certificate",
        {}
    )

    tls_version = ssl_data.get(
        "tls_version",
        "Unavailable"
    )

    cipher = ssl_data.get(
        "cipher",
        "Unavailable"
    )

    cipher_bits = ssl_data.get(
        "cipher_bits",
        "Unavailable"
    )

    common_name = certificate.get(
        "common_name",
        "Unavailable"
    )

    issuer = certificate.get(
        "issuer",
        "Unavailable"
    )

    valid_until = certificate.get(
        "valid_until",
        "Unavailable"
    )

    days_remaining = certificate.get(
        "days_remaining",
        "Unavailable"
    )

    # -------------------------------------------------
    # DNS
    # -------------------------------------------------

    dns_html = ""

    if dns_data:

        for key, value in dns_data.items():

            if isinstance(value, list):

                value = ", ".join(
                    str(item)
                    for item in value
                )

            dns_html += f"""
            <div class="data-row">

                <span class="data-key">
                    {html.escape(str(key))}
                </span>

                <span class="data-value">
                    {html.escape(str(value))}
                </span>

            </div>
            """

    else:

        dns_html = """
        <div class="muted">
            No DNS data available.
        </div>
        """

    # -------------------------------------------------
    # WHOIS
    # -------------------------------------------------

    whois_html = ""

    if whois_data:

        for key, value in whois_data.items():

            if isinstance(value, list):

                value = ", ".join(
                    str(item)
                    for item in value
                )

            whois_html += f"""
            <div class="data-row">

                <span class="data-key">
                    {html.escape(str(key))}
                </span>

                <span class="data-value">
                    {html.escape(str(value))}
                </span>

            </div>
            """

    else:

        whois_html = """
        <div class="muted">
            No WHOIS data available.
        </div>
        """

    # -------------------------------------------------
    # MODULE STATUS
    # -------------------------------------------------

    def module_status(module_data):

        if module_data:
            return "Completed"

        return "No data"

    # -------------------------------------------------
    # HTML DOCUMENT
    # -------------------------------------------------

    html_content = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<title>
Nexora Security Report - {safe_target}
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #0b1120;

    color: #e2e8f0;

    line-height: 1.6;
}}

.container {{

    max-width: 1150px;

    margin: auto;

    padding: 35px 20px;
}}

.header {{

    background:
        linear-gradient(
            135deg,
            #111827,
            #172554
        );

    border:
        1px solid #334155;

    border-radius: 16px;

    padding: 32px;

    margin-bottom: 25px;

    box-shadow:
        0 15px 35px
        rgba(0,0,0,0.25);
}}

.logo {{

    font-size: 38px;

    font-weight: bold;

    letter-spacing: 5px;
}}

.subtitle {{

    color: #94a3b8;

    margin-top: 4px;
}}

.target-grid {{

    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(220px, 1fr)
        );

    gap: 15px;

    margin-top: 28px;
}}

.card {{

    background: rgba(
        30,
        41,
        59,
        0.75
    );

    border:
        1px solid #334155;

    border-radius: 10px;

    padding: 18px;
}}

.card-label {{

    font-size: 11px;

    color: #94a3b8;

    text-transform: uppercase;

    letter-spacing: 1.5px;
}}

.card-value {{

    font-size: 17px;

    font-weight: bold;

    margin-top: 5px;

    word-break: break-word;
}}

.section {{

    background: #111827;

    border:
        1px solid #334155;

    border-radius: 14px;

    padding: 25px;

    margin-bottom: 25px;

    box-shadow:
        0 8px 25px
        rgba(0,0,0,0.15);
}}

.section h2 {{

    margin-top: 0;

    font-size: 21px;

    color: #f8fafc;
}}

.summary {{

    font-size: 16px;

    color: #cbd5e1;

    background: #1e293b;

    border-left:
        4px solid #38bdf8;

    padding: 18px;

    border-radius: 8px;
}}

.score-container {{

    display: flex;

    align-items: center;

    gap: 35px;

    flex-wrap: wrap;
}}

.score-circle {{

    width: 155px;

    height: 155px;

    border-radius: 50%;

    border: 9px solid #38bdf8;

    background: #1e293b;

    display: flex;

    align-items: center;

    justify-content: center;

    flex-direction: column;
}}

.score-circle.excellent {{
    border-color: #22c55e;
}}

.score-circle.good {{
    border-color: #84cc16;
}}

.score-circle.moderate {{
    border-color: #eab308;
}}

.score-circle.poor {{
    border-color: #f97316;
}}

.score-circle.critical {{
    border-color: #ef4444;
}}

.score-number {{

    font-size: 42px;

    font-weight: bold;
}}

.score-max {{

    color: #94a3b8;

    font-size: 13px;
}}

.score-rating {{

    font-size: 25px;

    font-weight: bold;

    margin-bottom: 5px;
}}

.severity-grid {{

    display: grid;

    grid-template-columns:
        repeat(
            4,
            1fr
        );

    gap: 15px;
}}

.severity-card {{

    background: #1e293b;

    border:
        1px solid #334155;

    border-radius: 10px;

    padding: 20px;

    text-align: center;
}}

.severity-number {{

    font-size: 32px;

    font-weight: bold;
}}

.severity-label {{

    color: #94a3b8;

    font-size: 12px;

    letter-spacing: 1px;
}}

.finding {{

    background: #1e293b;

    border:
        1px solid #334155;

    border-left:
        5px solid #64748b;

    border-radius: 10px;

    padding: 20px;

    margin-bottom: 15px;
}}

.finding.high {{
    border-left-color: #ef4444;
}}

.finding.medium {{
    border-left-color: #f97316;
}}

.finding.low {{
    border-left-color: #eab308;
}}

.finding.info {{
    border-left-color: #38bdf8;
}}

.finding-header {{

    display: flex;

    justify-content:
        space-between;

    align-items:
        flex-start;

    gap: 15px;
}}

.finding-title {{

    font-size: 17px;

    font-weight: bold;
}}

.finding-category {{

    color: #94a3b8;

    font-size: 13px;

    margin-top: 3px;
}}

.finding-description {{

    color: #cbd5e1;

    margin-top: 15px;
}}

.badge {{

    padding: 5px 10px;

    border-radius: 20px;

    font-size: 11px;

    font-weight: bold;
}}

.badge.high {{
    background: #7f1d1d;
    color: #fecaca;
}}

.badge.medium {{
    background: #7c2d12;
    color: #fed7aa;
}}

.badge.low {{
    background: #713f12;
    color: #fef08a;
}}

.badge.info {{
    background: #164e63;
    color: #bae6fd;
}}

.recommendation {{

    margin-top: 18px;

    padding: 14px;

    background: #0f172a;

    border-radius: 8px;
}}

.recommendation strong {{

    color: #38bdf8;
}}

.recommendation p {{

    margin-bottom: 0;

    color: #cbd5e1;
}}

.action {{

    display: flex;

    align-items: flex-start;

    gap: 14px;

    background: #1e293b;

    padding: 15px;

    border-radius: 9px;

    margin-bottom: 10px;
}}

.action-number {{

    min-width: 28px;

    height: 28px;

    border-radius: 50%;

    background: #38bdf8;

    color: #0f172a;

    display: flex;

    align-items: center;

    justify-content: center;

    font-weight: bold;
}}

.ports {{

    display: flex;

    flex-wrap: wrap;

    gap: 10px;
}}

.port,
.technology {{

    display: inline-block;

    background: #1e293b;

    border:
        1px solid #475569;

    padding: 8px 12px;

    border-radius: 8px;

    font-size: 13px;
}}

.technology {{

    border-color: #38bdf8;

    color: #bae6fd;
}}

.header-row,
.data-row {{

    display: flex;

    justify-content:
        space-between;

    gap: 20px;

    padding: 12px;

    border-bottom:
        1px solid #334155;
}}

.header-row:last-child,
.data-row:last-child {{
    border-bottom: none;
}}

.header-row.present strong {{
    color: #4ade80;
}}

.header-row.missing strong {{
    color: #f87171;
}}

.data-key {{

    color: #94a3b8;

    font-weight: bold;
}}

.data-value {{

    text-align: right;

    word-break: break-word;

    max-width: 65%;
}}

.module-grid {{

    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(250px, 1fr)
        );

    gap: 12px;
}}

.module {{

    background: #1e293b;

    border:
        1px solid #334155;

    border-radius: 9px;

    padding: 15px;

    display: flex;

    justify-content:
        space-between;

    align-items: center;
}}

.module-name {{
    font-weight: bold;
}}

.module-status {{

    color: #4ade80;

    font-size: 12px;

    font-weight: bold;
}}

.no-findings {{

    background: #052e16;

    border:
        1px solid #166534;

    color: #86efac;

    padding: 18px;

    border-radius: 9px;
}}

.muted {{
    color: #64748b;
}}

.footer {{

    text-align: center;

    color: #64748b;

    padding: 25px;
}}

@media(max-width:700px) {{

    .severity-grid {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

    .finding-header {{
        flex-direction: column;
    }}

    .header-row,
    .data-row {{
        flex-direction: column;
    }}

    .data-value {{
        max-width: 100%;
        text-align: left;
    }}

}}

</style>

</head>

<body>

<div class="container">

<!-- HEADER -->

<div class="header">

<div class="logo">
NEXORA
</div>

<div class="subtitle">
Professional Cybersecurity Reconnaissance Framework
</div>

<div class="target-grid">

<div class="card">

<div class="card-label">
Target
</div>

<div class="card-value">
{safe_target}
</div>

</div>

<div class="card">

<div class="card-label">
Scan Timestamp
</div>

<div class="card-value">
{safe_timestamp}
</div>

</div>

<div class="card">

<div class="card-label">
Security Rating
</div>

<div class="card-value">
{safe_rating}
</div>

</div>

</div>

</div>

<!-- EXECUTIVE SUMMARY -->

<div class="section">

<h2>
Executive Summary
</h2>

<div class="summary">
{safe_summary}
</div>

</div>

<!-- SECURITY SCORE -->

<div class="section">

<h2>
Security Score
</h2>

<div class="score-container">

<div class="score-circle {score_class}">

<div class="score-number">
{score}
</div>

<div class="score-max">
/ 100
</div>

</div>

<div>

<div class="score-rating">
{safe_rating}
</div>

<p>
Overall security assessment generated
by the Nexora intelligence engine.
</p>

</div>

</div>

</div>

<!-- SEVERITY -->

<div class="section">

<h2>
Severity Summary
</h2>

<div class="severity-grid">

<div class="severity-card">

<div class="severity-number">
{high}
</div>

<div class="severity-label">
HIGH
</div>

</div>

<div class="severity-card">

<div class="severity-number">
{medium}
</div>

<div class="severity-label">
MEDIUM
</div>

</div>

<div class="severity-card">

<div class="severity-number">
{low}
</div>

<div class="severity-label">
LOW
</div>

</div>

<div class="severity-card">

<div class="severity-number">
{info}
</div>

<div class="severity-label">
INFO
</div>

</div>

</div>

</div>

<!-- PRIORITY ACTIONS -->

<div class="section">

<h2>
Priority Actions
</h2>

{actions_html}

</div>

<!-- FINDINGS -->

<div class="section">

<h2>
Security Findings
</h2>

{findings_html}

</div>

<!-- PORTS -->

<div class="section">

<h2>
Open TCP Ports
</h2>

<div class="ports">

{ports_html}

</div>

</div>

<!-- TECHNOLOGIES -->

<div class="section">

<h2>
Technology Detection
</h2>

<div class="ports">

{technologies_html}

</div>

</div>

<!-- HTTP HEADERS -->

<div class="section">

<h2>
HTTP Security Headers
</h2>

{header_html}

</div>

<!-- SSL -->

<div class="section">

<h2>
SSL / TLS Analysis
</h2>

<div class="data-row">

<span class="data-key">
TLS Version
</span>

<span class="data-value">
{html.escape(str(tls_version))}
</span>

</div>

<div class="data-row">

<span class="data-key">
Cipher
</span>

<span class="data-value">
{html.escape(str(cipher))}
</span>

</div>

<div class="data-row">

<span class="data-key">
Cipher Strength
</span>

<span class="data-value">
{html.escape(str(cipher_bits))} bits
</span>

</div>

<div class="data-row">

<span class="data-key">
Certificate Common Name
</span>

<span class="data-value">
{html.escape(str(common_name))}
</span>

</div>

<div class="data-row">

<span class="data-key">
Certificate Issuer
</span>

<span class="data-value">
{html.escape(str(issuer))}
</span>

</div>

<div class="data-row">

<span class="data-key">
Valid Until
</span>

<span class="data-value">
{html.escape(str(valid_until))}
</span>

</div>

<div class="data-row">

<span class="data-key">
Days Remaining
</span>

<span class="data-value">
{html.escape(str(days_remaining))}
</span>

</div>

</div>

<!-- DNS -->

<div class="section">

<h2>
DNS Reconnaissance
</h2>

{dns_html}

</div>

<!-- WHOIS -->

<div class="section">

<h2>
WHOIS Information
</h2>

{whois_html}

</div>

<!-- MODULE SUMMARY -->

<div class="section">

<h2>
Reconnaissance Modules
</h2>

<div class="module-grid">

<div class="module">

<div class="module-name">
TCP Port Scan
</div>

<div class="module-status">
{module_status(port_scan)}
</div>

</div>

<div class="module">

<div class="module-name">
DNS Reconnaissance
</div>

<div class="module-status">
{module_status(dns_data)}
</div>

</div>

<div class="module">

<div class="module-name">
WHOIS
</div>

<div class="module-status">
{module_status(whois_data)}
</div>

</div>

<div class="module">

<div class="module-name">
HTTP Headers
</div>

<div class="module-status">
{module_status(headers_data)}
</div>

</div>

<div class="module">

<div class="module-name">
SSL/TLS Analysis
</div>

<div class="module-status">
{module_status(ssl_data)}
</div>

</div>

<div class="module">

<div class="module-name">
Technology Detection
</div>

<div class="module-status">
{module_status(technology_data)}
</div>

</div>

<div class="module">

<div class="module-name">
Intelligence Engine
</div>

<div class="module-status">
{module_status(intelligence)}
</div>

</div>

</div>

</div>

<!-- FOOTER -->

<div class="footer">

Nexora Cybersecurity Framework

<br>

Generated automatically

</div>

</div>

</body>

</html>
"""

    # -------------------------------------------------
    # SAFE FILE NAME
    # -------------------------------------------------

    safe_filename = (
        str(target)
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .replace(" ", "_")
    )

    file_timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"{safe_filename}_"
        f"{file_timestamp}.html"
    )

    filepath = os.path.join(
        output_dir,
        filename
    )

    # -------------------------------------------------
    # WRITE REPORT
    # -------------------------------------------------

    with open(
        filepath,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html_content)

    print(
        "\n[+] HTML report saved:"
    )

    print(
        f"    {filepath}"
    )

    return filepath
