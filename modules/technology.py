import requests
import re


def detect_from_headers(headers):
    """
    Detect technologies using HTTP response headers.
    """

    technologies = []

    server = headers.get("Server", "").lower()
    powered_by = headers.get("X-Powered-By", "").lower()

    # Web servers
    if "nginx" in server:
        technologies.append("Nginx")

    if "apache" in server:
        technologies.append("Apache")

    if "iis" in server:
        technologies.append("Microsoft IIS")

    # Languages / frameworks
    if "php" in powered_by:
        technologies.append("PHP")

    if "asp.net" in powered_by:
        technologies.append("ASP.NET")

    if "express" in powered_by:
        technologies.append("Express.js")

    return technologies


def detect_from_html(html):
    """
    Detect common technologies using HTML indicators.
    """

    technologies = []

    html_lower = html.lower()

    # WordPress
    if "wp-content" in html_lower:
        technologies.append("WordPress")

    if "wp-includes" in html_lower:
        if "WordPress" not in technologies:
            technologies.append("WordPress")

    # React
    if "react" in html_lower:
        technologies.append("React")

    # Next.js
    if "_next/" in html_lower:
        technologies.append("Next.js")

    # Bootstrap
    if "bootstrap" in html_lower:
        technologies.append("Bootstrap")

    # jQuery
    if "jquery" in html_lower:
        technologies.append("jQuery")

    return technologies


def run_technology(target, results=None):
    """
    Performs passive web technology detection.

    The module analyzes HTTP headers and page
    content without exploiting the target.
    """

    print("\n" + "=" * 55)
    print("                 TECHNOLOGY DETECTION")
    print("=" * 55)

    if not target.startswith(("http://", "https://")):

        url = "https://" + target

    else:

        url = target

    print(f"\nTarget : {url}")

    print("\n[*] Analyzing web technologies...\n")

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent":
                    "Nexora/0.1 Technology Detector"
            }
        )

    except requests.exceptions.Timeout:

        print("[-] Request timed out.")
        return None

    except requests.exceptions.ConnectionError:

        print("[-] Could not connect to target.")
        return None

    except requests.exceptions.RequestException as error:

        print("[-] Request failed.")
        print(f"    Reason: {error}")
        return None

    technologies = []

    # Header detection
    header_technologies = detect_from_headers(
        response.headers
    )

    technologies.extend(
        header_technologies
    )

    # HTML detection
    html_technologies = detect_from_html(
        response.text
    )

    technologies.extend(
        html_technologies
    )

    # Remove duplicates while preserving order
    technologies = list(
        dict.fromkeys(technologies)
    )

    print("Detected Technologies")
    print("-" * 35)

    if technologies:

        for technology in technologies:

            print(
                f"[+] {technology}"
            )

    else:

        print(
            "[-] No known technologies detected."
        )

    print("\n" + "=" * 55)
    print("              TECHNOLOGY SCAN COMPLETE")
    print("=" * 55)

    # Store results
    if results is not None:

        results.add(
            "technology",
            {
                "url": response.url,
                "status_code":
                    response.status_code,
                "technologies":
                    technologies
            }
        )

    return technologies
