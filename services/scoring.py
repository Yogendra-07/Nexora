def calculate_score(findings):
    """
    Calculate Nexora's security configuration score.

    This is a simplified indicator and is NOT
    equivalent to CVSS or a formal vulnerability score.
    """

    score = 100

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    deductions = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 0
    }

    for finding in findings:

        severity = finding.get(
            "severity",
            "INFO"
        ).upper()

        if severity not in severity_counts:
            severity = "INFO"

        severity_counts[severity] += 1

        score -= deductions[severity]

    # Keep score between 0 and 100
    score = max(
        0,
        min(100, score)
    )

    return {
        "score": score,
        "severity_counts": severity_counts
    }


def get_rating(score):
    """
    Convert numerical score into a simple rating.
    """

    if score >= 90:
        return "Excellent"

    if score >= 75:
        return "Good"

    if score >= 50:
        return "Needs Improvement"

    if score >= 25:
        return "Poor"

    return "Critical"
