import json
import os
from datetime import datetime


def save_json_report(results):
    """
    Save Nexora scan results as a JSON report.
    """

    # Make sure output directory exists
    output_dir = "output"

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    # Get target
    target = results.target

    # Create a safe filename
    safe_target = (
        target
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .replace("[", "")
        .replace("]", "")
        .replace("(", "")
        .replace(")", "")
        .replace(" ", "_")
    )

    # Remove characters that can cause filename problems
    safe_target = "".join(
        character
        if character.isalnum()
        or character in "._-"
        else "_"
        for character in safe_target
    )

    # Timestamp
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"{safe_target}_{timestamp}.json"
    )

    filepath = os.path.join(
        output_dir,
        filename
    )

    # Get all results
    data = results.get_all()

    # Write JSON
    with open(
        filepath,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            default=str
        )

    print(
        f"\n[+] JSON report saved:"
        f"\n    {filepath}"
    )

    return filepath
