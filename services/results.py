from datetime import datetime


class Results:
    """
    Central storage for all Nexora scan results.
    """

    def __init__(self, target):

        self.target = target

        self.data = {
            "target": target,

            "timestamp":
                datetime.now().isoformat(),

            "port_scan": {},

            "dns": {},

            "whois": {},

            "headers": {},

            "ssl": {},

            "technology": {},

            "findings": [],

            "security_score": {},

            "intelligence": {}
        }

    def add(self, category, data):
        """
        Store module results under a category.
        """

        self.data[category] = data

    def add_finding(self, finding):
        """
        Add a security finding.
        """

        self.data["findings"].append(
            finding
        )

    def get(self, category):
        """
        Retrieve a specific category.
        """

        return self.data.get(
            category,
            {}
        )

    def get_all(self):
        """
        Return all collected results.
        """

        return self.data
