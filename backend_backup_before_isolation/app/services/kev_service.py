import httpx


KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KEVService:
    """Check whether a CVE appears in CISA's KEV catalog."""

    def get_cve(self, cve_id: str) -> dict:
        cve_id = cve_id.upper().strip()

        with httpx.Client(timeout=20.0) as client:
            response = client.get(KEV_CATALOG_URL)
            response.raise_for_status()

        catalog = response.json()

        for vulnerability in catalog.get(
            "vulnerabilities",
            [],
        ):
            if vulnerability.get("cveID") == cve_id:
                return {
                    "cve_id": cve_id,
                    "known_exploited": True,
                    "date_added": vulnerability.get(
                        "dateAdded"
                    ),
                    "vendor_project": vulnerability.get(
                        "vendorProject"
                    ),
                    "product": vulnerability.get(
                        "product"
                    ),
                    "vulnerability_name": vulnerability.get(
                        "vulnerabilityName"
                    ),
                    "short_description": vulnerability.get(
                        "shortDescription"
                    ),
                    "required_action": vulnerability.get(
                        "requiredAction"
                    ),
                    "due_date": vulnerability.get(
                        "dueDate"
                    ),
                }

        return {
            "cve_id": cve_id,
            "known_exploited": False,
            "date_added": None,
        }
