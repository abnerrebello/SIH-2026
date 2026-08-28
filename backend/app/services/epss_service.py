import httpx


EPSS_BASE_URL = "https://api.first.org/data/v1/epss"


class EPSSService:
    """Retrieve EPSS exploit prediction data for a CVE."""

    def get_score(self, cve_id: str) -> dict:
        params = {
            "cve": cve_id.upper().strip(),
        }

        with httpx.Client(timeout=20.0) as client:
            response = client.get(
                EPSS_BASE_URL,
                params=params,
            )
            response.raise_for_status()

        data = response.json()

        records = data.get("data", [])

        if not records:
            raise ValueError(
                f"No EPSS data found for {cve_id}."
            )

        record = records[0]

        return {
            "cve_id": record.get("cve"),
            "epss_score": float(record["epss"]),
            "epss_percentile": float(record["percentile"]),
            "date": record.get("date"),
        }
