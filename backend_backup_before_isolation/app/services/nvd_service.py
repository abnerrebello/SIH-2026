from dataclasses import asdict, dataclass
import os
from typing import Any

import httpx


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class NVDVulnerability:
    cve_id: str
    source_identifier: str | None
    published: str | None
    last_modified: str | None
    status: str | None

    description: str | None

    cvss_version: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cvss_vector: str | None
    exploitability_score: float | None

    weaknesses: list[str]
    references: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NVDService:
    """Retrieve and normalize CVE data from the NVD 2.0 API."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY")

    def _headers(self) -> dict[str, str]:
        if not self.api_key:
            return {}
        return {"apiKey": self.api_key}

    @staticmethod
    def _description(cve: dict[str, Any]) -> str | None:
        for item in cve.get("descriptions", []):
            if item.get("lang") == "en":
                return item.get("value")

        descriptions = cve.get("descriptions", [])
        if descriptions:
            return descriptions[0].get("value")

        return None

    @staticmethod
    def _select_cvss(
        metrics: dict[str, Any],
    ) -> tuple[str | None, float | None, str | None, str | None, float | None]:
        # Prefer NVD CVSS v4.0 when available.
        v4 = metrics.get("cvssMetricV40", [])
        if v4:
            entry = v4[0]
            cvss = entry.get("cvssData", {})

            return (
                "4.0",
                cvss.get("baseScore"),
                cvss.get("baseSeverity"),
                cvss.get("vectorString"),
                entry.get("exploitabilityScore"),
            )

        # Fall back to CVSS v3.1.
        v31 = metrics.get("cvssMetricV31", [])
        if v31:
            entry = v31[0]
            cvss = entry.get("cvssData", {})

            return (
                "3.1",
                cvss.get("baseScore"),
                cvss.get("baseSeverity"),
                cvss.get("vectorString"),
                entry.get("exploitabilityScore"),
            )

        # Older records may only have v3.0.
        v30 = metrics.get("cvssMetricV30", [])
        if v30:
            entry = v30[0]
            cvss = entry.get("cvssData", {})

            return (
                "3.0",
                cvss.get("baseScore"),
                cvss.get("baseSeverity"),
                cvss.get("vectorString"),
                entry.get("exploitabilityScore"),
            )

        return None, None, None, None, None

    @staticmethod
    def _weaknesses(cve: dict[str, Any]) -> list[str]:
        result: list[str] = []

        for weakness in cve.get("weaknesses", []):
            for description in weakness.get("description", []):
                value = description.get("value")
                if value and value not in result:
                    result.append(value)

        return result

    @staticmethod
    def _references(cve: dict[str, Any]) -> list[str]:
        result: list[str] = []

        for reference in cve.get("references", []):
            url = reference.get("url")
            if url and url not in result:
                result.append(url)

        return result

    def get_cve(self, cve_id: str) -> dict[str, Any]:
        headers = self._headers()

        params = {
            "cveId": cve_id.upper().strip(),
        }

        with httpx.Client(
            timeout=20.0,
            headers=headers,
        ) as client:
            response = client.get(
                NVD_BASE_URL,
                params=params,
            )
            response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            raise ValueError(
                f"CVE {cve_id} was not found in NVD."
            )

        cve = vulnerabilities[0].get("cve", {})

        (
            cvss_version,
            cvss_score,
            cvss_severity,
            cvss_vector,
            exploitability_score,
        ) = self._select_cvss(
            cve.get("metrics", {})
        )

        normalized = NVDVulnerability(
            cve_id=cve.get("id", cve_id.upper().strip()),
            source_identifier=cve.get("sourceIdentifier"),
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            status=cve.get("vulnStatus"),
            description=self._description(cve),
            cvss_version=cvss_version,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cvss_vector=cvss_vector,
            exploitability_score=exploitability_score,
            weaknesses=self._weaknesses(cve),
            references=self._references(cve),
        )

        return normalized.to_dict()
