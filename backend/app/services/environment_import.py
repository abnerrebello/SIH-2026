import csv
import io
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    AssetCriticality,
    AssetRelationship,
    AssetVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
)


@dataclass
class ImportResult:
    assets_created: int
    assets_updated: int
    vulnerabilities_created: int
    vulnerabilities_updated: int
    relationships_created: int
    mappings_created: int
    errors: list[str]

    def to_dict(self) -> dict:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "vulnerabilities_created": self.vulnerabilities_created,
            "vulnerabilities_updated": self.vulnerabilities_updated,
            "relationships_created": self.relationships_created,
            "mappings_created": self.mappings_created,
            "errors": self.errors,
        }


class EnvironmentImportService:
    """Import assets, vulnerabilities and relationships from CSV."""

    REQUIRED_COLUMNS = {"record_type"}

    def import_csv(
        self,
        db: Session,
        content: bytes,
    ) -> ImportResult:
        result = ImportResult(
            assets_created=0,
            assets_updated=0,
            vulnerabilities_created=0,
            vulnerabilities_updated=0,
            relationships_created=0,
            mappings_created=0,
            errors=[],
        )

        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            result.errors.append(
                f"CSV must be UTF-8 encoded: {exc}"
            )
            return result

        reader = csv.DictReader(io.StringIO(text))

        if not reader.fieldnames:
            result.errors.append("CSV file has no header.")
            return result

        columns = {
            column.strip().lower()
            for column in reader.fieldnames
            if column
        }

        missing = self.REQUIRED_COLUMNS - columns

        if missing:
            result.errors.append(
                "Missing required column(s): "
                + ", ".join(sorted(missing))
            )
            return result

        rows = list(reader)

        # Pass 1: assets and vulnerabilities.
        for row_number, raw_row in enumerate(rows, start=2):
            row = self._normalize_row(raw_row)
            record_type = row.get("record_type", "").upper()

            try:
                if record_type == "ASSET":
                    self._upsert_asset(
                        db,
                        row,
                        result,
                    )

                elif record_type == "VULNERABILITY":
                    self._upsert_vulnerability(
                        db,
                        row,
                        result,
                    )

                elif record_type in {
                    "RELATIONSHIP",
                    "MAPPING",
                    "ASSET_VULNERABILITY",
                }:
                    continue

                elif not record_type:
                    result.errors.append(
                        f"Row {row_number}: record_type is required."
                    )

                else:
                    result.errors.append(
                        f"Row {row_number}: unknown record_type "
                        f"'{record_type}'."
                    )

            except (ValueError, KeyError) as exc:
                result.errors.append(
                    f"Row {row_number}: {exc}"
                )

        db.flush()

        # Pass 2: relationships and mappings.
        for row_number, raw_row in enumerate(rows, start=2):
            row = self._normalize_row(raw_row)
            record_type = row.get("record_type", "").upper()

            try:
                if record_type == "RELATIONSHIP":
                    self._create_relationship(
                        db,
                        row,
                        result,
                    )

                elif record_type in {
                    "MAPPING",
                    "ASSET_VULNERABILITY",
                }:
                    self._create_mapping(
                        db,
                        row,
                        result,
                    )

            except (ValueError, KeyError) as exc:
                result.errors.append(
                    f"Row {row_number}: {exc}"
                )

        db.commit()

        return result

    @staticmethod
    def _normalize_row(
        raw_row: dict[str | None, str | None],
    ) -> dict[str, str]:
        return {
            (key or "").strip().lower(): (
                value.strip()
                if isinstance(value, str)
                else ""
            )
            for key, value in raw_row.items()
        }

    def _upsert_asset(
        self,
        db: Session,
        row: dict[str, str],
        result: ImportResult,
    ) -> Asset:
        name = row.get("name")

        if not name:
            raise ValueError("Asset name is required.")

        asset = db.scalar(
            select(Asset).where(
                Asset.name == name
            )
        )

        criticality_raw = (
            row.get("criticality") or "MEDIUM"
        ).upper()

        try:
            criticality = AssetCriticality(
                criticality_raw
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid asset criticality "
                f"'{criticality_raw}'."
            ) from exc

        values = {
            "hostname": row.get("hostname") or None,
            "ip_address": row.get("ip_address") or None,
            "asset_type": (
                row.get("asset_type") or "UNKNOWN"
            ),
            "operating_system": (
                row.get("operating_system") or None
            ),
            "criticality": criticality,
            "internet_exposed": self._parse_bool(
                row.get("internet_exposed")
            ),
            "description": (
                row.get("description") or None
            ),
        }

        if asset is None:
            asset = Asset(
                name=name,
                **values,
            )
            db.add(asset)
            result.assets_created += 1
        else:
            for key, value in values.items():
                setattr(asset, key, value)
            result.assets_updated += 1

        return asset

    def _upsert_vulnerability(
        self,
        db: Session,
        row: dict[str, str],
        result: ImportResult,
    ) -> Vulnerability:
        cve_id = row.get("cve_id")

        if not cve_id:
            raise ValueError(
                "Vulnerability CVE ID is required."
            )

        cve_id = cve_id.upper()

        cvss_score = self._parse_float(
            row.get("cvss_score"),
            default=0.0,
        )

        severity_raw = (
            row.get("severity")
            or self._severity_from_cvss(cvss_score)
        ).upper()

        try:
            severity = VulnerabilitySeverity(
                severity_raw
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid vulnerability severity "
                f"'{severity_raw}'."
            ) from exc

        values = {
            "title": row.get("title") or cve_id,
            "description": row.get("description") or None,
            "cvss_score": cvss_score,
            "severity": severity,
            "exploitability_score": (
                self._parse_optional_float(
                    row.get("exploitability_score")
                )
            ),
            "actively_exploited": self._parse_bool(
                row.get("actively_exploited")
            ),
            "known_exploit": self._parse_bool(
                row.get("known_exploit")
            ),
            "remediation": row.get("remediation") or None,
        }

        vulnerability = db.scalar(
            select(Vulnerability).where(
                Vulnerability.cve_id == cve_id
            )
        )

        if vulnerability is None:
            vulnerability = Vulnerability(
                cve_id=cve_id,
                **values,
            )
            db.add(vulnerability)
            result.vulnerabilities_created += 1
        else:
            for key, value in values.items():
                setattr(
                    vulnerability,
                    key,
                    value,
                )
            result.vulnerabilities_updated += 1

        return vulnerability

    def _create_relationship(
        self,
        db: Session,
        row: dict[str, str],
        result: ImportResult,
    ) -> None:
        source_name = row.get("source_asset")
        target_name = row.get("target_asset")

        if not source_name or not target_name:
            raise ValueError(
                "Relationship requires source_asset "
                "and target_asset."
            )

        source = db.scalar(
            select(Asset).where(
                Asset.name == source_name
            )
        )

        target = db.scalar(
            select(Asset).where(
                Asset.name == target_name
            )
        )

        if source is None:
            raise ValueError(
                f"Source asset '{source_name}' not found."
            )

        if target is None:
            raise ValueError(
                f"Target asset '{target_name}' not found."
            )

        relationship_type = (
            row.get("relationship_type")
            or "NETWORK_ACCESS"
        )
        trust_level = (
            row.get("trust_level") or "MEDIUM"
        )

        existing = db.scalar(
            select(AssetRelationship).where(
                AssetRelationship.source_asset_id
                == source.id,
                AssetRelationship.target_asset_id
                == target.id,
                AssetRelationship.relationship_type
                == relationship_type,
            )
        )

        if existing:
            return

        db.add(
            AssetRelationship(
                source_asset_id=source.id,
                target_asset_id=target.id,
                relationship_type=relationship_type,
                trust_level=trust_level,
            )
        )

        result.relationships_created += 1

    def _create_mapping(
        self,
        db: Session,
        row: dict[str, str],
        result: ImportResult,
    ) -> None:
        asset_name = (
            row.get("asset_name")
            or row.get("asset")
            or row.get("name")
        )

        cve_id = row.get("cve_id")

        if not asset_name or not cve_id:
            raise ValueError(
                "Mapping requires asset_name and cve_id."
            )

        asset = db.scalar(
            select(Asset).where(
                Asset.name == asset_name
            )
        )

        vulnerability = db.scalar(
            select(Vulnerability).where(
                Vulnerability.cve_id
                == cve_id.upper()
            )
        )

        if asset is None:
            raise ValueError(
                f"Asset '{asset_name}' not found."
            )

        if vulnerability is None:
            raise ValueError(
                f"Vulnerability '{cve_id}' not found."
            )

        existing = db.scalar(
            select(AssetVulnerability).where(
                AssetVulnerability.asset_id == asset.id,
                AssetVulnerability.vulnerability_id
                == vulnerability.id,
            )
        )

        if existing:
            return

        db.add(
            AssetVulnerability(
                asset_id=asset.id,
                vulnerability_id=vulnerability.id,
                status=(
                    row.get("status") or "OPEN"
                ),
            )
        )

        result.mappings_created += 1

    @staticmethod
    def _parse_bool(
        value: str | None,
    ) -> bool:
        if not value:
            return False

        normalized = value.strip().lower()

        if normalized in {
            "true",
            "1",
            "yes",
            "y",
        }:
            return True

        if normalized in {
            "false",
            "0",
            "no",
            "n",
        }:
            return False

        raise ValueError(
            f"Invalid boolean value '{value}'."
        )

    @staticmethod
    def _parse_float(
        value: str | None,
        *,
        default: float,
    ) -> float:
        if not value:
            return default

        try:
            return float(value)
        except ValueError as exc:
            raise ValueError(
                f"Invalid numeric value '{value}'."
            ) from exc

    @staticmethod
    def _parse_optional_float(
        value: str | None,
    ) -> float | None:
        if not value:
            return None

        try:
            return float(value)
        except ValueError as exc:
            raise ValueError(
                f"Invalid numeric value '{value}'."
            ) from exc

    @staticmethod
    def _severity_from_cvss(
        cvss_score: float,
    ) -> str:
        if cvss_score >= 9.0:
            return "CRITICAL"
        if cvss_score >= 7.0:
            return "HIGH"
        if cvss_score >= 4.0:
            return "MEDIUM"
        if cvss_score > 0:
            return "LOW"
        return "NONE"
