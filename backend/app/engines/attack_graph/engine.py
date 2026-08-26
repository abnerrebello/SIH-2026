from dataclasses import dataclass, field

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetRelationship, AssetVulnerability


@dataclass
class AttackPath:
    source_asset_id: int
    target_asset_id: int
    asset_ids: list[int]
    asset_names: list[str]
    vulnerabilities: list[str]
    path_length: int
    target_criticality: str
    risk_score: float
    choke_points: list[int] = field(default_factory=list)


@dataclass
class AttackGraphResult:
    nodes: list[dict]
    edges: list[dict]
    paths: list[AttackPath]
    choke_points: list[dict]


class AttackGraphEngine:
    def __init__(self, db: Session):
        self.db = db
        self.graph = nx.DiGraph()

        self.assets = {
            asset.id: asset
            for asset in db.scalars(select(Asset)).all()
        }

        self.relationships = db.scalars(
            select(AssetRelationship)
        ).all()

        self.asset_vulnerabilities = db.scalars(
            select(AssetVulnerability)
        ).all()

        self.vulnerabilities_by_asset: dict[int, list[str]] = {}

        for mapping in self.asset_vulnerabilities:
            vulnerability = mapping.vulnerability
            self.vulnerabilities_by_asset.setdefault(
                mapping.asset_id,
                [],
            ).append(vulnerability.cve_id)

        self._build_graph()

    def _build_graph(self) -> None:
        for asset in self.assets.values():
            self.graph.add_node(
                asset.id,
                name=asset.name,
                asset_type=asset.asset_type,
                criticality=asset.criticality.value,
                internet_exposed=asset.internet_exposed,
            )

        for relationship in self.relationships:
            self.graph.add_edge(
                relationship.source_asset_id,
                relationship.target_asset_id,
                relationship_type=relationship.relationship_type,
                trust_level=relationship.trust_level,
            )

    @staticmethod
    def _criticality_weight(criticality: str) -> float:
        return {
            "LOW": 10.0,
            "MEDIUM": 25.0,
            "HIGH": 45.0,
            "CRITICAL": 70.0,
        }.get(criticality, 25.0)

    def _path_risk(
        self,
        path: list[int],
    ) -> float:
        target = self.assets[path[-1]]

        target_score = self._criticality_weight(
            target.criticality.value
        )

        vulnerability_bonus = 0.0

        for asset_id in path:
            vulnerability_count = len(
                self.vulnerabilities_by_asset.get(asset_id, [])
            )
            vulnerability_bonus += min(
                vulnerability_count * 8.0,
                24.0,
            )

        exposure_bonus = 15.0 if self.assets[path[0]].internet_exposed else 0.0

        path_penalty = max(
            0.0,
            (len(path) - 2) * 3.0,
        )

        score = (
            target_score
            + vulnerability_bonus
            + exposure_bonus
            - path_penalty
        )

        return round(min(score, 100.0), 2)

    def _choke_point_ids(
        self,
        paths: list[list[int]],
    ) -> set[int]:
        appearances: dict[int, int] = {}

        for path in paths:
            for asset_id in path[1:-1]:
                appearances[asset_id] = appearances.get(asset_id, 0) + 1

        return {
            asset_id
            for asset_id, count in appearances.items()
            if count >= 2
        }

    def analyze(self) -> AttackGraphResult:
        internet_assets = [
            asset
            for asset in self.assets.values()
            if asset.internet_exposed
        ]

        critical_assets = [
            asset
            for asset in self.assets.values()
            if asset.criticality.value == "CRITICAL"
        ]

        raw_paths: list[list[int]] = []

        for source in internet_assets:
            for target in critical_assets:
                if source.id == target.id:
                    continue

                if nx.has_path(self.graph, source.id, target.id):
                    paths = nx.all_simple_paths(
                        self.graph,
                        source=source.id,
                        target=target.id,
                        cutoff=8,
                    )

                    raw_paths.extend(paths)

        choke_points = self._choke_point_ids(raw_paths)

        analyzed_paths: list[AttackPath] = []

        for path in raw_paths:
            target = self.assets[path[-1]]

            vulnerability_ids: list[str] = []

            for asset_id in path:
                vulnerability_ids.extend(
                    self.vulnerabilities_by_asset.get(
                        asset_id,
                        [],
                    )
                )

            analyzed_paths.append(
                AttackPath(
                    source_asset_id=path[0],
                    target_asset_id=path[-1],
                    asset_ids=path,
                    asset_names=[
                        self.assets[asset_id].name
                        for asset_id in path
                    ],
                    vulnerabilities=sorted(
                        set(vulnerability_ids)
                    ),
                    path_length=len(path) - 1,
                    target_criticality=target.criticality.value,
                    risk_score=self._path_risk(path),
                    choke_points=[
                        asset_id
                        for asset_id in path
                        if asset_id in choke_points
                    ],
                )
            )

        analyzed_paths.sort(
            key=lambda item: item.risk_score,
            reverse=True,
        )

        nodes = [
            {
                "id": asset.id,
                "name": asset.name,
                "asset_type": asset.asset_type,
                "criticality": asset.criticality.value,
                "internet_exposed": asset.internet_exposed,
            }
            for asset in self.assets.values()
        ]

        edges = [
            {
                "source": relationship.source_asset_id,
                "target": relationship.target_asset_id,
                "relationship_type": relationship.relationship_type,
                "trust_level": relationship.trust_level,
            }
            for relationship in self.relationships
        ]

        choke_point_output = []

        for asset_id in sorted(choke_points):
            asset = self.assets[asset_id]

            appearances = sum(
                asset_id in path
                for path in raw_paths
            )

            choke_point_output.append(
                {
                    "asset_id": asset_id,
                    "asset_name": asset.name,
                    "criticality": asset.criticality.value,
                    "path_count": appearances,
                    "vulnerabilities": self.vulnerabilities_by_asset.get(
                        asset_id,
                        [],
                    ),
                }
            )

        return AttackGraphResult(
            nodes=nodes,
            edges=edges,
            paths=analyzed_paths,
            choke_points=choke_point_output,
        )
