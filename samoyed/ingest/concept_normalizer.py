from __future__ import annotations

from samoyed.cloud.artifacts import ConceptArtifact
from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder


class ConceptNormalizer:
    def ingest(self, builder: GraphBuilder, artifacts: list[ConceptArtifact]) -> None:
        id_map: dict[str, str] = {}

        for artifact in artifacts:
            node_id = builder.add_concept_node(
                concept_type=artifact.concept_type,
                native_id=artifact.native_id,
                props={
                    "provider": artifact.provider.value,
                    "scope_id": artifact.scope_id,
                    **artifact.properties,
                    **(
                        {
                            "evidence": {
                                "kind": artifact.evidence.kind,
                                "details": artifact.evidence.details,
                            }
                        }
                        if artifact.evidence
                        else {}
                    ),
                    "confidence": artifact.confidence.value,
                },
            )
            id_map[artifact.native_id] = node_id
            builder.link_session(node_id)

        for artifact in artifacts:
            artifact_node = id_map[artifact.native_id]
            for edge in artifact.edges:
                src_id = id_map.get(edge.src_native_id or artifact.native_id, artifact_node)
                if edge.src_native_id and edge.src_native_id not in id_map:
                    src_id = builder.add_concept_node(
                        concept_type=ConceptType.IDENTITY,
                        native_id=edge.src_native_id,
                        props={"arn": edge.src_native_id},
                    )
                    id_map[edge.src_native_id] = src_id
                    builder.link_session(src_id)

                dst_id = id_map.get(edge.target_native_id)
                if not dst_id and edge.target_native_id:
                    if edge.target_concept_type:
                        dst_id = builder.add_concept_node(
                            concept_type=edge.target_concept_type,
                            native_id=edge.target_native_id,
                            props=edge.props,
                        )
                        id_map[edge.target_native_id] = dst_id
                        builder.link_session(dst_id)
                    else:
                        from samoyed.graph.model import GraphNode

                        label = edge.target_label or "Resource"
                        builder.snapshot.add_node(
                            GraphNode(
                                node_id=edge.target_native_id,
                                label=label,
                                props=edge.props,
                            )
                        )
                        dst_id = edge.target_native_id

                if dst_id:
                    builder.add_edge(
                        src_id=src_id,
                        rel_type=edge.rel_type,
                        dst_id=dst_id,
                        props={"confidence": edge.confidence.value, **edge.props},
                    )
