from __future__ import annotations

from samoyed.cloud.artifacts import ConceptArtifact
from samoyed.cloud.concepts import ConceptType
from samoyed.graph.builder import GraphBuilder
from samoyed.graph.native_ids import canonical_native_id, infer_concept_type


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
            canonical = canonical_native_id(artifact.native_id)
            if canonical != artifact.native_id:
                id_map[canonical] = node_id
            builder.link_session(node_id)

        for artifact in artifacts:
            artifact_node = id_map[artifact.native_id]
            for edge in artifact.edges:
                src_ref = edge.src_native_id or artifact.native_id
                src_id = id_map.get(src_ref) or id_map.get(canonical_native_id(src_ref))
                if not src_id and edge.src_native_id:
                    src_canonical = canonical_native_id(edge.src_native_id)
                    src_id = builder.add_concept_node(
                        concept_type=infer_concept_type(src_canonical) or ConceptType.IDENTITY,
                        native_id=src_canonical,
                        props={"arn": edge.src_native_id if edge.src_native_id.startswith("arn:") else None},
                    )
                    id_map[edge.src_native_id] = src_id
                    id_map[src_canonical] = src_id
                    builder.link_session(src_id)
                if not src_id:
                    src_id = artifact_node

                target_ref = edge.target_native_id or ""
                target_canonical = canonical_native_id(target_ref)
                dst_id = id_map.get(target_ref) or id_map.get(target_canonical)
                if not dst_id and target_ref:
                    concept = edge.target_concept_type or infer_concept_type(target_canonical)
                    if concept:
                        dst_id = builder.add_concept_node(
                            concept_type=concept,
                            native_id=target_canonical,
                            props=edge.props,
                        )
                        id_map[target_ref] = dst_id
                        id_map[target_canonical] = dst_id
                        builder.link_session(dst_id)

                if dst_id:
                    builder.add_edge(
                        src_id=src_id,
                        rel_type=edge.rel_type,
                        dst_id=dst_id,
                        props={"confidence": edge.confidence.value, **edge.props},
                    )
