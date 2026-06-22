from __future__ import annotations

from samoyed.attack.outcomes import (
    admin_outcome_metadata,
    is_attack_outcome_edge,
    matches_attack_outcome_target,
    virtual_outcome_target,
)
from samoyed.cloud.concepts import CloudProvider


def test_admin_outcome_metadata_aws():
    meta = admin_outcome_metadata(CloudProvider.AWS)
    assert meta["attack_outcome"] == "administrator-access"
    assert meta["outcome_concept"] == "AttackOutcome"


def test_is_attack_outcome_edge():
    assert is_attack_outcome_edge("CAN_PRIVESC_TO", {"attack_outcome": "administrator-access"})
    assert not is_attack_outcome_edge("READS", {"attack_outcome": "administrator-access"})
    assert not is_attack_outcome_edge("CAN_PRIVESC_TO", {})


def test_virtual_outcome_target():
    props = admin_outcome_metadata(CloudProvider.AWS)
    target = virtual_outcome_target(props, "Principal:alice")
    assert target["concept_type"] == "AttackOutcome"
    assert target["virtual"] is True
    assert target["node_id"] == "Principal:alice"


def test_matches_attack_outcome_target_filters_concept():
    props = admin_outcome_metadata(CloudProvider.AWS)
    assert matches_attack_outcome_target(
        "CAN_PRIVESC_TO",
        props,
        target_concept="AttackOutcome",
        target_resource_type=None,
    )
    assert not matches_attack_outcome_target(
        "CAN_PRIVESC_TO",
        props,
        target_concept="SecretStore",
        target_resource_type=None,
    )
