from __future__ import annotations

from samoyed.attack.intercloud_map import describe_intercloud_paths
from samoyed.fixtures.registry import get_fixture, fixture_path
from samoyed.sessions import SESSION_STORE


def test_intercloud_tri_cloud_fixture_registered():
    assert get_fixture("intercloud-tri-cloud").id == "intercloud-tri-cloud"
    assert fixture_path("intercloud-tri-cloud").is_file()
    assert fixture_path("wif-aws-azure").is_file()
    assert fixture_path("wif-gcp-azure").is_file()


def test_describe_intercloud_paths_tri_cloud(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMOYED_HOME", str(tmp_path))
    SESSION_STORE._sessions.clear()
    record = SESSION_STORE.load_fixture("intercloud-tri-cloud", session_id="tri-cloud-map")

    payload = describe_intercloud_paths(SESSION_STORE, session_id=record.session_id)
    assert payload.get("session_id") == record.session_id
    assert payload.get("error") is None
    assert payload.get("bridges"), "expected WIF / cross-cloud bridges"
    mechanisms = {b.get("mechanism") for b in payload["bridges"]}
    assert "wif" in mechanisms

    providers_seen: set[str] = set()
    for bridge in payload["bridges"]:
        for key in ("src_provider", "dst_provider"):
            if bridge.get(key):
                providers_seen.add(bridge[key])
    assert len(providers_seen & {"aws", "gcp", "azure"}) >= 2

    assert payload.get("top_paths"), "expected attack paths from CI host"
    path_providers = set()
    for path in payload["top_paths"]:
        path_providers.update(path.get("providers") or [])
    # At least one path should cross clouds; overall map should mention 3 providers when possible
    assert len(path_providers & {"aws", "gcp", "azure"}) >= 2
