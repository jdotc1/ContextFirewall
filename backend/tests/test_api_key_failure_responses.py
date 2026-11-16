"""An explicitly presented invalid key must not silently read demo memories."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app import identity, main


def test_anonymous_and_valid_key_namespace_resolution(monkeypatch):
    observed = []

    async def recall(_query, *, namespaces):
        observed.append(namespaces)
        return "public test rules"

    async def lookup(_key):
        return "tenant-a"

    monkeypatch.setattr(main, "recall_rules", recall)
    monkeypatch.setattr(identity, "_namespace_for_key", lookup)
    client = TestClient(main.app)

    assert client.get("/rules").status_code == 200
    assert client.get("/rules", headers={"Authorization": "Bearer cf_live_valid"}).status_code == 200
    assert observed == [{"demo"}, {"tenant-a"}]


def test_invalid_or_revoked_api_key_returns_401_without_demo_fallback(monkeypatch):
    async def revoked(_key):
        return None

    async def no_recall(*_args, **_kwargs):
        raise AssertionError("Rejected keys must not recall demo memories")

    monkeypatch.setattr(identity, "_namespace_for_key", revoked)
    monkeypatch.setattr(main, "recall_rules", no_recall)
    response = TestClient(main.app).get(
        "/rules", headers={"Authorization": "Bearer cf_live_revoked"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "API key is invalid or revoked."}


def test_credential_store_outage_returns_503_without_private_details(monkeypatch):
    async def failed(_key):
        raise identity.ApiKeyStoreUnavailableError("private-db-address")

    async def no_recall(*_args, **_kwargs):
        raise AssertionError("Unavailable store must not recall demo memories")

    monkeypatch.setattr(identity, "_namespace_for_key", failed)
    monkeypatch.setattr(main, "recall_rules", no_recall)
    response = TestClient(main.app).get(
        "/rules", headers={"Authorization": "Bearer cf_live_valid"}
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "API key validation is temporarily unavailable."}
    assert "private-db-address" not in response.text
