from app.mail_edge.simplelogin_repository import SimpleLoginAliasRoutingRepository
from tests.api.utils import get_new_user_and_api_key


def test_api_alias_lifecycle_controls_mail_edge_routing(flask_client):
    _, owner_key = get_new_user_and_api_key()
    _, other_key = get_new_user_and_api_key()
    owner_headers = {"Authentication": owner_key.code}
    other_headers = {"Authentication": other_key.code}

    assert flask_client.post("/api/alias/random/new").status_code == 401
    created = flask_client.post(
        "/api/alias/random/new", headers=owner_headers, json={"note": "mail launch"}
    )
    assert created.status_code == 201
    alias_id = created.json["id"]
    address = created.json["email"]
    domain = address.rsplit("@", 1)[1]
    path = f"/api/aliases/{alias_id}"
    repository = SimpleLoginAliasRoutingRepository()

    assert created.json["alias"] == address
    assert repository.resolve_or_create(address, domain).alias_id == alias_id
    assert repository.resolve_destination(alias_id).address == address

    assert flask_client.get(path, headers=other_headers).status_code == 403
    assert flask_client.post(f"{path}/toggle", headers=other_headers).status_code == 403
    assert flask_client.delete(path, headers=other_headers).status_code == 403
    assert repository.resolve_destination(alias_id).address == address

    disabled = flask_client.post(f"{path}/toggle", headers=owner_headers)
    assert disabled.status_code == 200
    assert disabled.json == {"enabled": False}
    assert repository.resolve_or_create(address, domain) is None
    assert repository.resolve_destination(alias_id) is None

    enabled = flask_client.post(f"{path}/toggle", headers=owner_headers)
    assert enabled.status_code == 200
    assert enabled.json == {"enabled": True}
    assert repository.resolve_destination(alias_id).address == address

    deleted = flask_client.delete(path, headers=owner_headers)
    assert deleted.status_code == 200
    assert deleted.json == {"deleted": True}
    assert repository.resolve_or_create(address, domain) is None
    assert repository.resolve_destination(alias_id) is None
