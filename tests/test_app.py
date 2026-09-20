import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}


def test_index(client):
    assert client.get("/").json["service"] == "appsec-demo"


@pytest.mark.parametrize("name, expected", [(None, "world"), ("  Linh  ", "Linh"), ("Việt", "Việt")])
def test_greeting(client, name, expected):
    response = client.get("/api/greeting", query_string={} if name is None else {"name": name})
    assert response.status_code == 200
    assert response.json == {"message": f"Hello, {expected}!"}


@pytest.mark.parametrize("name", ["", "   ", "x" * 81, "a\nb"])
def test_invalid_name(client, name):
    assert client.get("/api/greeting", query_string={"name": name}).status_code == 400


def test_user_input_is_json_not_html(client):
    response = client.get("/api/greeting", query_string={"name": "<script>alert(1)</script>"})
    assert response.mimetype == "application/json"


def test_unknown_route(client):
    assert client.get("/missing").status_code == 404
