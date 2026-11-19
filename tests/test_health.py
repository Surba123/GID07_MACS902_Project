def test_health_is_safe_and_successful(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok", "service": "macs902-pki-document-system"}
    assert "SECRET_KEY" not in response.get_data(as_text=True)


def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Trust every signature. Protect every document." in response.data


def test_missing_page_is_controlled(client):
    assert client.get("/missing").status_code == 404
