from fastapi.testclient import TestClient

def test_health():
    from app.main import app
    c=TestClient(app)
    assert c.get('/health').status_code==200

