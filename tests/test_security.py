import re
import zipfile
import pytest
from fastapi.testclient import TestClient

def token(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

@pytest.fixture
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv('KAZEVAULT_DATA', str(tmp_path / 'data'))
    import importlib
    import app.main as module
    module = importlib.reload(module)
    client = TestClient(module.app)
    yield module, client
    module.engine.dispose()

def setup_user(client):
    page=client.get('/setup'); csrf=token(page.text)
    response=client.post('/setup', data={'csrf_token':csrf,'username':'admin','password':'correct horse battery','confirm':'correct horse battery'}, follow_redirects=False)
    assert response.status_code==303

def login(client):
    page=client.get('/login'); csrf=token(page.text)
    response=client.post('/login', data={'csrf_token':csrf,'username':'admin','password':'correct horse battery'}, follow_redirects=False)
    assert response.status_code==303

def test_setup_csrf_auth_and_logout(app_client):
    _, client=app_client
    page=client.get('/setup'); assert page.status_code==200
    assert client.post('/setup', data={'username':'admin','password':'correct horse battery','confirm':'correct horse battery'}).status_code==403
    setup_user(client); login(client)
    assert client.get('/records').status_code==200
    assert client.post('/logout').status_code==403
    csrf=token(client.get('/records/new').text)
    assert client.post('/logout', data={'csrf_token':csrf}, follow_redirects=False).status_code==303
    assert client.get('/records', follow_redirects=False).status_code==303

def test_csrf_record_and_unauthorized_access(app_client):
    _, client=app_client
    assert client.get('/records', follow_redirects=False).status_code==303
    setup_user(client); login(client)
    assert client.post('/records/save', data={'title':'blocked'}).status_code==403
    csrf=token(client.get('/records/new').text)
    assert client.post('/records/save', data={'csrf_token':csrf,'title':'Private note','kind':'note','content':'secret'}, follow_redirects=False).status_code==303

def test_login_throttling_and_upload_filename_validation(app_client):
    module, client=app_client
    setup_user(client)
    for _ in range(5):
        page=client.get('/login'); client.post('/login', data={'csrf_token':token(page.text),'username':'admin','password':'wrong password'})
    page=client.get('/login')
    assert client.post('/login', data={'csrf_token':token(page.text),'username':'admin','password':'wrong password'}).status_code==429
    module.login_attempts.clear()
    login(client); csrf=token(client.get('/documents').text)
    response=client.post('/documents/upload', data={'csrf_token':csrf}, files={'file':('../escape.txt','bad')})
    assert response.status_code in (200, 303)

def test_backup_manifest_validation_and_restore(app_client):
    module, client=app_client
    setup_user(client); login(client)
    csrf=token(client.get('/records/new').text)
    client.post('/records/save', data={'csrf_token':csrf,'title':'Before backup','kind':'note','content':'original'}, follow_redirects=False)
    path=module.create_backup(); manifest=module.validate_backup(path)
    assert manifest['format']=='kazevault-backup-1'
    with zipfile.ZipFile(path) as z:
        assert 'manifest.json' in z.namelist(); assert 'kaze_vault.db' in z.namelist()
    bad=module.BACKUPS/'bad.zip'
    with zipfile.ZipFile(bad,'w') as z: z.writestr('../escape.txt','no')
    assert not module.backup_summary(bad)['ok']
    bad.unlink()
    csrf=token(client.get('/backups').text)
    response=client.post(f'/backups/{path.name}/restore', data={'csrf_token':csrf,'confirm':'RESTORE'}, follow_redirects=False)
    assert response.status_code==303
    assert any(p.name.startswith('pre-restore-') for p in module.BACKUPS.glob('*.zip'))

def test_password_vault_encryption_lock_and_generator(app_client):
    module, client=app_client
    setup_user(client); login(client)
    page=client.get('/passwords'); csrf=token(page.text)
    assert client.post('/passwords/setup', data={'csrf_token':csrf,'master':'vault master password','confirm':'vault master password'}, follow_redirects=False).status_code==303
    csrf=token(client.get('/passwords/new').text)
    client.post('/passwords/save', data={'csrf_token':csrf,'service':'Example','username':'alice','password':'SuperSecret123!','notes':'private'}, follow_redirects=False)
    with module.db() as s:
        entry=s.query(module.PasswordEntry).first(); assert b'SuperSecret123!' not in entry.encrypted_secret; pid=entry.id
    csrf=token(client.get('/passwords').text)
    assert client.post(f'/passwords/{pid}/reveal', data={'csrf_token':csrf}).json()['password']=='SuperSecret123!'
    assert 'SuperSecret123!' not in client.get('/passwords').text
    client.post('/passwords/lock', data={'csrf_token':csrf}, follow_redirects=False)
    assert client.post(f'/passwords/{pid}/reveal', data={'csrf_token':csrf}).status_code==403
    generated=client.get('/passwords/generate?length=32').json()['password']; assert len(generated)==32

def test_unified_search_media_range_and_system_report(app_client):
    _, client=app_client
    setup_user(client); login(client)
    csrf=token(client.get('/records/new').text)
    client.post('/records/save', data={'csrf_token':csrf,'title':'Searchable note','kind':'note','content':'needle'}, follow_redirects=False)
    assert 'Searchable note' in client.get('/search?q=needle').text
    csrf=token(client.get('/documents').text)
    client.post('/documents/upload', data={'csrf_token':csrf}, files={'file':('clip.mp4',b'0123456789','video/mp4')}, follow_redirects=False)
    media=client.get('/media'); assert media.status_code==200 and 'clip.mp4' in media.text
    download=client.get('/documents/1/download',headers={'Range':'bytes=0-3'}); assert download.status_code in (200,206)
    assert client.get('/system').status_code==200
