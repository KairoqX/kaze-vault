import os, secrets, shutil, sqlite3, zipfile, tempfile, time, hmac, re, json, hashlib, uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine, String, Text, Boolean, DateTime, ForeignKey, or_, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv('KAZEVAULT_DATA', ROOT/'data')); ATTACH = DATA/'attachments'; BACKUPS = ROOT/'backups'
DATA.mkdir(parents=True, exist_ok=True); ATTACH.mkdir(parents=True, exist_ok=True); BACKUPS.mkdir(parents=True, exist_ok=True)
DB = DATA/'kaze_vault.db'
engine = create_engine(f'sqlite:///{DB}', connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
ph = PasswordHasher()

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__='users'; id: Mapped[int]=mapped_column(primary_key=True); username: Mapped[str]=mapped_column(String(80), unique=True); password_hash: Mapped[str]=mapped_column(String(255)); created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
class Record(Base):
    __tablename__='records'; id: Mapped[int]=mapped_column(primary_key=True); kind: Mapped[str]=mapped_column(String(20), default='record'); title: Mapped[str]=mapped_column(String(200)); content: Mapped[str]=mapped_column(Text, default=''); category: Mapped[str]=mapped_column(String(80), default=''); tags: Mapped[str]=mapped_column(String(500), default=''); favorite: Mapped[bool]=mapped_column(Boolean, default=False); entry_date: Mapped[str]=mapped_column(String(20), nullable=True); created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow); updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
class Attachment(Base):
    __tablename__='attachments'; id: Mapped[int]=mapped_column(primary_key=True); stored_name: Mapped[str]=mapped_column(String(100), unique=True); original_name: Mapped[str]=mapped_column(String(255)); content_type: Mapped[str]=mapped_column(String(100), default='application/octet-stream'); size: Mapped[int]=mapped_column(default=0); category: Mapped[str]=mapped_column(String(80), default=''); created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
Base.metadata.create_all(engine)

SESSION_SECRET=os.getenv('KAZEVAULT_SESSION_SECRET') or secrets.token_urlsafe(48)
app=FastAPI(title='KazeVault'); app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=28800, same_site='lax', https_only=os.getenv('KAZEVAULT_HTTPS','0')=='1')
templates=Jinja2Templates(directory=str(ROOT/'app/templates'))
app.mount('/static', StaticFiles(directory=str(ROOT/'app/static')), name='static')
MAX_UPLOAD=25*1024*1024; ALLOWED={'pdf','txt','md','png','jpg','jpeg','gif','webp','docx','xlsx','csv'}; LOGIN_WINDOW=300; LOGIN_MAX=5
BACKUP_FORMAT='kazevault-backup-1'; MAX_BACKUP_ARCHIVE=2*1024*1024*1024
login_attempts={}
def db(): return SessionLocal()
def user(request): return request.session.get('uid')
def require(request):
    if not user(request): raise HTTPException(303, headers={'Location':'/login'})
def csrf(request: Request):
    token=request.session.get('csrf_token')
    if not token:
        token=secrets.token_urlsafe(32); request.session['csrf_token']=token
    return token
async def csrf_protect(request: Request):
    form=await request.form(); expected=request.session.get('csrf_token'); supplied=form.get('csrf_token','')
    if not expected or not supplied or not hmac.compare_digest(str(expected),str(supplied)): raise HTTPException(403,'Invalid CSRF token')
def login_allowed(request: Request):
    now=time.monotonic(); key=request.client.host if request.client else 'unknown'; recent=[t for t in login_attempts.get(key,[]) if now-t<LOGIN_WINDOW]; login_attempts[key]=recent
    if len(recent)>=LOGIN_MAX: raise HTTPException(429,'Too many login attempts. Try again later.')
    recent.append(now)
def setup_needed():
    with db() as s: return s.query(User).count()==0
def ctx(request, **kw): return {'request':request, 'setup_needed':setup_needed(), 'csrf_token':csrf(request), 'flash':request.session.pop('flash',None), **kw}

def _safe_zip_name(name):
    p=Path(name.replace('\\','/'))
    return bool(name) and not p.is_absolute() and '..' not in p.parts and not name.startswith(('/', '\\'))
def _sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()
def _backup_paths(name):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',name or '') or not name.endswith('.zip'): raise HTTPException(400,'Invalid backup name')
    p=(BACKUPS/name).resolve()
    if p.parent!=BACKUPS.resolve(): raise HTTPException(400,'Invalid backup path')
    return p
def create_backup(prefix='kazevault'):
    stamp=datetime.utcnow().strftime('%Y%m%d-%H%M%S'); out=BACKUPS/f'{prefix}-{stamp}-{secrets.token_hex(4)}.zip'; temp=BACKUPS/f'.{uuid.uuid4().hex}.tmp'; dbtmp=BACKUPS/f'.{uuid.uuid4().hex}.dbtmp'
    try:
        con=sqlite3.connect(DB); dcon=sqlite3.connect(dbtmp); con.backup(dcon); dcon.close(); con.close()
        check=sqlite3.connect(dbtmp); ok=check.execute('PRAGMA integrity_check').fetchone()[0]; check.close()
        if ok!='ok': raise RuntimeError('SQLite integrity check failed while creating backup')
        inventory=[]
        for p in sorted(ATTACH.iterdir()):
            if p.is_file(): inventory.append({'path':'attachments/'+p.name,'size':p.stat().st_size,'sha256':_sha256(p)})
        manifest={'format':BACKUP_FORMAT,'created_at':datetime.utcnow().isoformat()+'Z','database_filename':'kaze_vault.db','attachments':inventory}
        with zipfile.ZipFile(temp,'x',zipfile.ZIP_DEFLATED) as z:
            z.write(dbtmp,'kaze_vault.db'); z.writestr('manifest.json',json.dumps(manifest,indent=2))
            for item in inventory: z.write(ATTACH/item['path'].split('/',1)[1],item['path'])
        temp.replace(out); return out
    except (OSError, sqlite3.Error, zipfile.BadZipFile) as e:
        raise RuntimeError(f'Backup failed: {e}') from e
    finally:
        for p in (temp,dbtmp):
            try: p.unlink()
            except FileNotFoundError: pass
def validate_backup(path):
    if not path.is_file() or path.stat().st_size>MAX_BACKUP_ARCHIVE: raise ValueError('Backup is missing or exceeds the safety size limit')
    with zipfile.ZipFile(path) as z:
        names=z.namelist()
        if len(names)!=len(set(names)): raise ValueError('Backup contains duplicate archive paths')
        if any(not _safe_zip_name(n) for n in names): raise ValueError('Backup contains an unsafe archive path')
        allowed={'manifest.json','kaze_vault.db'}|{n for n in names if n.startswith('attachments/')}
        if any(n not in allowed for n in names): raise ValueError('Backup contains unexpected files')
        if 'manifest.json' not in names or 'kaze_vault.db' not in names: raise ValueError('Backup is missing required files')
        try: manifest=json.loads(z.read('manifest.json'))
        except (ValueError,UnicodeDecodeError): raise ValueError('Backup manifest is invalid JSON')
        if manifest.get('format')!=BACKUP_FORMAT or manifest.get('database_filename')!='kaze_vault.db' or not isinstance(manifest.get('attachments'),list): raise ValueError('Unsupported or invalid backup manifest')
        listed={x.get('path') for x in manifest['attachments']}
        if any(not isinstance(x,dict) or not isinstance(x.get('path'),str) or not _safe_zip_name(x['path']) or not x['path'].startswith('attachments/') for x in manifest['attachments']): raise ValueError('Invalid attachment inventory')
        actual={n for n in names if n.startswith('attachments/')}
        if listed!=actual: raise ValueError('Attachment inventory does not match archive contents')
        with tempfile.TemporaryDirectory() as td:
            dbcopy=Path(td)/'kaze_vault.db'; dbcopy.write_bytes(z.read('kaze_vault.db')); c=sqlite3.connect(dbcopy); result=c.execute('PRAGMA integrity_check').fetchone()[0]; c.close()
            if result!='ok': raise ValueError('Backup database failed SQLite integrity check')
        for item in manifest['attachments']:
            data=z.read(item['path'])
            if len(data)!=item.get('size') or hashlib.sha256(data).hexdigest()!=item.get('sha256'): raise ValueError(f"Attachment integrity check failed: {item['path']}")
    return manifest
def backup_summary(path):
    try:
        m=validate_backup(path); return {'ok':True,'created_at':m['created_at'],'attachments':len(m['attachments']),'error':None}
    except Exception as e: return {'ok':False,'created_at':'unknown','attachments':0,'error':str(e)}

@app.get('/', response_class=HTMLResponse)
def home(request: Request):
    if setup_needed(): return RedirectResponse('/setup', 303)
    if not user(request): return RedirectResponse('/login', 303)
    with db() as s:
        counts={k:s.query(Record).filter(Record.kind==k).count() for k in ('record','note','journal','knowledge')}; recent=s.query(Record).order_by(Record.updated_at.desc()).limit(6).all(); cats=s.query(Record.category,func.count(Record.id)).filter(Record.category!='').group_by(Record.category).all()
    return templates.TemplateResponse('dashboard.html',ctx(request, counts=counts,recent=recent,cats=cats))
@app.get('/setup', response_class=HTMLResponse)
def setup(request: Request): return RedirectResponse('/',303) if not setup_needed() else templates.TemplateResponse('setup.html',ctx(request))
@app.post('/setup')
def setup_post(request: Request, username: str=Form(...), password: str=Form(...), confirm: str=Form(...), _: None=Depends(csrf_protect)):
    if not setup_needed(): raise HTTPException(403)
    if len(username.strip())<3 or len(password)<10 or password!=confirm: return templates.TemplateResponse('setup.html',ctx(request,error='Use a username of 3+ characters, a password of 10+ characters, and matching confirmation.'))
    with db() as s: s.add(User(username=username.strip(),password_hash=ph.hash(password))); s.commit()
    return RedirectResponse('/login',303)
@app.get('/login',response_class=HTMLResponse)
def login(request: Request): return templates.TemplateResponse('login.html',ctx(request,error=None))
@app.post('/login')
def login_post(request: Request, username: str=Form(...), password: str=Form(...), _: None=Depends(csrf_protect)):
    login_allowed(request)
    with db() as s: u=s.query(User).filter_by(username=username.strip()).first()
    try: ok=u and ph.verify(u.password_hash,password)
    except (VerifyMismatchError, Exception): ok=False
    if not ok: return templates.TemplateResponse('login.html',ctx(request,error='Invalid credentials.'))
    key=request.client.host if request.client else 'unknown'; login_attempts.pop(key,None)
    request.session.clear(); request.session['uid']=u.id; csrf(request); return RedirectResponse('/',303)
@app.post('/logout')
def logout(request: Request, _: None=Depends(csrf_protect)): request.session.clear(); return RedirectResponse('/login',303)

@app.get('/records',response_class=HTMLResponse)
def records(request: Request, q: str='', kind: str='', page:int=1):
    require(request); page=max(1,page)
    with db() as s:
        query=s.query(Record)
        if kind: query=query.filter(Record.kind==kind)
        if q: like=f'%{q}%'; query=query.filter(or_(Record.title.ilike(like),Record.content.ilike(like),Record.tags.ilike(like),Record.category.ilike(like)))
        items=query.order_by(Record.favorite.desc(),Record.updated_at.desc()).offset((page-1)*20).limit(21).all()
    return templates.TemplateResponse('records.html',ctx(request,items=items[:20],has_next=len(items)>20,q=q,kind=kind,page=page))
@app.get('/records/new',response_class=HTMLResponse)
def new_record(request: Request,kind='record'): require(request); return templates.TemplateResponse('edit.html',ctx(request,record=None,kind=kind))
@app.post('/records/save')
def save_record(request:Request, id:int=Form(0), kind:str=Form('record'), title:str=Form(...), content:str=Form(''), category:str=Form(''), tags:str=Form(''), entry_date:str=Form(''), favorite:bool=Form(False), _: None=Depends(csrf_protect)):
    require(request)
    if not title.strip(): return templates.TemplateResponse('edit.html',ctx(request,record=None,kind=kind,error='Title is required.'))
    with db() as s:
        r=s.get(Record,id) if id else Record(kind=kind,title=title.strip())
        if not r: raise HTTPException(404)
        r.kind=kind; r.title=title.strip(); r.content=content; r.category=category.strip(); r.tags=tags.strip(); r.entry_date=entry_date.strip() or None; r.favorite=favorite
        s.add(r); s.commit()
    return RedirectResponse('/records',303)
@app.get('/records/{rid}/edit',response_class=HTMLResponse)
def edit(request: Request,rid:int):
    require(request)
    with db() as s: r=s.get(Record,rid)
    if not r: raise HTTPException(404)
    return templates.TemplateResponse('edit.html',ctx(request,record=r,kind=r.kind))
@app.post('/records/{rid}/delete')
def delete_record(request: Request,rid:int, _: None=Depends(csrf_protect)):
    require(request)
    with db() as s: r=s.get(Record,rid); s.delete(r) if r else None; s.commit()
    return RedirectResponse('/records',303)

@app.get('/documents',response_class=HTMLResponse)
def documents(request: Request):
    require(request)
    with db() as s: items=s.query(Attachment).order_by(Attachment.created_at.desc()).all()
    return templates.TemplateResponse('documents.html',ctx(request,items=items,error=None))
@app.post('/documents/upload')
async def upload(request:Request,file:UploadFile=File(...),category:str=Form(''), _: None=Depends(csrf_protect)):
    require(request); suffix=Path(file.filename or '').suffix.lower().lstrip('.')
    original=file.filename or ''
    if suffix not in ALLOWED or Path(original).name != original or any(ord(c)<32 for c in original): return templates.TemplateResponse('documents.html',ctx(request,items=[],error='File type or filename is not allowed.'))
    data=await file.read()
    if len(data)>MAX_UPLOAD: raise HTTPException(413,'File exceeds 25 MB limit')
    stored=secrets.token_hex(16)+'.'+suffix; (ATTACH/stored).write_bytes(data)
    with db() as s: s.add(Attachment(stored_name=stored,original_name=Path(file.filename).name,content_type=file.content_type or 'application/octet-stream',size=len(data),category=category)); s.commit()
    return RedirectResponse('/documents',303)
@app.get('/documents/{aid}/download')
def download(request: Request,aid:int):
    require(request)
    with db() as s: a=s.get(Attachment,aid)
    if not a or not (ATTACH/a.stored_name).is_file(): raise HTTPException(404)
    response=FileResponse(ATTACH/a.stored_name,filename=a.original_name,media_type=a.content_type)
    response.headers['X-Content-Type-Options']='nosniff'; response.headers['Content-Security-Policy']="default-src 'none'; frame-ancestors 'none'"
    return response
@app.post('/documents/{aid}/delete')
def delete_doc(request: Request,aid:int, _: None=Depends(csrf_protect)):
    require(request)
    with db() as s: a=s.get(Attachment,aid); p=ATTACH/a.stored_name if a else None; s.delete(a) if a else None; s.commit()
    if p and p.is_file(): p.unlink()
    return RedirectResponse('/documents',303)

@app.post('/backup')
def backup(request: Request, _: None=Depends(csrf_protect)):
    require(request)
    try: out=create_backup(); request.session['flash']=f'Backup created: {out.name}'
    except Exception as e: request.session['flash']=f'Backup failed: {e}'
    return RedirectResponse('/backups',303)
@app.get('/backups',response_class=HTMLResponse)
def backups(request: Request):
    require(request); items=[]
    for p in sorted(BACKUPS.glob('*.zip'),reverse=True):
        s=backup_summary(p); s.update({'name':p.name,'size':p.stat().st_size}); items.append(s)
    return templates.TemplateResponse('backups.html',ctx(request,items=items,storage=sum(x['size'] for x in items)))
@app.get('/backups/{name}/download')
def download_backup(request: Request,name: str):
    require(request); p=_backup_paths(name)
    if not p.is_file(): raise HTTPException(404)
    return FileResponse(p,filename=p.name,media_type='application/zip')
@app.post('/backups/{name}/verify')
def verify_backup(request: Request,name: str, _: None=Depends(csrf_protect)):
    require(request); p=_backup_paths(name)
    s=backup_summary(p); request.session['flash']=f"Backup verified: {name}" if s['ok'] else f"Verification failed: {s['error']}"
    return RedirectResponse('/backups',303)
@app.post('/backups/{name}/delete')
def delete_backup(request: Request,name: str, _: None=Depends(csrf_protect)):
    require(request); p=_backup_paths(name); s=backup_summary(p)
    valid=[x for x in BACKUPS.glob('*.zip') if backup_summary(x)['ok']]
    if s['ok'] and len(valid)<=1: request.session['flash']='The only verified backup cannot be deleted.'
    elif p.is_file(): p.unlink(); request.session['flash']=f'Deleted backup: {name}'
    else: request.session['flash']='Backup was not found.'
    return RedirectResponse('/backups',303)
@app.post('/backups/{name}/restore')
def restore_backup(request: Request,name: str,confirm: str=Form(''), _: None=Depends(csrf_protect)):
    require(request); p=_backup_paths(name)
    if confirm!='RESTORE': request.session['flash']='Type RESTORE in the confirmation field to continue.'; return RedirectResponse('/backups',303)
    try:
        manifest=validate_backup(p); pre=create_backup('pre-restore')
        token=uuid.uuid4().hex; stage=DATA/f'.restore-{token}'; staged_db=stage/'kaze_vault.db'; staged_attach=stage/'attachments'; stage.mkdir(); staged_attach.mkdir()
        with zipfile.ZipFile(p) as z:
            z.extract('kaze_vault.db',stage); z.extractall(stage,members=[n for n in z.namelist() if n.startswith('attachments/')])
        engine.dispose(); old_db=DATA/f'.pre-restore-{token}.db'; old_attach=DATA/f'.pre-restore-{token}-attachments'
        os.replace(DB,old_db); os.replace(staged_db,DB); os.replace(ATTACH,old_attach); os.replace(staged_attach,ATTACH)
        shutil.rmtree(stage,ignore_errors=True); shutil.rmtree(old_attach,ignore_errors=True); old_db.unlink(missing_ok=True)
        request.session['flash']=f'Restored {name}. A verified pre-restore backup was created as {pre.name}; restart KazeVault now.'
    except Exception as e:
        try:
            if 'old_db' in locals() and old_db.exists():
                if DB.exists(): DB.unlink()
                os.replace(old_db,DB)
            if 'old_attach' in locals() and old_attach.exists():
                if ATTACH.exists(): shutil.rmtree(ATTACH,ignore_errors=True)
                os.replace(old_attach,ATTACH)
        except Exception: pass
        if 'stage' in locals(): shutil.rmtree(stage,ignore_errors=True)
        request.session['flash']=f'Restore failed; existing data was preserved where possible: {e}'
    return RedirectResponse('/backups',303)
@app.get('/health')
def health(): return {'ok':True,'setup_needed':setup_needed()}

