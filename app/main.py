import os, secrets, shutil, sqlite3, zipfile, tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
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

app=FastAPI(title='KazeVault'); app.add_middleware(SessionMiddleware, secret_key=os.getenv('KAZEVAULT_SESSION_SECRET', secrets.token_hex(32)), max_age=28800, same_site='lax', https_only=os.getenv('KAZEVAULT_HTTPS','0')=='1')
templates=Jinja2Templates(directory=str(ROOT/'app/templates'))
app.mount('/static', StaticFiles(directory=str(ROOT/'app/static')), name='static')
MAX_UPLOAD=25*1024*1024; ALLOWED={'pdf','txt','md','png','jpg','jpeg','gif','webp','docx','xlsx','csv'}
def db(): return SessionLocal()
def user(request): return request.session.get('uid')
def require(request):
    if not user(request): raise HTTPException(303, headers={'Location':'/login'})
def setup_needed():
    with db() as s: return s.query(User).count()==0
def ctx(request, **kw): return {'request':request, 'setup_needed':setup_needed(), **kw}

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
def setup_post(request: Request, username: str=Form(...), password: str=Form(...), confirm: str=Form(...)):
    if not setup_needed(): raise HTTPException(403)
    if len(username.strip())<3 or len(password)<10 or password!=confirm: return templates.TemplateResponse('setup.html',ctx(request,error='Use a username of 3+ characters, a password of 10+ characters, and matching confirmation.'))
    with db() as s: s.add(User(username=username.strip(),password_hash=ph.hash(password))); s.commit()
    return RedirectResponse('/login',303)
@app.get('/login',response_class=HTMLResponse)
def login(request: Request): return templates.TemplateResponse('login.html',ctx(request,error=None))
@app.post('/login')
def login_post(request: Request, username: str=Form(...), password: str=Form(...)):
    with db() as s: u=s.query(User).filter_by(username=username.strip()).first()
    try: ok=u and ph.verify(u.password_hash,password)
    except (VerifyMismatchError, Exception): ok=False
    if not ok: return templates.TemplateResponse('login.html',ctx(request,error='Invalid credentials.'))
    request.session.clear(); request.session['uid']=u.id; return RedirectResponse('/',303)
@app.post('/logout')
def logout(request): request.session.clear(); return RedirectResponse('/login',303)

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
def save_record(request:Request, id:int=Form(0), kind:str=Form('record'), title:str=Form(...), content:str=Form(''), category:str=Form(''), tags:str=Form(''), entry_date:str=Form(''), favorite:bool=Form(False)):
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
def delete_record(request,rid:int):
    require(request)
    with db() as s: r=s.get(Record,rid); s.delete(r) if r else None; s.commit()
    return RedirectResponse('/records',303)

@app.get('/documents',response_class=HTMLResponse)
def documents(request: Request):
    require(request)
    with db() as s: items=s.query(Attachment).order_by(Attachment.created_at.desc()).all()
    return templates.TemplateResponse('documents.html',ctx(request,items=items,error=None))
@app.post('/documents/upload')
async def upload(request:Request,file:UploadFile=File(...),category:str=Form('')):
    require(request); suffix=Path(file.filename or '').suffix.lower().lstrip('.')
    if suffix not in ALLOWED: return templates.TemplateResponse('documents.html',ctx(request,items=[],error='File type is not allowed.'))
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
    return FileResponse(ATTACH/a.stored_name,filename=a.original_name,media_type=a.content_type)
@app.post('/documents/{aid}/delete')
def delete_doc(request: Request,aid:int):
    require(request)
    with db() as s: a=s.get(Attachment,aid); p=ATTACH/a.stored_name if a else None; s.delete(a) if a else None; s.commit()
    if p and p.is_file(): p.unlink()
    return RedirectResponse('/documents',303)

@app.post('/backup')
def backup(request: Request):
    require(request); stamp=datetime.now().strftime('%Y%m%d-%H%M%S'); out=BACKUPS/f'kazevault-{stamp}.zip'; temp=BACKUPS/f'.{stamp}.tmp'
    with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED) as z:
        con=sqlite3.connect(DB); dest=temp.with_suffix('.dbtmp'); dcon=sqlite3.connect(dest); con.backup(dcon); dcon.close(); con.close(); z.write(dest,'kaze_vault.db'); dest.unlink()
        for p in ATTACH.iterdir():
            if p.is_file(): z.write(p,'attachments/'+p.name)
    temp.replace(out); return RedirectResponse('/',303)
@app.get('/backups',response_class=HTMLResponse)
def backups(request: Request): require(request); return templates.TemplateResponse('backups.html',ctx(request,items=sorted(BACKUPS.glob('*.zip'),reverse=True)))
@app.get('/health')
def health(): return {'ok':True,'setup_needed':setup_needed()}

