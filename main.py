from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import sqlite3, json, os, hashlib, secrets
from datetime import date, datetime

app = FastAPI(title="SIB MSME RM Tracker")
DB = "sib_msme.db"

# ─── DB helpers ────────────────────────────────────────────────
def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    db = conn()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        mobile      TEXT DEFAULT '',
        email       TEXT UNIQUE NOT NULL,
        password    TEXT NOT NULL,
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token       TEXT PRIMARY KEY,
        rm_id       INTEGER NOT NULL,
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS branches (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        rm_id   INTEGER NOT NULL DEFAULT 1,
        name    TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS customers (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        rm_id               INTEGER NOT NULL DEFAULT 1,
        account_number      TEXT,
        customer_id         TEXT,
        branch_id           INTEGER,
        customer_name       TEXT NOT NULL,
        nature_of_account   TEXT,
        sanctioned_limit    REAL,
        limit_expiry_date   TEXT,
        monthly_emi         REAL,
        rate_of_interest    REAL,
        collateral_details  TEXT,
        outstanding_amount  REAL,
        related_parties     TEXT,
        stock_insurance     INTEGER DEFAULT 0,
        stock_ins_expiry    TEXT,
        created_at          TEXT DEFAULT (datetime('now','localtime')),
        updated_at          TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS property_insurance (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id     INTEGER,
        policy_number   TEXT,
        description     TEXT,
        expiry_date     TEXT,
        FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS bpm_items (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        rm_id                INTEGER NOT NULL DEFAULT 1,
        bpm_workitem         TEXT,
        date_of_login        TEXT,
        nature_of_request    TEXT,
        customer_type        TEXT,
        customer_name        TEXT,
        existing_customer_id INTEGER,
        account_number       TEXT,
        present_status       TEXT,
        date_of_sanction     TEXT,
        sanctioned_amount    REAL,
        date_of_disbursement TEXT,
        disbursement_amount  REAL,
        created_at           TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS targets (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        rm_id                 INTEGER NOT NULL DEFAULT 1,
        fy                    TEXT,
        target_disburse       REAL,
        target_book           REAL,
        previous_yearend_book REAL
    );

    CREATE TABLE IF NOT EXISTS daily_book (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        rm_id       INTEGER NOT NULL DEFAULT 1,
        entry_date  TEXT,
        book_amount REAL
    );
    """)
    db.commit()
    # Migrate existing tables: add rm_id if missing
    for tbl in ['branches', 'customers', 'bpm_items', 'targets', 'daily_book']:
        try:
            db.execute(f"ALTER TABLE {tbl} ADD COLUMN rm_id INTEGER NOT NULL DEFAULT 1")
            db.commit()
        except Exception:
            pass
    db.close()

init_db()

# ─── Auth helpers ───────────────────────────────────────────────
def hash_pw(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return f"{salt}:{h}"

def verify_pw(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(':', 1)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == h
    except Exception:
        return False

def get_rm_id(authorization: Optional[str] = Header(None)) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    token = authorization[7:]
    db = conn()
    row = db.execute("SELECT rm_id FROM sessions WHERE token=?", (token,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(401, "Invalid or expired session")
    return row['rm_id']

# ─── Auth Models ────────────────────────────────────────────────
class RegisterUser(BaseModel):
    name: str
    mobile: Optional[str] = ""
    email: str
    password: str

class LoginUser(BaseModel):
    email: str
    password: str

class UpdateProfile(BaseModel):
    name: str
    mobile: Optional[str] = ""
    current_password: Optional[str] = ""
    new_password: Optional[str] = ""

# ─── Auth APIs ──────────────────────────────────────────────────
@app.get("/api/auth/check-users")
def check_users():
    db = conn()
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db.close()
    return {"has_users": count > 0}

@app.post("/api/auth/register")
def register(u: RegisterUser):
    if len(u.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    db = conn()
    try:
        cur = db.execute(
            "INSERT INTO users (name, mobile, email, password) VALUES (?,?,?,?)",
            (u.name, u.mobile or "", u.email, hash_pw(u.password))
        )
        rm_id = cur.lastrowid
        token = secrets.token_hex(32)
        db.execute("INSERT INTO sessions (token, rm_id) VALUES (?,?)", (token, rm_id))
        db.commit(); db.close()
        return {"token": token, "user": {"id": rm_id, "name": u.name, "mobile": u.mobile or "", "email": u.email}}
    except Exception as e:
        db.close()
        raise HTTPException(400, "Email already registered")

@app.post("/api/auth/login")
def login(u: LoginUser):
    db = conn()
    row = db.execute("SELECT * FROM users WHERE email=?", (u.email,)).fetchone()
    if not row or not verify_pw(u.password, row['password']):
        db.close(); raise HTTPException(401, "Invalid email or password")
    token = secrets.token_hex(32)
    db.execute("INSERT INTO sessions (token, rm_id) VALUES (?,?)", (token, row['id']))
    db.commit(); db.close()
    return {"token": token, "user": {"id": row['id'], "name": row['name'], "mobile": row['mobile'] or "", "email": row['email']}}

@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        db = conn()
        db.execute("DELETE FROM sessions WHERE token=?", (token,))
        db.commit(); db.close()
    return {"ok": True}

@app.get("/api/auth/profile")
def get_profile(rm_id: int = Depends(get_rm_id)):
    db = conn()
    row = db.execute("SELECT id, name, mobile, email FROM users WHERE id=?", (rm_id,)).fetchone()
    db.close()
    if not row: raise HTTPException(404, "User not found")
    return dict(row)

@app.put("/api/auth/profile")
def update_profile(u: UpdateProfile, rm_id: int = Depends(get_rm_id)):
    db = conn()
    user = db.execute("SELECT * FROM users WHERE id=?", (rm_id,)).fetchone()
    if not user: db.close(); raise HTTPException(404, "User not found")
    if u.new_password:
        if not verify_pw(u.current_password or "", user['password']):
            db.close(); raise HTTPException(400, "Current password is incorrect")
        if len(u.new_password) < 6:
            db.close(); raise HTTPException(400, "New password must be at least 6 characters")
        db.execute("UPDATE users SET name=?, mobile=?, password=? WHERE id=?",
                   (u.name, u.mobile or "", hash_pw(u.new_password), rm_id))
    else:
        db.execute("UPDATE users SET name=?, mobile=? WHERE id=?", (u.name, u.mobile or "", rm_id))
    db.commit()
    row = db.execute("SELECT id, name, mobile, email FROM users WHERE id=?", (rm_id,)).fetchone()
    db.close()
    return dict(row)

# ─── Data Models ────────────────────────────────────────────────
class Branch(BaseModel):
    name: str

class PropertyIns(BaseModel):
    policy_number: Optional[str] = ""
    description: Optional[str] = ""
    expiry_date: Optional[str] = ""

class Customer(BaseModel):
    account_number: Optional[str] = ""
    customer_id: Optional[str] = ""
    branch_id: Optional[int] = None
    customer_name: str
    nature_of_account: Optional[str] = ""
    sanctioned_limit: Optional[float] = None
    limit_expiry_date: Optional[str] = ""
    monthly_emi: Optional[float] = None
    rate_of_interest: Optional[float] = None
    collateral_details: Optional[str] = ""
    outstanding_amount: Optional[float] = None
    related_parties: Optional[List[str]] = []
    stock_insurance: Optional[int] = 0
    stock_ins_expiry: Optional[str] = ""
    property_insurances: Optional[List[PropertyIns]] = []

class CustomerBulk(BaseModel):
    customers: List[Customer]

class BPMItem(BaseModel):
    bpm_workitem: str
    date_of_login: Optional[str] = ""
    nature_of_request: Optional[str] = ""
    customer_type: Optional[str] = "existing"
    customer_name: Optional[str] = ""
    existing_customer_id: Optional[int] = None
    account_number: Optional[str] = ""
    present_status: Optional[str] = "logged_in"
    date_of_sanction: Optional[str] = ""
    sanctioned_amount: Optional[float] = None
    date_of_disbursement: Optional[str] = ""
    disbursement_amount: Optional[float] = None

class Target(BaseModel):
    fy: str
    target_disburse: Optional[float] = None
    target_book: Optional[float] = None
    previous_yearend_book: Optional[float] = None

class DailyBook(BaseModel):
    entry_date: str
    book_amount: float

# ─── BRANCH APIs ───────────────────────────────────────────────
@app.get("/api/branches")
def get_branches(rm_id: int = Depends(get_rm_id)):
    db = conn()
    rows = db.execute("SELECT * FROM branches WHERE rm_id=? ORDER BY name", (rm_id,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/branches")
def add_branch(b: Branch, rm_id: int = Depends(get_rm_id)):
    db = conn()
    try:
        cur = db.execute("INSERT INTO branches (rm_id, name) VALUES (?,?)", (rm_id, b.name))
        db.commit()
        row = db.execute("SELECT * FROM branches WHERE id=?", (cur.lastrowid,)).fetchone()
        db.close(); return dict(row)
    except Exception:
        db.close(); raise HTTPException(400, "Branch already exists")

@app.delete("/api/branches/{bid}")
def del_branch(bid: int, rm_id: int = Depends(get_rm_id)):
    db = conn()
    db.execute("DELETE FROM branches WHERE id=? AND rm_id=?", (bid, rm_id))
    db.commit(); db.close()
    return {"deleted": bid}

# ─── CUSTOMER APIs ─────────────────────────────────────────────
@app.get("/api/customers")
def get_customers(search: str = "", branch_id: int = 0, nature: str = "",
                  rm_id: int = Depends(get_rm_id)):
    db = conn()
    q = "SELECT c.*, b.name as branch_name FROM customers c LEFT JOIN branches b ON c.branch_id=b.id WHERE c.rm_id=?"
    params = [rm_id]
    if search:
        q += " AND (c.customer_name LIKE ? OR c.account_number LIKE ? OR c.customer_id LIKE ?)"
        params += [f"%{search}%", f"%{search}%", f"%{search}%"]
    if branch_id:
        q += " AND c.branch_id=?"; params.append(branch_id)
    if nature:
        q += " AND c.nature_of_account=?"; params.append(nature)
    q += " ORDER BY c.customer_name"
    rows = db.execute(q, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d['related_parties'] = json.loads(d.get('related_parties') or '[]')
        pins = db.execute("SELECT * FROM property_insurance WHERE customer_id=?", (d['id'],)).fetchall()
        d['property_insurances'] = [dict(p) for p in pins]
        result.append(d)
    db.close(); return result

@app.get("/api/customers/{cid}")
def get_customer(cid: int):
    db = conn()
    r = db.execute("SELECT c.*, b.name as branch_name FROM customers c LEFT JOIN branches b ON c.branch_id=b.id WHERE c.id=?", (cid,)).fetchone()
    if not r: db.close(); raise HTTPException(404, "Not found")
    d = dict(r)
    d['related_parties'] = json.loads(d.get('related_parties') or '[]')
    pins = db.execute("SELECT * FROM property_insurance WHERE customer_id=?", (cid,)).fetchall()
    d['property_insurances'] = [dict(p) for p in pins]
    db.close(); return d

@app.post("/api/customers")
def add_customer(c: Customer, rm_id: int = Depends(get_rm_id)):
    db = conn()
    try:
        cur = db.execute("""INSERT INTO customers
            (rm_id,account_number,customer_id,branch_id,customer_name,nature_of_account,
             sanctioned_limit,limit_expiry_date,monthly_emi,rate_of_interest,
             collateral_details,outstanding_amount,related_parties,
             stock_insurance,stock_ins_expiry)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rm_id, c.account_number, c.customer_id, c.branch_id, c.customer_name,
             c.nature_of_account, c.sanctioned_limit, c.limit_expiry_date,
             c.monthly_emi, c.rate_of_interest, c.collateral_details,
             c.outstanding_amount, json.dumps(c.related_parties or []),
             c.stock_insurance, c.stock_ins_expiry))
        cid = cur.lastrowid
        for pi in (c.property_insurances or []):
            db.execute("INSERT INTO property_insurance (customer_id,policy_number,description,expiry_date) VALUES (?,?,?,?)",
                       (cid, pi.policy_number, pi.description, pi.expiry_date))
        db.commit(); db.close()
        return get_customer(cid)
    except Exception as e:
        db.close(); raise HTTPException(400, str(e))

@app.post("/api/customers/bulk")
def bulk_customers(payload: CustomerBulk, rm_id: int = Depends(get_rm_id)):
    added = 0
    errors = []
    db = conn()
    for c in payload.customers:
        if not c.customer_name:
            continue
        try:
            cur = db.execute("""INSERT INTO customers
                (rm_id,account_number,customer_id,branch_id,customer_name,nature_of_account,
                 sanctioned_limit,limit_expiry_date,monthly_emi,rate_of_interest,
                 collateral_details,outstanding_amount,related_parties,
                 stock_insurance,stock_ins_expiry)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rm_id, c.account_number, c.customer_id, c.branch_id, c.customer_name,
                 c.nature_of_account, c.sanctioned_limit, c.limit_expiry_date,
                 c.monthly_emi, c.rate_of_interest, c.collateral_details,
                 c.outstanding_amount, json.dumps(c.related_parties or []),
                 c.stock_insurance, c.stock_ins_expiry))
            cid = cur.lastrowid
            for pi in (c.property_insurances or []):
                db.execute("INSERT INTO property_insurance (customer_id,policy_number,description,expiry_date) VALUES (?,?,?,?)",
                           (cid, pi.policy_number, pi.description, pi.expiry_date))
            added += 1
        except Exception as e:
            errors.append(f"{c.customer_name}: {str(e)}")
    db.commit(); db.close()
    return {"added": added, "errors": errors}

@app.put("/api/customers/{cid}")
def update_customer(cid: int, c: Customer, rm_id: int = Depends(get_rm_id)):
    db = conn()
    db.execute("""UPDATE customers SET
        account_number=?,customer_id=?,branch_id=?,customer_name=?,nature_of_account=?,
        sanctioned_limit=?,limit_expiry_date=?,monthly_emi=?,rate_of_interest=?,
        collateral_details=?,outstanding_amount=?,related_parties=?,
        stock_insurance=?,stock_ins_expiry=?,updated_at=datetime('now','localtime')
        WHERE id=? AND rm_id=?""",
        (c.account_number, c.customer_id, c.branch_id, c.customer_name,
         c.nature_of_account, c.sanctioned_limit, c.limit_expiry_date,
         c.monthly_emi, c.rate_of_interest, c.collateral_details,
         c.outstanding_amount, json.dumps(c.related_parties or []),
         c.stock_insurance, c.stock_ins_expiry, cid, rm_id))
    db.execute("DELETE FROM property_insurance WHERE customer_id=?", (cid,))
    for pi in (c.property_insurances or []):
        db.execute("INSERT INTO property_insurance (customer_id,policy_number,description,expiry_date) VALUES (?,?,?,?)",
                   (cid, pi.policy_number, pi.description, pi.expiry_date))
    db.commit(); db.close()
    return get_customer(cid)

@app.delete("/api/customers/{cid}")
def del_customer(cid: int, rm_id: int = Depends(get_rm_id)):
    db = conn()
    db.execute("DELETE FROM customers WHERE id=? AND rm_id=?", (cid, rm_id))
    db.commit(); db.close()
    return {"deleted": cid}

# ─── BPM APIs ──────────────────────────────────────────────────
@app.get("/api/bpm")
def get_bpm(status: str = "", nature: str = "", rm_id: int = Depends(get_rm_id)):
    db = conn()
    q = "SELECT b.*, c.customer_name as existing_name FROM bpm_items b LEFT JOIN customers c ON b.existing_customer_id=c.id WHERE b.rm_id=?"
    params = [rm_id]
    if status: q += " AND b.present_status=?"; params.append(status)
    if nature: q += " AND b.nature_of_request=?"; params.append(nature)
    q += " ORDER BY b.date_of_login DESC"
    rows = db.execute(q, params).fetchall(); db.close()
    return [dict(r) for r in rows]

@app.post("/api/bpm")
def add_bpm(b: BPMItem, rm_id: int = Depends(get_rm_id)):
    db = conn()
    try:
        cur = db.execute("""INSERT INTO bpm_items
            (rm_id,bpm_workitem,date_of_login,nature_of_request,customer_type,customer_name,
             existing_customer_id,account_number,present_status,date_of_sanction,
             sanctioned_amount,date_of_disbursement,disbursement_amount)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rm_id, b.bpm_workitem, b.date_of_login, b.nature_of_request, b.customer_type,
             b.customer_name, b.existing_customer_id, b.account_number, b.present_status,
             b.date_of_sanction, b.sanctioned_amount, b.date_of_disbursement, b.disbursement_amount))
        db.commit()
        row = db.execute("SELECT * FROM bpm_items WHERE id=?", (cur.lastrowid,)).fetchone()
        db.close(); return dict(row)
    except Exception as e:
        db.close(); raise HTTPException(400, str(e))

@app.put("/api/bpm/{bid}")
def update_bpm(bid: int, b: BPMItem, rm_id: int = Depends(get_rm_id)):
    db = conn()
    db.execute("""UPDATE bpm_items SET
        bpm_workitem=?,date_of_login=?,nature_of_request=?,customer_type=?,customer_name=?,
        existing_customer_id=?,account_number=?,present_status=?,date_of_sanction=?,
        sanctioned_amount=?,date_of_disbursement=?,disbursement_amount=? WHERE id=? AND rm_id=?""",
        (b.bpm_workitem, b.date_of_login, b.nature_of_request, b.customer_type,
         b.customer_name, b.existing_customer_id, b.account_number, b.present_status,
         b.date_of_sanction, b.sanctioned_amount, b.date_of_disbursement, b.disbursement_amount, bid, rm_id))
    db.commit()
    row = db.execute("SELECT * FROM bpm_items WHERE id=?", (bid,)).fetchone()
    db.close(); return dict(row)

@app.delete("/api/bpm/{bid}")
def del_bpm(bid: int, rm_id: int = Depends(get_rm_id)):
    db = conn()
    db.execute("DELETE FROM bpm_items WHERE id=? AND rm_id=?", (bid, rm_id))
    db.commit(); db.close()
    return {"deleted": bid}

# ─── TARGETS & BOOK ────────────────────────────────────────────
@app.get("/api/targets")
def get_targets(rm_id: int = Depends(get_rm_id)):
    db = conn()
    row = db.execute("SELECT * FROM targets WHERE rm_id=? ORDER BY id DESC LIMIT 1", (rm_id,)).fetchone()
    db.close(); return dict(row) if row else {}

@app.post("/api/targets")
def set_targets(t: Target, rm_id: int = Depends(get_rm_id)):
    db = conn()
    db.execute("DELETE FROM targets WHERE rm_id=?", (rm_id,))
    db.execute("INSERT INTO targets (rm_id,fy,target_disburse,target_book,previous_yearend_book) VALUES (?,?,?,?,?)",
               (rm_id, t.fy, t.target_disburse, t.target_book, t.previous_yearend_book))
    db.commit(); db.close(); return get_targets(rm_id)

@app.get("/api/book")
def get_book(rm_id: int = Depends(get_rm_id)):
    db = conn()
    rows = db.execute("SELECT * FROM daily_book WHERE rm_id=? ORDER BY entry_date DESC LIMIT 60", (rm_id,)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/book")
def add_book(b: DailyBook, rm_id: int = Depends(get_rm_id)):
    db = conn()
    existing = db.execute("SELECT id FROM daily_book WHERE rm_id=? AND entry_date=?", (rm_id, b.entry_date)).fetchone()
    if existing:
        db.execute("UPDATE daily_book SET book_amount=? WHERE id=?", (b.book_amount, existing['id']))
    else:
        db.execute("INSERT INTO daily_book (rm_id, entry_date, book_amount) VALUES (?,?,?)", (rm_id, b.entry_date, b.book_amount))
    db.commit(); db.close(); return {"ok": True}

# ─── DASHBOARD ─────────────────────────────────────────────────
@app.get("/api/dashboard")
def dashboard(rm_id: int = Depends(get_rm_id)):
    db = conn()
    today = date.today().isoformat()
    exp_limits = db.execute("""SELECT customer_name,account_number,limit_expiry_date,sanctioned_limit
        FROM customers WHERE rm_id=? AND limit_expiry_date!='' AND limit_expiry_date IS NOT NULL
        AND nature_of_account IN ('ccol','overdraft')
        AND julianday(limit_expiry_date) - julianday(?) <= 60
        ORDER BY limit_expiry_date""", (rm_id, today)).fetchall()
    stock_ins = db.execute("""SELECT customer_name,account_number,'Stock Insurance' as ins_type, stock_ins_expiry as expiry
        FROM customers WHERE rm_id=? AND stock_insurance=1 AND stock_ins_expiry!='' AND stock_ins_expiry IS NOT NULL
        AND julianday(stock_ins_expiry) - julianday(?) BETWEEN -30 AND 30
        ORDER BY stock_ins_expiry""", (rm_id, today)).fetchall()
    prop_ins = db.execute("""SELECT c.customer_name,c.account_number,
        'Property: '||pi.description as ins_type, pi.expiry_date as expiry
        FROM property_insurance pi JOIN customers c ON pi.customer_id=c.id
        WHERE c.rm_id=? AND pi.expiry_date!='' AND pi.expiry_date IS NOT NULL
        AND julianday(pi.expiry_date) - julianday(?) BETWEEN -30 AND 30
        ORDER BY pi.expiry_date""", (rm_id, today)).fetchall()
    total_customers = db.execute("SELECT COUNT(*) FROM customers WHERE rm_id=?", (rm_id,)).fetchone()[0]
    total_book = db.execute("SELECT SUM(outstanding_amount) FROM customers WHERE rm_id=?", (rm_id,)).fetchone()[0] or 0
    bpm_active = db.execute("SELECT COUNT(*) FROM bpm_items WHERE rm_id=? AND present_status NOT IN ('disbursed','rejected','complete')", (rm_id,)).fetchone()[0]
    curr_month = today[:7]
    curr_year = today[:4]+"-04-01" if int(today[5:7])>=4 else str(int(today[:4])-1)+"-04-01"
    mtd_disb = db.execute("SELECT SUM(disbursement_amount) FROM bpm_items WHERE rm_id=? AND date_of_disbursement LIKE ?", (rm_id, curr_month+"%")).fetchone()[0] or 0
    ytd_disb = db.execute("SELECT SUM(disbursement_amount) FROM bpm_items WHERE rm_id=? AND date_of_disbursement >= ?", (rm_id, curr_year)).fetchone()[0] or 0
    ftd_disb = db.execute("SELECT SUM(disbursement_amount) FROM bpm_items WHERE rm_id=? AND date_of_disbursement=?", (rm_id, today)).fetchone()[0] or 0
    tgt = db.execute("SELECT * FROM targets WHERE rm_id=? ORDER BY id DESC LIMIT 1", (rm_id,)).fetchone()
    books = db.execute("SELECT * FROM daily_book WHERE rm_id=? ORDER BY entry_date DESC LIMIT 2", (rm_id,)).fetchall()
    db.close()
    return {
        "expiring_limits": [dict(r) for r in exp_limits],
        "expiring_insurance": [dict(r) for r in stock_ins] + [dict(r) for r in prop_ins],
        "total_customers": total_customers,
        "total_book": round(total_book/10000000, 2),
        "bpm_active": bpm_active,
        "ftd_disb": round(ftd_disb/10000000, 4),
        "mtd_disb": round(mtd_disb/10000000, 4),
        "ytd_disb": round(ytd_disb/10000000, 4),
        "targets": dict(tgt) if tgt else {},
        "book_entries": [dict(b) for b in books]
    }

# ─── REPORT ────────────────────────────────────────────────────
@app.get("/api/report/book-movement")
def book_movement_report(rm_id: int = Depends(get_rm_id)):
    db = conn()
    today = date.today().isoformat()
    curr_month = today[:7]
    curr_year_start = today[:4]+"-04-01" if int(today[5:7])>=4 else str(int(today[:4])-1)+"-04-01"
    prev_month = db.execute("SELECT entry_date,book_amount FROM daily_book WHERE rm_id=? AND entry_date < ? ORDER BY entry_date DESC LIMIT 1", (rm_id, curr_month+"-01")).fetchone()
    today_book = db.execute("SELECT book_amount FROM daily_book WHERE rm_id=? AND entry_date=?", (rm_id, today)).fetchone()
    yesterday = db.execute("SELECT entry_date,book_amount FROM daily_book WHERE rm_id=? AND entry_date < ? ORDER BY entry_date DESC LIMIT 1", (rm_id, today)).fetchone()
    tgt = db.execute("SELECT * FROM targets WHERE rm_id=? ORDER BY id DESC LIMIT 1", (rm_id,)).fetchone()
    prev_ye = tgt['previous_yearend_book'] if tgt else 0
    ftd_disb = db.execute("SELECT SUM(disbursement_amount) FROM bpm_items WHERE rm_id=? AND date_of_disbursement=?", (rm_id, today)).fetchone()[0] or 0
    mtd_disb = db.execute("SELECT SUM(disbursement_amount) FROM bpm_items WHERE rm_id=? AND date_of_disbursement LIKE ?", (rm_id, curr_month+"%")).fetchone()[0] or 0
    ytd_disb = db.execute("SELECT SUM(disbursement_amount) FROM bpm_items WHERE rm_id=? AND date_of_disbursement >= ?", (rm_id, curr_year_start)).fetchone()[0] or 0
    prev_ye_book = db.execute("SELECT book_amount FROM daily_book WHERE rm_id=? AND (entry_date=? OR entry_date < ?) ORDER BY entry_date DESC LIMIT 1", (rm_id, curr_year_start, curr_year_start)).fetchone()
    db.close()
    def cr(v): return f"{round((v or 0)/10000000,2):.2f} Cr" if v else "-- Cr"
    today_val = today_book['book_amount'] if today_book else None
    yest_val = yesterday['book_amount'] if yesterday else None
    prev_m_val = prev_month['book_amount'] if prev_month else None
    prev_ye_val = prev_ye_book['book_amount'] if prev_ye_book else (prev_ye*10000000 if prev_ye else None)
    ftd_book = (today_val or 0) - (yest_val or 0)
    report = f"""📊 *BOOK MOVEMENT as on {today}*

*Core Book*
As on Previous Year End : {cr(prev_ye_val)}
As on Previous Month End : {cr(prev_m_val)}
As on Yesterday : {cr(yest_val)}
As on Today : {cr(today_val)}
FTD : {cr(ftd_book) if today_val and yest_val else '-- Cr'}
MTD : --
YTD : --

*Today's Activities*
FTD Disbursement: {cr(ftd_disb)}
MTD Disbursement: {cr(mtd_disb)}
YTD Disbursement: {cr(ytd_disb)}"""
    return {"report": report, "date": today}

# ─── Serve frontend ────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def index(): return FileResponse("static/index.html")
