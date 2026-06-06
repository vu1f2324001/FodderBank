from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os
import sqlite3
from datetime import datetime
import random
import string
import bcrypt

app = Flask(__name__) 
app.secret_key = os.environ.get('FODDER_APP_SECRET') or os.urandom(24)
app.config['SESSION_COOKIE_SECURE'] = False  # Allow non-HTTPS in development
app.config['SESSION_COOKIE_HTTPONLY'] = False  # Allow JS access in development
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Allow cross-origin cookies from same site

# ---------------- DATABASE ----------------
def db():
    con = sqlite3.connect("database.db")
    con.row_factory = sqlite3.Row
    return con

def create_tables():
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS farmers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        aadhaar TEXT UNIQUE,
        name TEXT,
        password TEXT,
        village TEXT,
        quota INTEGER DEFAULT 1500
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS managers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        manager_id TEXT UNIQUE,
        name TEXT,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS admins(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id TEXT UNIQUE,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stock(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fodder_type TEXT UNIQUE,
        quantity INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        farmer_aadhaar TEXT,
        fodder_type TEXT,
        quantity INTEGER,
        bank TEXT,
        method TEXT,
        status TEXT,
        token TEXT,
        date TEXT
    )
    """)
    con.commit()
    con.close()

create_tables()


def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = session.get('user')
            if not user:
                # return JSON unauthorized for API calls, otherwise redirect to login
                if request.is_json or request.headers.get('Accept','').find('application/json')!=-1 or request.headers.get('X-Requested-With')=='XMLHttpRequest':
                    return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
                return redirect(url_for('farmer'))
            if role and user.get('role') != role:
                if request.is_json or request.headers.get('Accept','').find('application/json')!=-1:
                    return jsonify({'success': False, 'msg': 'Forbidden'}), 403
                return redirect(url_for('farmer'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# ---------------- HELPERS ----------------

def generate_token():
    return "FDB-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


# ---------------- ROUTES ----------------

@app.route("/")
def farmer():
    return render_template("farmer.html")


@app.route("/dashboard")
def dashboard():
    # Render the farmer dashboard view. Templates use `initial_page` to
    # set the initial client-side state (so the JS app shows the dashboard).
    user = session.get('user')
    if not user or user.get('role') != 'farmer':
        return redirect(url_for('farmer'))
    return render_template("farmer.html", initial_page='dashboard-availability')


@app.route('/logout')
def logout():
    session.pop('user', None)
    # If call is AJAX/JSON return JSON, else redirect to main page
    if request.is_json or request.headers.get('Accept','').find('application/json')!=-1:
        return jsonify({'success': True})
    return redirect(url_for('farmer'))

@app.route("/manager")
def manager():
    return render_template("manager.html")

@app.route("/admin")
def admin():
    return render_template("admin.html")

# ---------- LOGIN ----------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    con = db()

    existing = con.execute(
        "SELECT * FROM farmers WHERE aadhaar=?", (data["aadhaar"],)
    ).fetchone()

    if existing:
        return jsonify({"success": False, "msg": "Already registered"})

    # Hash password using bcrypt before storing
    pwd = data["password"]
    hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
    con.execute("""
        INSERT INTO farmers (aadhaar, name, password, village)
        VALUES (?,?,?,?)
    """, (data["aadhaar"], data["name"], hashed.decode('utf-8'), data["village"]))

    con.commit()
    con.close()

    return jsonify({"success": True})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    con = db()
    user = con.execute("SELECT * FROM farmers WHERE aadhaar=?", (data["aadhaar"],)).fetchone()
    con.close()
    if user:
        # Handle both old plaintext passwords and new bcrypt hashed passwords
        stored_pwd = user['password']
        if isinstance(stored_pwd, str):
            stored_pwd = stored_pwd.encode('utf-8')

        try:
            if bcrypt.checkpw(data["password"].encode('utf-8'), stored_pwd):
                session['user'] = {'role': 'farmer', 'aadhaar': user['aadhaar'], 'name': user['name']}
                return jsonify({"success": True})
        except ValueError:
            # If bcrypt fails (invalid salt), try plaintext comparison (for old data)
            if data["password"] == user['password']:
                session['user'] = {'role': 'farmer', 'aadhaar': user['aadhaar'], 'name': user['name']}
                return jsonify({"success": True})

    return jsonify({"success": False})

@app.route("/login/farmer", methods=["POST"])
def login_farmer():
    data = request.json
    con = db()
    user = con.execute("SELECT * FROM farmers WHERE aadhaar=?", (data["aadhaar"],)).fetchone()
    con.close()
    if user and bcrypt.checkpw(data["password"].encode('utf-8'), user['password'].encode('utf-8')):
        session['user'] = {'role': 'farmer', 'aadhaar': user['aadhaar'], 'name': user['name']}
        return jsonify({"success": True})
    return jsonify({"success": False})


@app.route('/login/manager', methods=['POST'])
def login_manager():
    data = request.json
    con = db()
    user = con.execute("SELECT * FROM managers WHERE manager_id=?", (data.get('manager_id'),)).fetchone()
    con.close()
    if user and bcrypt.checkpw(data.get('password').encode('utf-8'), user['password'].encode('utf-8')):
        session['user'] = {'role': 'manager', 'manager_id': user['manager_id'], 'name': user['name']}
        return jsonify({'success': True})
    return jsonify({'success': False})


@app.route('/login/admin', methods=['POST'])
def login_admin():
    data = request.json
    con = db()
    user = con.execute("SELECT * FROM admins WHERE admin_id=?", (data.get('admin_id'),)).fetchone()
    con.close()
    if user and bcrypt.checkpw(data.get('password').encode('utf-8'), user['password'].encode('utf-8')):
        session['user'] = {'role': 'admin', 'admin_id': user['admin_id']}
        return jsonify({'success': True})
    return jsonify({'success': False})


# ---------- FARMER REQUEST REAL LOGIC ----------

@app.route("/request_fodder", methods=["POST"])
def request_fodder():
    # Only farmers may make requests
    user = session.get('user')
    if not user or user.get('role') != 'farmer':
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401

    data = request.json
    aadhaar = user.get('aadhaar')
    fodder = data["fodderType"]
    qty = int(data["quantity"])

    con = db()
    farmer = con.execute("SELECT quota FROM farmers WHERE aadhaar=?", (aadhaar,)).fetchone()

    if not farmer:
        con.close()
        return jsonify({"success": False, "msg": "Farmer not found"})

    if qty > farmer["quota"]:
        con.close()
        return jsonify({"success": False, "msg": "Quota exceeded"})

    con.execute("""
        INSERT INTO requests (farmer_aadhaar,fodder_type,quantity,bank,method,status,date)
        VALUES (?,?,?,?,?,?,?)
    """, (aadhaar, fodder, qty, data.get("bank"), data.get("method"), "Pending", datetime.now()))

    con.commit()
    con.close()

    return jsonify({"success": True})


# ---------- MANAGER REAL APPROVAL FLOW ----------

@app.route("/manager/approve", methods=["POST"])
def approve():
    # Only managers may approve
    user = session.get('user')
    if not user or user.get('role') != 'manager':
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401

    data = request.json
    req_id = data["id"]

    con = db()
    req = con.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        con.close()
        return jsonify({'success': False, 'msg': 'Request not found'}), 404

    stock = con.execute("SELECT * FROM stock WHERE fodder_type=?", (req["fodder_type"],)).fetchone()

    if not stock or stock["quantity"] < req["quantity"]:
        con.close()
        return jsonify({"success": False, "msg": "Not enough stock"})

    token = generate_token()

    # Update stock
    con.execute("UPDATE stock SET quantity = quantity - ? WHERE fodder_type=?",
                (req["quantity"], req["fodder_type"]))

    # Deduct quota
    con.execute("UPDATE farmers SET quota = quota - ? WHERE aadhaar=?",
                (req["quantity"], req["farmer_aadhaar"]))

    # Update request
    con.execute("UPDATE requests SET status='Approved', token=? WHERE id=?",
                (token, req_id))

    con.commit()
    con.close()

    return jsonify({"success": True, "token": token})


@app.route('/stock', methods=['GET'])
def get_stock():
    # Allow any logged-in user to view stock
    if not session.get('user'):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    con = db()
    rows = con.execute("SELECT * FROM stock").fetchall()
    con.close()
    stocks = [dict(r) for r in rows]
    return jsonify(stocks)


@app.route('/requests', methods=['GET'])
def get_requests():
    # Only managers/admins should fetch all requests
    user = session.get('user')
    if not user or user.get('role') not in ('manager', 'admin'):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    con = db()
    rows = con.execute("SELECT * FROM requests ORDER BY date DESC").fetchall()
    con.close()
    requests_list = [dict(r) for r in rows]
    return jsonify(requests_list)


@app.route('/manager/update_stock', methods=['POST'])
def update_stock():
    # Only managers may update stock
    user = session.get('user')
    if not user or user.get('role') != 'manager':
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401

    data = request.json
    fodder = data.get('fodder_type')
    qty = int(data.get('quantity', 0))
    action = data.get('action', 'in')  # 'in' or 'out'

    con = db()
    existing = con.execute("SELECT * FROM stock WHERE fodder_type=?", (fodder,)).fetchone()

    if existing:
        if action == 'in':
            con.execute("UPDATE stock SET quantity = quantity + ? WHERE fodder_type=?", (qty, fodder))
        else:
            con.execute("UPDATE stock SET quantity = quantity - ? WHERE fodder_type=?", (qty, fodder))
    else:
        # Insert new stock record
        con.execute("INSERT INTO stock (fodder_type, quantity) VALUES (?,?)", (fodder, qty))

    con.commit()
    con.close()
    return jsonify({"success": True})


@app.route('/setup/create_manager', methods=['POST'])
def setup_create_manager():
    data = request.json
    con = db()
    existing = con.execute('SELECT * FROM managers WHERE manager_id=?', (data.get('manager_id'),)).fetchone()
    if existing:
        con.close()
        return jsonify({'success': False, 'msg': 'Manager exists'})
    hashed = bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt())
    con.execute('INSERT INTO managers (manager_id, name, password) VALUES (?,?,?)', (data.get('manager_id'), data.get('name'), hashed.decode('utf-8')))
    con.commit()
    con.close()
    return jsonify({'success': True})


@app.route('/setup/create_admin', methods=['POST'])
def setup_create_admin():
    data = request.json
    con = db()
    existing = con.execute('SELECT * FROM admins WHERE admin_id=?', (data.get('admin_id'),)).fetchone()
    if existing:
        con.close()
        return jsonify({'success': False, 'msg': 'Admin exists'})
    hashed = bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt())
    con.execute('INSERT INTO admins (admin_id, password) VALUES (?,?)', (data.get('admin_id'), hashed.decode('utf-8')))
    con.commit()
    con.close()
    return jsonify({'success': True})

# ---------- ADMIN: EMERGENCY MODE ----------

@app.route('/farmer/requests', methods=['GET'])
def farmer_requests():
    # Get the current farmer's requests
    user = session.get('user')
    if not user:
        return jsonify({'success': False, 'msg': 'Session not found. Please log in again.'}), 401
    if user.get('role') != 'farmer':
        return jsonify({'success': False, 'msg': 'Not a farmer. Role: ' + str(user.get('role'))}), 401
    
    aadhaar = user.get('aadhaar')
    if not aadhaar:
        return jsonify({'success': False, 'msg': 'Aadhaar not in session.'}), 401
    
    try:
        con = db()
        rows = con.execute("SELECT id, fodder_type, quantity, status, token, date FROM requests WHERE farmer_aadhaar=? ORDER BY date DESC", (aadhaar,)).fetchall()
        con.close()
        requests_list = [dict(r) for r in rows]
        return jsonify(requests_list)
    except Exception as e:
        return jsonify({'success': False, 'msg': 'Database error: ' + str(e)}), 500


@app.route('/farmer/quota', methods=['GET'])
def farmer_quota():
    # Get the current farmer's remaining quota
    user = session.get('user')
    if not user or user.get('role') != 'farmer':
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    aadhaar = user.get('aadhaar')
    con = db()
    farmer = con.execute("SELECT quota, name, village FROM farmers WHERE aadhaar=?", (aadhaar,)).fetchone()
    con.close()
    
    if farmer:
        return jsonify({'success': True, 'quota': farmer['quota'], 'name': farmer['name'], 'village': farmer['village']})
    return jsonify({'success': False, 'msg': 'Farmer not found'}), 404


@app.route("/admin/emergency", methods=["POST"])
def emergency():
    data = request.json
    status = data["status"]

    # (Simulation only)
    return jsonify({"success": True, "mode": status})

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True, port=5001)
