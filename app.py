import json, hashlib, subprocess, time
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
DATA_FILE = Path(__file__).parent / "data.json"
ACTIVE_WINDOW = 300
MASTER_HWID = "1f92eac060cd50521eddd89987181df6"
ADMIN_KEY = "starware-admin-2026"
SUB_DURATION = 30 * 24 * 3600

def load_data():
    if DATA_FILE.exists():
        return json.loads(DATA_FILE.read_text())
    return {"users": {}}

def save_data(data):
    DATA_FILE.write_text(json.dumps(data, indent=2))

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def _check_sub(user):
    expiry = user.get("sub_expiry")
    if expiry is None:
        return None
    if time.time() > expiry:
        return "Subscription expired. Renew via PayPal (\u20ac5/month) to regain access."
    return None

@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(force=True)
    username = body.get("username", "").strip().lower()
    password = body.get("password", "").strip()
    hwid = body.get("hwid", "")

    if hwid == MASTER_HWID:
        return jsonify({"status": "ok", "message": "Authorized (owner)"})
    if not username or not password or not hwid:
        return jsonify({"status": "error", "message": "Missing fields"})

    db = load_data()
    user = db.get("users", {}).get(username)
    if not user or user["password"] != hash_password(password):
        return jsonify({"status": "error", "message": "Invalid username or password"})

    sub_err = _check_sub(user)
    if sub_err:
        return jsonify({"status": "error", "message": sub_err})

    bound = user.get("hwid")
    if bound is None:
        user["hwid"] = hwid
        user["last_active"] = time.time()
        save_data(db)
        return jsonify({"status": "ok", "message": "Logged in and HWID bound"})
    elif bound == hwid:
        user["last_active"] = time.time()
        save_data(db)
        return jsonify({"status": "ok", "message": "Logged in"})
    else:
        return jsonify({"status": "error", "message": "Account already bound to another device"})

@app.route("/check", methods=["GET"])
def check_hwid():
    hwid = request.args.get("hwid", "")
    if hwid == MASTER_HWID:
        return jsonify({"status": "ok", "message": "Authorized (owner)"})
    db = load_data()
    for uname, user in db.get("users", {}).items():
        if user.get("hwid") == hwid:
            sub_err = _check_sub(user)
            if sub_err:
                return jsonify({"status": "denied", "message": sub_err})
            user["last_active"] = time.time()
            save_data(db)
            return jsonify({"status": "ok", "message": f"Authorized as {uname}"})
    return jsonify({"status": "denied", "message": "Not authorized"})

@app.route("/active", methods=["GET"])
def active_users():
    db = load_data()
    now = time.time()
    cutoff = now - ACTIVE_WINDOW
    online = []
    for uname, user in db.get("users", {}).items():
        last = user.get("last_active")
        if last and last > cutoff:
            online.append({"username": uname, "hwid": user.get("hwid", "?")[:12], "last_seen": last})
    return jsonify({"status": "ok", "online": len(online), "users": online})

# --- Admin endpoints (used by Discord bot) ---

def _admin_check():
    auth = request.headers.get("Authorization", "")
    if auth != ADMIN_KEY:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    return None

@app.route("/admin/users", methods=["GET"])
def admin_list_users():
    err = _admin_check()
    if err: return err
    db = load_data()
    return jsonify({"status": "ok", "users": db.get("users", {})})

@app.route("/admin/create", methods=["POST"])
def admin_create_user():
    err = _admin_check()
    if err: return err
    body = request.get_json(force=True)
    username = body.get("username", "").strip().lower()
    password = body.get("password", "").strip()
    created_by = body.get("created_by", "admin")
    sub_type = body.get("sub_type", "monthly")  # "monthly" or "lifetime"
    if not username or not password:
        return jsonify({"status": "error", "message": "Missing fields"})
    db = load_data()
    if username in db.setdefault("users", {}):
        return jsonify({"status": "error", "message": "User already exists"})
    sub_expiry = None if sub_type == "lifetime" else time.time() + SUB_DURATION
    db["users"][username] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "password_plain": password,
        "hwid": None,
        "created_by": created_by,
        "sub_expiry": sub_expiry
    }
    save_data(db)
    return jsonify({"status": "ok", "message": f"User {username} created"})

@app.route("/admin/unbind", methods=["POST"])
def admin_unbind():
    err = _admin_check()
    if err: return err
    body = request.get_json(force=True)
    username = body.get("username", "").strip().lower()
    db = load_data()
    user = db.get("users", {}).get(username)
    if not user:
        return jsonify({"status": "error", "message": "User not found"})
    user["hwid"] = None
    save_data(db)
    return jsonify({"status": "ok", "message": f"Unbound {username}"})

@app.route("/admin/renew", methods=["POST"])
def admin_renew():
    err = _admin_check()
    if err: return err
    body = request.get_json(force=True)
    username = body.get("username", "").strip().lower()
    db = load_data()
    user = db.get("users", {}).get(username)
    if not user:
        return jsonify({"status": "error", "message": "User not found"})
    if user.get("sub_expiry") is None:
        return jsonify({"status": "error", "message": "User already has lifetime"})
    old = user["sub_expiry"]
    now = time.time()
    user["sub_expiry"] = now + SUB_DURATION if old < now else old + SUB_DURATION
    save_data(db)
    return jsonify({"status": "ok", "message": f"Renewed {username}", "expiry": user["sub_expiry"]})

@app.route("/admin/extend", methods=["POST"])
def admin_extend():
    err = _admin_check()
    if err: return err
    body = request.get_json(force=True)
    username = body.get("username", "").strip().lower()
    days = int(body.get("days", 30))
    db = load_data()
    user = db.get("users", {}).get(username)
    if not user:
        return jsonify({"status": "error", "message": "User not found"})
    if user.get("sub_expiry") is None:
        return jsonify({"status": "error", "message": "User already has lifetime"})
    old = user["sub_expiry"]
    now = time.time()
    extra = days * 86400
    user["sub_expiry"] = now + extra if old < now else old + extra
    save_data(db)
    return jsonify({"status": "ok", "message": f"Extended {username} by {days}d", "expiry": user["sub_expiry"]})

@app.route("/admin/setlifetime", methods=["POST"])
def admin_setlifetime():
    err = _admin_check()
    if err: return err
    body = request.get_json(force=True)
    username = body.get("username", "").strip().lower()
    db = load_data()
    user = db.get("users", {}).get(username)
    if not user:
        return jsonify({"status": "error", "message": "User not found"})
    user["sub_expiry"] = None
    save_data(db)
    return jsonify({"status": "ok", "message": f"{username} now has lifetime"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
