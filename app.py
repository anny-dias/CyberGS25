from flask import Flask, request, jsonify, g
import sqlite3, os, subprocess, json, pickle, re

app = Flask(__name__)
DB_PATH = "lab.db"

# -------------------- DB helpers --------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    # garante que o arquivo exista e popula com seed.sql
    if not os.path.exists(DB_PATH):
        open(DB_PATH, "w").close()
    with open("seed.sql", "r", encoding="utf-8") as f:
        sql = f.read()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(sql)
    conn.commit()
    conn.close()

# chama a inicialização imediatamente (uma vez) ao importar o módulo
init_db()


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db: db.close()

# Para “simular” usuário logado (NÃO FAÇA EM PROD)
def get_current_user():
    # header X-User: alice ou bob
    user = request.headers.get("X-User", "bob")
    db = get_db()
    cur = db.execute("SELECT username, role FROM users WHERE username = ?", (user,))
    row = cur.fetchone()
    if not row:
        return {"username": "bob", "role": "user"}
    return {"username": row["username"], "role": row["role"]}

# ====================================================
# 1) SQL INJECTION
# ====================================================

# --- VULNERÁVEL ---
@app.get("/vuln/sql/users")
def vuln_sql_list():
    # filtro vindo do cliente
    q = request.args.get("q", "")
    # ERRO: concatenação direta
    sql = f"SELECT id, username, role FROM users WHERE username LIKE '%{q}%'"
    rows = get_db().execute(sql).fetchall()
    return jsonify([dict(r) for r in rows])

# --- CORRIGIDO ---
@app.get("/safe/sql/users")
def safe_sql_list():
    q = request.args.get("q", "")
    # Correto: parâmetro
    rows = get_db().execute(
        "SELECT id, username, role FROM users WHERE username LIKE ?",
        (f"%{q}%",)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

# ====================================================
# 2) BROKEN ACCESS CONTROL (Quebra de controle de acesso)
# ====================================================

# --- VULNERÁVEL ---
@app.delete("/vuln/admin/delete")
def vuln_admin_delete():
    # ERRO: usa ?user=<alvo> sem checar papel
    target = request.args.get("user")
    db = get_db()
    db.execute("DELETE FROM users WHERE username = '" + target + "'")  # (também inseguro)
    db.commit()
    return jsonify({"deleted": target})

# --- CORRIGIDO ---
def require_admin(func):
    def wrapper(*args, **kwargs):
        me = get_current_user()
        if me["role"] != "admin":
            return jsonify({"error": "forbidden"}), 403
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.delete("/safe/admin/delete")
@require_admin
def safe_admin_delete():
    target = request.args.get("user")
    db = get_db()
    # também corrige SQL injection aqui:
    db.execute("DELETE FROM users WHERE username = ?", (target,))
    db.commit()
    return jsonify({"deleted": target})

# ====================================================
# 3) INSECURE DESERIALIZATION (Desserialização insegura)
# ====================================================

# --- VULNERÁVEL ---
@app.post("/vuln/pickle")
def vuln_pickle():
    # ERRO: desserializa dados arbitrários do cliente
    data = request.data
    obj = pickle.loads(data)  # pericoloso: executa código
    return jsonify({"loaded_type": str(type(obj))})

# --- CORRIGIDO ---
@app.post("/safe/json")
def safe_json():
    # Use JSON (ou outra serialização segura)
    try:
        obj = json.loads(request.data.decode("utf-8"))
    except Exception:
        return jsonify({"error": "invalid json"}), 400
    # opcional: validação de schema
    if not isinstance(obj, dict) or "msg" not in obj:
        return jsonify({"error": "schema"}), 400
    return jsonify({"ok": True, "msg": obj["msg"]})

# ====================================================
# 4) COMMAND INJECTION (Injeção de comando)
# ====================================================

# --- VULNERÁVEL ---
@app.get("/vuln/ping")
def vuln_ping():
    host = request.args.get("host", "127.0.0.1")
    # ERRO: concatena comando
    cmd = f"ping -c 1 {host}" if os.name != "nt" else f"ping -n 1 {host}"
    code = os.system(cmd)
    return jsonify({"exit_code": code})

# --- CORRIGIDO ---
ALLOWED_HOST_RE = re.compile(r"^[a-zA-Z0-9\.\-]+$")

@app.get("/safe/ping")
def safe_ping():
    host = request.args.get("host", "127.0.0.1")
    if not ALLOWED_HOST_RE.match(host):
        return jsonify({"error": "invalid host"}), 400
    cmd = ["ping", "-c", "1", host] if os.name != "nt" else ["ping", "-n", "1", host]
    # Safe: sem shell, lista de args
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return jsonify({"exit_code": proc.returncode, "stdout": proc.stdout.decode("utf-8")[:200]})

# ====================================================
# Raiz
# ====================================================
@app.get("/")
def index():
    return jsonify({
        "ok": True,
        "routes": [
            "/vuln/sql/users?q=",
            "/safe/sql/users?q=",
            "/vuln/admin/delete?user=",
            "/safe/admin/delete?user=",
            "/vuln/pickle  (POST binário pickle)",
            "/safe/json    (POST JSON)",
            "/vuln/ping?host=",
            "/safe/ping?host="
        ],
        "tip": "Use o header X-User: alice (admin) ou bob (user)"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
