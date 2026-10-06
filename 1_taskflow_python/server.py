"""TaskFlow — Python backend (stdlib only: http.server + sqlite3) + JS frontend.
Запуск: python server.py  ->  http://localhost:8000"""
import json, sqlite3, hashlib, secrets, hmac, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "taskflow.db")

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    with db() as c:
        c.executescript("""
        create table if not exists users(id integer primary key, name text unique, pw text, salt text);
        create table if not exists sessions(token text primary key, user_id int);
        create table if not exists tasks(id integer primary key, user_id int, title text,
            status text default 'todo', priority int default 2, created text default current_timestamp);""")

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

class Handler(BaseHTTPRequestHandler):
    def reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def current_user(self):
        t = self.headers.get("Authorization", "").replace("Bearer ", "")
        with db() as c:
            r = c.execute("select user_id from sessions where token=?", (t,)).fetchone()
        return r["user_id"] if r else None

    def auth(self, kind):
        d = self.body()
        name, pw = (d.get("name") or "").strip(), d.get("pw") or ""
        if len(name) < 2 or len(pw) < 4:
            return self.reply(400, {"error": "Имя от 2 и пароль от 4 символов"})
        with db() as c:
            if kind == "register":
                salt = secrets.token_hex(8)
                try:
                    cur = c.execute("insert into users(name,pw,salt) values(?,?,?)", (name, hash_pw(pw, salt), salt))
                except sqlite3.IntegrityError:
                    return self.reply(409, {"error": "Имя занято"})
                uid = cur.lastrowid
            else:
                u = c.execute("select * from users where name=?", (name,)).fetchone()
                if not u or not hmac.compare_digest(u["pw"], hash_pw(pw, u["salt"])):
                    return self.reply(401, {"error": "Неверное имя или пароль"})
                uid = u["id"]
            token = secrets.token_hex(24)
            c.execute("insert into sessions values(?,?)", (token, uid))
        self.reply(200, {"token": token, "name": name})

    def route(self, m):
        p = urlparse(self.path).path
        if not p.startswith("/api/"):
            f = os.path.join(BASE, "static", "index.html")
            if p == "/" and os.path.exists(f):
                b = open(f, "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            else:
                self.reply(404, {"error": "not found"})
            return
        try:
            parts = p[5:].strip("/").split("/")
            if parts[0] in ("register", "login") and m == "POST":
                return self.auth(parts[0])
            uid = self.current_user()
            if not uid:
                return self.reply(401, {"error": "unauthorized"})
            with db() as c:
                if parts[0] == "tasks":
                    if m == "GET":
                        rows = c.execute("select * from tasks where user_id=? order by priority desc, id desc", (uid,))
                        return self.reply(200, [dict(r) for r in rows])
                    if m == "POST":
                        d = self.body()
                        t = (d.get("title") or "").strip()
                        if not t:
                            return self.reply(400, {"error": "Нужен заголовок"})
                        pr = min(3, max(1, int(d.get("priority", 2))))
                        cur = c.execute("insert into tasks(user_id,title,priority) values(?,?,?)", (uid, t[:200], pr))
                        return self.reply(201, {"id": cur.lastrowid})
                    tid = int(parts[1])
                    if m == "PUT":
                        st = self.body().get("status")
                        if st not in ("todo", "doing", "done"):
                            return self.reply(400, {"error": "bad status"})
                        c.execute("update tasks set status=? where id=? and user_id=?", (st, tid, uid))
                        return self.reply(200, {"ok": 1})
                    if m == "DELETE":
                        c.execute("delete from tasks where id=? and user_id=?", (tid, uid))
                        return self.reply(200, {"ok": 1})
                if parts[0] == "stats" and m == "GET":
                    r = c.execute("select status, count(*) n from tasks where user_id=? group by status", (uid,))
                    s = {"todo": 0, "doing": 0, "done": 0}
                    s.update({x["status"]: x["n"] for x in r})
                    total = sum(s.values())
                    s["percent_done"] = round(100 * s["done"] / total) if total else 0
                    return self.reply(200, s)
            self.reply(404, {"error": "not found"})
        except (ValueError, IndexError, json.JSONDecodeError):
            self.reply(400, {"error": "bad request"})

    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PUT(self): self.route("PUT")
    def do_DELETE(self): self.route("DELETE")
    def log_message(self, *a): pass

if __name__ == "__main__":
    init()
    print("TaskFlow: http://localhost:8000")
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
