from flask import Flask, render_template, request, redirect, session
from db import get_db, init_db
import bcrypt

app = Flask(__name__)
app.secret_key = "dev_secret_key"

XSS_DEMO = False
SQLI_LOGIN_DEMO = True   


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/")
def home():
    if "user_id" in session:
        return redirect("/comments")
    return "Mini Vuln App çalışıyor. /register veya /login"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        role = "admin" if username == "admin" else "user"

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role),
            )
            db.commit()
        except Exception as e:
            return f"Register error: {e}", 400

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user:
            stored = user["password_hash"]
            if isinstance(stored, str):
                stored = stored.encode("utf-8")

            if bcrypt.checkpw(password.encode("utf-8"), stored):
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["username"] = user["username"]
                return redirect("/comments")

        return "Login failed", 401

    return render_template("login.html")

@app.route("/register_vuln", methods=["GET", "POST"])
def register_vuln():
    """
    Bilerek zayıf demo: plaintext password.
    SQLi'yi login tarafında göstereceğimiz için burada insert parametrized (güvenli) bırakıldı.
    """
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        role = "admin" if username == "admin" else "user"

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users_vuln (username, password, role) VALUES (?, ?, ?)",
                (username, password, role),
            )
            db.commit()
        except Exception as e:
            return f"Register_vuln error: {e}", 400

        return redirect("/login_vuln")

    return render_template("register.html")


@app.route("/login_vuln", methods=["GET", "POST"])
def login_vuln():
    """
    Bilerek SQL Injection'a açık login demo.
    """
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db()

        if SQLI_LOGIN_DEMO:
            query = (
                "SELECT id, username, role FROM users_vuln "
                f"WHERE username = '{username}' AND password = '{password}'"
            )
            user = db.execute(query).fetchone()
        else:
            user = db.execute(
                "SELECT id, username, role FROM users_vuln WHERE username = ? AND password = ?",
                (username, password),
            ).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            return redirect("/comments")

        return "Login failed", 401

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/comments", methods=["GET", "POST"])
def comments():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()

    if request.method == "POST":
        content = request.form["content"]
        db.execute(
            "INSERT INTO comments (user_id, content) VALUES (?, ?)",
            (session["user_id"], content),
        )
        db.commit()

    rows = db.execute(
        """
        SELECT comments.id, comments.content, comments.created_at, users.username
        FROM comments
        JOIN users ON users.id = comments.user_id
        ORDER BY comments.id DESC
        """
    ).fetchall()

    return render_template("comments.html", comments=rows, xss_demo=XSS_DEMO)

@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    rows = db.execute(
        """
        SELECT comments.id, comments.content, comments.created_at, users.username
        FROM comments
        JOIN users ON users.id = comments.user_id
        ORDER BY comments.id DESC
        """
    ).fetchall()

    return render_template("admin.html", comments=rows, xss_demo=XSS_DEMO)


@app.route("/admin/delete/<int:comment_id>", methods=["POST"])
def admin_delete_comment(comment_id):
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    return redirect("/admin")

@app.route("/search", methods=["GET", "POST"])
def search():
    if "user_id" not in session:
        return redirect("/login")

    results = []
    q = ""

    if request.method == "POST":
        q = request.form["q"]
        db = get_db()

        results = db.execute(
            """
            SELECT comments.id, comments.content, comments.created_at, users.username
            FROM comments
            JOIN users ON users.id = comments.user_id
            WHERE users.username = ?
            ORDER BY comments.id DESC
            """,
            (q,),
        ).fetchall()

    return render_template("search.html", results=results, q=q)


if __name__ == "__main__":
    app.run(debug=True)