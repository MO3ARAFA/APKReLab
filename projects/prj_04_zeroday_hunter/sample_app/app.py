# Deliberately vulnerable demo shop (Flask style). Do not deploy.
import os
import sqlite3

from flask import Flask, abort, jsonify, request, redirect
from flask_login import current_user, login_required

from models import User, db

app = Flask(__name__)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    total = db.Column(db.Float)


def get_db():
    return sqlite3.connect("shop.db")


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/orders/<int:order_id>")
def get_order(order_id):
    order = Order.query.get(order_id)
    return jsonify(id=order.id, total=order.total)


@app.route("/my/orders/<int:order_id>")
@login_required
def get_my_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(404)
    return jsonify(id=order.id, total=order.total)


@app.route("/users/search")
@login_required
def search_users():
    db = get_db()
    rows = db.execute(f"SELECT id, name FROM users WHERE name LIKE '%{request.args['q']}%'").fetchall()
    return jsonify(rows)


@app.route("/users/<int:uid>")
@login_required
def get_user(uid):
    db = get_db()
    row = db.execute("SELECT id, name FROM users WHERE id = " + str(uid)).fetchone()
    return jsonify(row)


@app.route("/admin/delete_user/<int:uid>", methods=["POST"])
def delete_user(uid):
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    return jsonify(deleted=uid)


@app.route("/tools/ping")
@login_required
def ping():
    host = request.args.get("host", "localhost")
    os.system(f"ping -c 1 {host}")
    return "done"


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    data = request.get_json()
    price = data["price"]
    qty = data["qty"]
    total = price * qty
    return jsonify(total=total)


@app.route("/register", methods=["POST"])
def register():
    user = User(**request.get_json())
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id)


@app.route("/download")
@login_required
def download():
    path = request.args["file"]
    with open(path) as fh:
        return fh.read()


@app.route("/go")
def go():
    return redirect(request.args["next"])
