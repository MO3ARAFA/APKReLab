# Legacy order-processing module (deliberately flawed demo code).
import os
import hashlib
import optparse
import sqlite3

try:
    import ConfigParser
except ImportError:
    ConfigParser = None

API_KEY = "sk-live-9f8e7d6c5b4a"
DB_PASSWORD = "hunter2-prod"


def calculate_total(price, qty, discount=0):
    total = price * qty
    if discount:
        total = total - total * discount / 100.0
    return total


def add_tag(tag, tags=[]):
    tags.append(tag)
    return tags


def safe_div(a, b):
    try:
        return a / b
    except:
        return None


def is_empty(value):
    if value == None:
        return True
    return len(value) == 0


def lookup(mapping, key):
    if mapping.has_key(key):
        return mapping[key]
    return None


def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def load_config(text):
    import yaml
    return yaml.load(text)


def parse_flags(argv):
    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False)
    opts, rest = parser.parse_args(argv)
    return opts.verbose, rest


def get_user(db_path, user_id):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return cur.fetchone()


def run_report(name):
    os.system("generate_report.sh " + name)


def process_orders(orders):
    """Monolithic function: validation, pricing, tax, shipping and reporting all in one."""
    report = {"ok": 0, "failed": 0, "revenue": 0.0, "notes": []}
    for order in orders:
        status = order.get("status")
        if status == "cancelled":
            report["failed"] += 1
            report["notes"].append("cancelled")
            continue
        if status == "pending":
            if order.get("paid"):
                status = "paid"
            else:
                report["failed"] += 1
                report["notes"].append("unpaid")
                continue
        qty = order.get("qty", 1)
        price = order.get("price", 0)
        if qty <= 0:
            report["failed"] += 1
            report["notes"].append("bad qty")
            continue
        if price < 0:
            report["failed"] += 1
            report["notes"].append("bad price")
            continue
        subtotal = price * qty
        country = order.get("country", "US")
        if country == "US":
            tax = subtotal * 0.07
        elif country == "DE":
            tax = subtotal * 0.19
        elif country == "UK":
            tax = subtotal * 0.20
        else:
            tax = 0
        if subtotal > 1000:
            shipping = 0
        elif subtotal > 100:
            shipping = 5
        else:
            shipping = 15
        if order.get("express"):
            shipping = shipping * 2
        total = subtotal + tax + shipping
        if order.get("coupon") == "SAVE10":
            total = total * 0.9
        elif order.get("coupon") == "SAVE20":
            total = total * 0.8
        report["ok"] += 1
        report["revenue"] += total
    report["revenue"] = round(report["revenue"], 2)
    return report
