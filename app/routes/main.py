"""
app/routes/main.py — Landing page and top-level routes.
"""
from flask import Blueprint, render_template

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/demo")
def demo_page():
    return render_template("demo.html")
