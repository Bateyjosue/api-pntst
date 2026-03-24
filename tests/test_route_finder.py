"""Tests for route_finder module."""

import os
import tempfile
import pytest
from api_pntst.discovery.route_finder import find_routes, _add_route


class TestAddRoute:
    def test_basic_add(self):
        routes, seen = [], set()
        _add_route("GET", "/api/users", "app.py", "code", routes, seen)
        assert len(routes) == 1
        assert routes[0]["method"] == "GET"
        assert routes[0]["path"] == "/api/users"

    def test_deduplicates(self):
        routes, seen = [], set()
        _add_route("GET", "/api/users", "app.py", "code", routes, seen)
        _add_route("GET", "/api/users", "app.py", "code", routes, seen)
        assert len(routes) == 1

    def test_prepends_slash(self):
        routes, seen = [], set()
        _add_route("POST", "login", "app.py", "code", routes, seen)
        assert routes[0]["path"] == "/login"

    def test_skips_template_literals(self):
        routes, seen = [], set()
        _add_route("GET", "${BASE_PATH}/users", "app.py", "code", routes, seen)
        assert len(routes) == 0


class TestFindRoutes:
    def test_finds_flask_route(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write("""
from flask import Flask
app = Flask(__name__)

@app.route('/users', methods=['GET', 'POST'])
def users():
    pass

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    pass
""")
            routes = find_routes(tmpdir)
            paths = [r["path"] for r in routes]
            assert "/users" in paths

    def test_finds_fastapi_route(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "main.py"), "w") as f:
                f.write("""
from fastapi import FastAPI
app = FastAPI()

@app.get('/items')
def get_items():
    pass

@app.post('/items')
def create_item():
    pass
""")
            routes = find_routes(tmpdir)
            methods = {r["method"] for r in routes}
            paths = {r["path"] for r in routes}
            assert "GET" in methods
            assert "POST" in methods
            assert "/items" in paths

    def test_finds_express_route(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "routes.js"), "w") as f:
                f.write("""
const router = express.Router();
router.get('/products', getProducts);
router.post('/products', createProduct);
router.delete('/products/:id', deleteProduct);
""")
            routes = find_routes(tmpdir)
            methods = {r["method"] for r in routes}
            assert "GET" in methods
            assert "POST" in methods
            assert "DELETE" in methods

    def test_returns_empty_for_missing_dir(self):
        routes = find_routes("/nonexistent/path/xyz")
        assert routes == []

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = os.path.join(tmpdir, "node_modules", "express")
            os.makedirs(nm)
            with open(os.path.join(nm, "router.js"), "w") as f:
                f.write("app.get('/should-not-appear', handler);")
            routes = find_routes(tmpdir)
            paths = [r["path"] for r in routes]
            assert "/should-not-appear" not in paths
