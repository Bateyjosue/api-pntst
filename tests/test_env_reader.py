"""Tests for env_reader module."""

import os
import tempfile
import pytest
from api_pntst.discovery.env_reader import read_env, _parse_dotenv


class TestParseDotenv:
    def test_basic_key_value(self):
        result = _parse_dotenv("PORT=3000\nDB_HOST=localhost")
        assert result == {"PORT": "3000", "DB_HOST": "localhost"}

    def test_strips_double_quotes(self):
        result = _parse_dotenv('BASE_URL="http://localhost:3000"')
        assert result["BASE_URL"] == "http://localhost:3000"

    def test_strips_single_quotes(self):
        result = _parse_dotenv("API_KEY='mysecret'")
        assert result["API_KEY"] == "mysecret"

    def test_ignores_comments(self):
        result = _parse_dotenv("# comment\nPORT=8080")
        assert "# comment" not in result
        assert result["PORT"] == "8080"

    def test_ignores_blank_lines(self):
        result = _parse_dotenv("\n\nPORT=9000\n\n")
        assert result == {"PORT": "9000"}

    def test_value_with_equals_sign(self):
        result = _parse_dotenv("DB_URL=postgres://user:pass@host/db?ssl=true")
        assert result["DB_URL"] == "postgres://user:pass@host/db?ssl=true"


class TestReadEnv:
    def test_reads_dot_env_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = os.path.join(tmpdir, ".env")
            with open(env_path, "w") as f:
                f.write("TEST_PORT=4321\nTEST_HOST=127.0.0.1\n")

            result = read_env(tmpdir)
            assert result["TEST_PORT"] == "4321"
            assert result["TEST_HOST"] == "127.0.0.1"

    def test_returns_dict_for_missing_dir(self):
        result = read_env("/nonexistent/directory/xyz")
        assert isinstance(result, dict)

    def test_includes_os_environ(self):
        os.environ["_API_PNTST_TEST_VAR"] = "hello"
        try:
            result = read_env("/tmp")
            assert result.get("_API_PNTST_TEST_VAR") == "hello"
        finally:
            del os.environ["_API_PNTST_TEST_VAR"]

    def test_env_file_overrides_os_environ(self):
        """Values in .env should take precedence over os.environ."""
        os.environ["_PNTST_OVERRIDE"] = "from_os"
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".env"), "w") as f:
                f.write("_PNTST_OVERRIDE=from_file\n")
            result = read_env(tmpdir)
            assert result["_PNTST_OVERRIDE"] == "from_file"
        del os.environ["_PNTST_OVERRIDE"]
