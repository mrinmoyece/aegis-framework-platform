"""Deterministic unit tests for postgres.py security-critical paths (no real DB)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis_framework.errors import RepositoryUnavailable
from aegis_framework.postgres import (
    MigrationRunner,
    _assert_runtime_session_security,
    _configure_runtime_connection,
    _reset_runtime_connection,
    open_runtime_pool,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_connection(
    *,
    current_user: str = "aegis_runtime",
    rolsuper: bool = False,
    rolbypassrls: bool = False,
    session_rolsuper: bool = False,
    session_rolbypassrls: bool = False,
    row_security: str = "on",
    transaction_status: object = None,
    tenant_id: str | None = None,
) -> MagicMock:
    from psycopg.pq import TransactionStatus

    conn = MagicMock()
    conn.info.transaction_status = (
        transaction_status if transaction_status is not None else TransactionStatus.IDLE
    )

    role_row = {
        "current_user": current_user,
        "rolsuper": rolsuper,
        "rolbypassrls": rolbypassrls,
    }
    session_row = {
        "session_rolsuper": session_rolsuper,
        "session_rolbypassrls": session_rolbypassrls,
    }
    row_security_row = {"row_security": row_security}
    leaked_row: dict[str, str | None] = {"tenant_id": tenant_id}

    def execute_side_effect(query: str, *args: object, **kwargs: object) -> MagicMock:
        result = MagicMock()
        q = str(query).strip()
        if "session_rolsuper" in q:
            result.fetchone.return_value = session_row
        elif "current_user" in q and "rolsuper" in q:
            result.fetchone.return_value = role_row
        elif "row_security" in q:
            result.fetchone.return_value = row_security_row
        elif "aegis.tenant_id" in q and "RESET" not in q and "set_config" not in q:
            result.fetchone.return_value = leaked_row
        else:
            result.fetchone.return_value = {}
        return result

    conn.execute.side_effect = execute_side_effect
    return conn


# ---------------------------------------------------------------------------
# open_runtime_pool
# ---------------------------------------------------------------------------


class TestOpenRuntimePoolBounds:
    def test_negative_minimum_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="bounds"):
            open_runtime_pool(dsn="postgresql://localhost/test", minimum_size=-1)

    def test_zero_maximum_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="bounds"):
            open_runtime_pool(dsn="postgresql://localhost/test", maximum_size=0)

    def test_minimum_exceeds_maximum_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="bounds"):
            open_runtime_pool(
                dsn="postgresql://localhost/test", minimum_size=5, maximum_size=3
            )

    def test_pool_open_failure_raises_repository_unavailable(self) -> None:
        with patch("aegis_framework.postgres.ConnectionPool") as mock_cls:
            mock_pool = MagicMock()
            mock_pool.open.side_effect = OSError("connection refused")
            mock_cls.return_value = mock_pool
            with pytest.raises(RepositoryUnavailable, match="runtime pool failed"):
                open_runtime_pool(dsn="postgresql://localhost/test")


# ---------------------------------------------------------------------------
# _assert_runtime_session_security
# ---------------------------------------------------------------------------


class TestAssertRuntimeSessionSecurity:
    def test_passes_when_all_safe(self) -> None:
        conn = _mock_connection()
        _assert_runtime_session_security(conn, failure_message="should not raise")

    def test_raises_when_not_aegis_runtime(self) -> None:
        conn = _mock_connection(current_user="postgres")
        with pytest.raises(RepositoryUnavailable):
            _assert_runtime_session_security(conn, failure_message="bad role")

    def test_raises_when_rolsuper(self) -> None:
        conn = _mock_connection(rolsuper=True)
        with pytest.raises(RepositoryUnavailable):
            _assert_runtime_session_security(conn, failure_message="superuser")

    def test_raises_when_rolbypassrls(self) -> None:
        conn = _mock_connection(rolbypassrls=True)
        with pytest.raises(RepositoryUnavailable):
            _assert_runtime_session_security(conn, failure_message="bypassrls")

    def test_raises_when_session_rolsuper(self) -> None:
        conn = _mock_connection(session_rolsuper=True)
        with pytest.raises(RepositoryUnavailable):
            _assert_runtime_session_security(conn, failure_message="session super")

    def test_raises_when_session_rolbypassrls(self) -> None:
        conn = _mock_connection(session_rolbypassrls=True)
        with pytest.raises(RepositoryUnavailable):
            _assert_runtime_session_security(
                conn, failure_message="session bypassrls"
            )

    def test_raises_when_row_security_off(self) -> None:
        conn = _mock_connection(row_security="off")
        with pytest.raises(RepositoryUnavailable):
            _assert_runtime_session_security(conn, failure_message="rls off")

    def test_raises_when_role_row_is_none(self) -> None:
        conn = MagicMock()
        result = MagicMock()
        result.fetchone.return_value = None
        conn.execute.return_value = result
        with pytest.raises(RepositoryUnavailable):
            _assert_runtime_session_security(conn, failure_message="no role row")


# ---------------------------------------------------------------------------
# _reset_runtime_connection
# ---------------------------------------------------------------------------


class TestResetRuntimeConnection:
    def test_raises_when_tenant_id_leaked(self) -> None:
        conn = _mock_connection(tenant_id="tenant-leaked")
        with pytest.raises(RepositoryUnavailable, match="leaked"):
            _reset_runtime_connection(conn)

    def test_passes_when_no_tenant_leaked(self) -> None:
        conn = _mock_connection(tenant_id=None)
        _reset_runtime_connection(conn)  # should not raise

    def test_rolls_back_active_transaction(self) -> None:
        from psycopg.pq import TransactionStatus

        conn = _mock_connection(
            tenant_id=None, transaction_status=TransactionStatus.INTRANS
        )
        _reset_runtime_connection(conn)
        conn.rollback.assert_called()


# ---------------------------------------------------------------------------
# _configure_runtime_connection
# ---------------------------------------------------------------------------


class TestConfigureRuntimeConnection:
    def test_sets_role_and_rls(self) -> None:
        conn = _mock_connection()
        _configure_runtime_connection(conn)
        calls = [str(c.args[0]) for c in conn.execute.call_args_list]
        assert any("SET ROLE aegis_runtime" in c for c in calls)
        assert any("row_security" in c for c in calls)
        conn.commit.assert_called_once()


# ---------------------------------------------------------------------------
# MigrationRunner
# ---------------------------------------------------------------------------


class TestMigrationRunner:
    def test_default_path_exists(self) -> None:
        runner = MigrationRunner()
        assert runner._path.suffix == ".sql"

    def test_custom_path_stored(self) -> None:
        p = Path(".") / "custom.sql"
        runner = MigrationRunner(path=p)
        assert runner._path == p

    def test_path_not_found_raises(self) -> None:
        runner = MigrationRunner(path=Path("/nonexistent/migration.sql"))
        conn = MagicMock()
        with pytest.raises(FileNotFoundError):
            runner.apply(conn)
