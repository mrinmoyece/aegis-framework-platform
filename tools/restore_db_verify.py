"""Verify and rebuild an isolated PostgreSQL logical restore."""

from __future__ import annotations

import argparse
import json
import os
from hashlib import sha256
from pathlib import Path

from psycopg import Connection
from psycopg.rows import dict_row

from aegis_framework.durability import ApplicationEvent
from aegis_framework.replay import ReplayDebugger


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default=os.getenv("AEGIS_RESTORE_DSN"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()
    if not args.dsn:
        parser.error("AEGIS_RESTORE_DSN or --dsn is required")
    with Connection.connect(args.dsn, row_factory=dict_row) as connection:
        events = tuple(
            ApplicationEvent.model_validate(row)
            for row in connection.execute(
                """
                SELECT tenant_id, aggregate_type, aggregate_id,
                       aggregate_sequence, tenant_cursor, event_id, event_type,
                       occurred_at, actor_ref, correlation_ref, causation_ref,
                       schema_version, payload, aggregate_previous_hash,
                       tenant_previous_hash, record_hash
                FROM aegis.application_events
                WHERE tenant_id = 'restore-tenant'
                ORDER BY tenant_cursor
                """
            ).fetchall()
        )
        integrity = ReplayDebugger(events).verify()
        if not integrity.valid:
            raise RuntimeError("restored application ledger integrity failed")
        if args.rebuild:
            _rebuild(connection)
        projection = connection.execute(
            """
            SELECT
              (SELECT count(*) FROM aegis.investigation_runs
               WHERE tenant_id = 'restore-tenant') AS runs,
              (SELECT count(*) FROM aegis.investigation_timeline
               WHERE tenant_id = 'restore-tenant') AS timeline
            """
        ).fetchone()
        migrations = connection.execute(
            """
            SELECT version, filename, checksum
            FROM aegis.schema_migrations
            ORDER BY version
            """
        ).fetchall()
        rls = connection.execute(
            """
            SELECT count(*) AS guarded
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE (n.nspname, c.relname) IN (
              ('aegis', 'application_events'),
              ('aegis', 'memory_chunks'),
              ('aegis', 'interop_trust_registry'),
              ('public', 'checkpoints'),
              ('public', 'checkpoint_blobs'),
              ('public', 'checkpoint_writes')
            )
              AND c.relrowsecurity
              AND c.relforcerowsecurity
            """
        ).fetchone()
        pending_outbox = connection.execute(
            """
            SELECT count(*) AS pending
            FROM aegis.outbox_messages
            WHERE tenant_id = 'restore-tenant' AND status = 'pending'
            """
        ).fetchone()
        checkpoint_rows = connection.execute(
            """
            SELECT
              (SELECT count(*) FROM public.checkpoints)
              + (SELECT count(*) FROM public.checkpoint_blobs)
              + (SELECT count(*) FROM public.checkpoint_writes) AS rows
            """
        ).fetchone()
    if (
        projection is None
        or migrations is None
        or rls is None
        or pending_outbox is None
        or checkpoint_rows is None
    ):
        raise RuntimeError("restore verification query returned no result")
    if projection["runs"] != 1 or projection["timeline"] != 2:
        raise RuntimeError("application projection rebuild did not converge")
    if len(migrations) != 10:
        raise RuntimeError("migration history is incomplete")
    if rls["guarded"] != 6:
        raise RuntimeError("restored tenant RLS is incomplete")
    evidence = {
        "checkpoint_rows_after_disposable_rebuild": checkpoint_rows["rows"],
        "event_count": integrity.event_count,
        "last_cursor": integrity.last_cursor,
        "last_hash": integrity.last_hash,
        "migration_count": len(migrations),
        "migration_digest": sha256(
            json.dumps(migrations, default=str, sort_keys=True).encode()
        ).hexdigest(),
        "outbox_pending_reconciliation": pending_outbox["pending"],
        "projection_rows": projection["runs"],
        "rls_guarded_tables": rls["guarded"],
        "timeline_rows": projection["timeline"],
        "vector_index_rebuilt": args.rebuild,
    }
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


def _rebuild(connection: Connection[dict[str, object]]) -> None:
    connection.execute(
        "DELETE FROM aegis.investigation_timeline WHERE tenant_id = 'restore-tenant'"
    )
    connection.execute(
        "DELETE FROM aegis.investigation_runs WHERE tenant_id = 'restore-tenant'"
    )
    connection.execute(
        """
        INSERT INTO aegis.investigation_runs (
          tenant_id, run_id, incident_id, request_ref, workflow_id, status,
          version, last_cursor, created_at, updated_at
        )
        SELECT
          tenant_id,
          aggregate_id,
          min(payload->>'incident_id'),
          min(payload->>'request_ref'),
          min(payload->>'workflow_id'),
          (array_agg(payload->>'status' ORDER BY tenant_cursor DESC))[1],
          max(aggregate_sequence),
          max(tenant_cursor),
          min(occurred_at),
          max(occurred_at)
        FROM aegis.application_events
        WHERE tenant_id = 'restore-tenant'
          AND aggregate_type = 'investigation'
        GROUP BY tenant_id, aggregate_id
        """
    )
    connection.execute(
        """
        INSERT INTO aegis.investigation_timeline (
          tenant_id, run_id, tenant_cursor, event_type, status,
          failure_code, occurred_at
        )
        SELECT
          tenant_id, aggregate_id, tenant_cursor, event_type,
          payload->>'status', NULL, occurred_at
        FROM aegis.application_events
        WHERE tenant_id = 'restore-tenant'
          AND aggregate_type = 'investigation'
        ORDER BY tenant_cursor
        """
    )
    connection.execute("REINDEX INDEX aegis.memory_chunks_vector_idx")
    connection.execute(
        "TRUNCATE public.checkpoint_writes, public.checkpoint_blobs, public.checkpoints"
    )
    connection.commit()


if __name__ == "__main__":
    raise SystemExit(main())
