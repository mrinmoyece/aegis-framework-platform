"""Optional durable LangGraph checkpoint adapter backed by PostgreSQL."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from langgraph.checkpoint.postgres import PostgresSaver
from psycopg import Connection
from psycopg.rows import dict_row

from aegis_framework.checkpointing import strict_checkpoint_serializer
from aegis_framework.graph import LangGraphInvestigator
from aegis_framework.ports import StructuredModelPort


@contextmanager
def postgres_investigator(
    *,
    dsn: str,
    model: StructuredModelPort,
) -> Iterator[LangGraphInvestigator]:
    """Create checkpoint tables and bind one investigator to a saver lifetime."""

    with Connection.connect(
        dsn,
        autocommit=True,
        prepare_threshold=0,
        row_factory=dict_row,
    ) as connection:
        checkpointer = PostgresSaver(
            connection,
            serde=strict_checkpoint_serializer(),
        )
        checkpointer.setup()
        yield LangGraphInvestigator(model=model, checkpointer=checkpointer)
