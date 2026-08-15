"""Hardened serializer configuration shared by every checkpoint backend."""

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer


def strict_checkpoint_serializer() -> JsonPlusSerializer:
    """Block import/call deserialization outside LangGraph's built-in safe types."""

    return JsonPlusSerializer(
        pickle_fallback=False,
        allowed_json_modules=None,
        allowed_msgpack_modules=None,
    )
