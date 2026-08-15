"""AWS Lambda is unavailable in this scaffold."""

from typing import Any


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Refuse invocation while deployment remains unimplemented."""
    del event, context
    raise RuntimeError("AWS Lambda is not implemented in this scaffold")
