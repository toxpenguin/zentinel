"""Zentinel agent SDK — write external agents for the Zentinel proxy.

Implements the agent side of the v2 protocol over Unix domain sockets;
subclass :class:`Agent`, override the events you need, call :func:`run`.
"""

from .server import Agent, Server, run
from .types import (
    PROTOCOL_VERSION,
    AuditMetadata,
    Decision,
    HeaderOp,
    RequestBodyChunkEvent,
    RequestCompleteEvent,
    RequestHeadersEvent,
    Response,
    ResponseBodyChunkEvent,
    ResponseHeadersEvent,
    add_header,
    allow,
    allow_response,
    block,
    challenge,
    redirect,
    remove_header,
    respond,
    set_header,
)

__all__ = [
    "PROTOCOL_VERSION",
    "Agent",
    "AuditMetadata",
    "Decision",
    "HeaderOp",
    "RequestBodyChunkEvent",
    "RequestCompleteEvent",
    "RequestHeadersEvent",
    "Response",
    "ResponseBodyChunkEvent",
    "ResponseHeadersEvent",
    "Server",
    "add_header",
    "allow",
    "allow_response",
    "block",
    "challenge",
    "redirect",
    "remove_header",
    "respond",
    "run",
    "set_header",
]
