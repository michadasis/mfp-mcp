"""Vercel entrypoint: serves the MyFitnessPal MCP server as a serverless ASGI app.

The upstream server (delize/myfitness-mcp) is installed as a dependency and
left untouched. This file adapts it to Vercel:

- OAuth: swaps in stateless_oauth.py, where client ids, auth codes and tokens
  are HMAC-signed payloads instead of in-memory dicts, so the connector stays
  authorized across restarts, redeploys and cold starts.
- MCP transport: stateless JSON mode with a fresh server task per request
  (no lifespan-owned task group, no in-memory sessions).
- MyFitnessPal cookies: read from the MFP_COOKIES env var (JSON dict, or the
  raw "Cookie:" header copied from browser DevTools) instead of a mounted
  Firefox profile. Env vars persist across restarts and redeploys.
"""

import importlib.util
import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# --- Environment defaults (must be set before importing the server) ---------

os.environ.setdefault("MCP_TRANSPORT", "streamable-http")

# Diary dates default to "today"; make that the user's local day, not UTC.
os.environ["TZ"] = os.environ.get("MFP_TZ", "Europe/Athens")
time.tzset()

if not os.environ.get("MCP_RESOURCE_URL") and os.environ.get("VERCEL_PROJECT_PRODUCTION_URL"):
    os.environ["MCP_RESOURCE_URL"] = f"https://{os.environ['VERCEL_PROJECT_PRODUCTION_URL']}"


def _parse_cookies(raw: str) -> dict[str, str]:
    """Accept a JSON cookie dict ({name: value} or {"cookies": {...}}) or a raw Cookie header."""
    raw = raw.strip()
    if raw.lower().startswith("cookie:"):
        raw = raw[len("cookie:"):].strip()
    if raw.startswith("{"):
        data = json.loads(raw)
        cookies = data.get("cookies", data)
        return {str(k): str(v) for k, v in cookies.items()}
    cookies: dict[str, str] = {}
    for part in raw.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name:
            cookies[name] = value
    return cookies


_raw_cookies = os.environ.get("MFP_COOKIES", "")
if _raw_cookies:
    _cookie_file = Path("/tmp/mfp_cookies.json")
    _cookie_file.write_text(json.dumps({"cookies": _parse_cookies(_raw_cookies)}))
    os.environ["MFP_COOKIES_FILE"] = str(_cookie_file)
    os.environ.pop("MFP_FIREFOX_PROFILE_DIR", None)

# Register the stateless OAuth provider under the upstream module name, so the
# server's `from .oauth_provider import SinglePasscodeOAuthProvider` picks it up.
_spec = importlib.util.spec_from_file_location("myfitnesspal_mcp.oauth_provider", ROOT / "stateless_oauth.py")
_oauth_module = importlib.util.module_from_spec(_spec)
sys.modules["myfitnesspal_mcp.oauth_provider"] = _oauth_module
_spec.loader.exec_module(_oauth_module)

# --- Server -----------------------------------------------------------------

import anyio  # noqa: E402
from mcp.server.streamable_http import StreamableHTTPServerTransport  # noqa: E402
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import PlainTextResponse, Response  # noqa: E402

from myfitnesspal_mcp.server import mcp  # noqa: E402

logger = logging.getLogger("myfitnesspal_mcp.vercel")


class ServerlessSessionManager(StreamableHTTPSessionManager):
    """Stateless session manager that needs no lifespan-owned task group."""

    @asynccontextmanager
    async def run(self):
        yield

    async def _handle_request(self, scope, receive, send) -> None:
        if scope["method"] != "POST":
            # No sessions and no server-initiated SSE stream in stateless mode.
            await Response(status_code=405, headers={"Allow": "POST"})(scope, receive, send)
            return

        transport = StreamableHTTPServerTransport(
            mcp_session_id=None,
            is_json_response_enabled=True,
            event_store=None,
            security_settings=self.security_settings,
        )

        async with anyio.create_task_group() as tg:

            async def run_server(*, task_status=anyio.TASK_STATUS_IGNORED):
                async with transport.connect() as (read_stream, write_stream):
                    task_status.started()
                    try:
                        await self.app.run(
                            read_stream,
                            write_stream,
                            self.app.create_initialization_options(),
                            stateless=True,
                        )
                    except Exception:
                        logger.exception("Stateless MCP request crashed")

            try:
                await tg.start(run_server)
                await transport.handle_request(scope, receive, send)
            finally:
                with anyio.CancelScope(shield=True):
                    await transport.terminate()
                tg.cancel_scope.cancel()


mcp._session_manager = ServerlessSessionManager(
    app=mcp._mcp_server,
    json_response=True,
    stateless=True,
    security_settings=mcp.settings.transport_security,
)


@mcp.custom_route("/", methods=["GET"])
async def health(request: Request) -> Response:
    return PlainTextResponse("MyFitnessPal MCP is running. Connector URL: /mcp\n")


app = mcp.streamable_http_app()
