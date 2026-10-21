# mfp-mcp-vercel

MyFitnessPal connector for Claude, running on Vercel. A thin wrapper around
[delize/myfitness-mcp](https://github.com/delize/myfitness-mcp) (installed as a
pinned dependency) that makes it work serverless:

- **Stateless OAuth** (`stateless_oauth.py`): client ids, auth codes and tokens are
  HMAC-signed payloads, so the connector stays authorized across restarts and redeploys.
- **Stateless MCP transport** (`app.py`): fresh server task per request, JSON responses.
- **Cookies from env**: MyFitnessPal session cookies come from `MFP_COOKIES`.

## Environment variables

| Variable | Required | Notes |
|---|---|---|
| `MCP_OAUTH_PASSCODE` | yes | Passcode you type once when connecting Claude. Changing it revokes all tokens. |
| `MFP_COOKIES` | yes | Raw `Cookie` header from a myfitnesspal.com request (DevTools, Network tab), or a JSON `{name: value}` dict. |
| `MCP_RESOURCE_URL` | no | Public base URL. Defaults to `https://$VERCEL_PROJECT_PRODUCTION_URL`. |
| `MFP_TZ` | no | Time zone for "today" in the diary. Default `Europe/Athens`. |
| `MCP_ACCESS_TOKEN_TTL` | no | Access token lifetime in seconds. Default 30 days. |

Env var changes need a redeploy to take effect.

## Connect Claude

Settings, Connectors, Add custom connector, URL `https://<project>.vercel.app/mcp`.
Leave client id/secret empty and enter the passcode on the login page.

## Refreshing cookies

MyFitnessPal sessions expire (about 30 days). When tools start returning auth
errors: log into myfitnesspal.com, copy the `Cookie` request header again,
update `MFP_COOKIES`, redeploy.

## Updating upstream

Bump the commit hash of `myfitnesspal-mcp-service` in `pyproject.toml`. `app.py`
overrides MCP SDK internals, so keep `mcp` pinned and retest when bumping it.
