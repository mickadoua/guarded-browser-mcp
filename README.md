# guarded-browser-mcp

An MCP server that lets an AI agent drive a **self-hosted Chromium**, with guardrails enforced by the server
itself rather than by the agent's instructions.

Built for a personal assistant: filling in online forms, preparing purchases, reading pages, while the human
watches the same browser live and takes over whenever needed (login, two-factor authentication, captcha).

## Guardrails

| Guardrail | Effect |
|---|---|
| Allowed / denied sites | Domain allowlist or denylist per session. Any navigation to a refused domain is blocked inside the browser, including after a redirect or within a frame. The denylist always wins. |
| Separate final action | `click` refuses buttons that send, submit, pay or order. Only `submit_final` triggers them: set it to "ask first" in your MCP client or gateway, and every submission waits for human approval. Toggles (checkboxes, radio buttons, switches, pressed buttons) only change a choice and are never final. |
| Sensitive fields | `type_text` refuses password, payment card, IBAN and one-time-code fields. The human fills them in directly in the browser. |
| Isolated sessions | Each access token has its own browser context (cookies, logins, rules). A token never drives another session. Several sessions can share one Chromium. |
| Untrusted content | Page text is returned as data, never as instructions. |

Site rules are re-read on every call: edit them without restarting.

## Tools

| Tool | Effect |
|---|---|
| `open_url` | open a URL if the site is allowed |
| `read_page` | title, URL, visible text and numbered actionable elements |
| `screenshot` | PNG screenshot |
| `click` | click a numbered element, unless it is a final action |
| `type_text` | fill in a field, unless it is sensitive |
| `select_option` | pick an option in a dropdown |
| `submit_final` | trigger a final action, with a summary of what goes out |
| `sites` | rules in force for the session (read-only) |

## Architecture

```
agent ──MCP + token──▶ guarded-browser-mcp ──CDP (secret path)──▶ nginx gate ──▶ Chromium (one session)
                                                                                   ▲
human ──web UI (KasmVNC, behind your authentication)──────────────────────────────┘
```

- Chromium (`linuxserver/chromium` image) serves a web UI and keeps its profile on disk.
- Chrome only accepts remote debugging on `127.0.0.1`: a small nginx gate sharing its network namespace exposes
  it on a secret path, with access logging disabled.
- `guarded-browser-mcp` uses Playwright over CDP: no browser is bundled in its image.

## Setup

1. Copy `deploy/compose.example.yaml`, `sessions.example.yaml` to `sessions.yaml`, and `policies/example.yaml`
   to `policies/<session>.yaml`.
2. In `.env`, generate long random values: `BROWSER_PASSWORD`, `CDP_TOKEN_ASSISTANT`, `MCP_TOKEN_ASSISTANT`
   (32 characters minimum).
3. `docker compose up -d`.
4. Publish the browser web UI (port 3000) only behind strong authentication, never in the clear on the Internet.
   Never publish the CDP port. Publish the MCP server only behind an authenticating proxy (for example a tunnel
   with a service token), in addition to its bearer token.
5. Register the server in your MCP client: streamable HTTP transport, path `/mcp`, header
   `Authorization: Bearer <MCP_TOKEN_ASSISTANT>`. Set `submit_final` to "ask first".

### Several sessions

Two ways to add a session, both declared in `sessions.yaml` with their own token and rules:

- **Same Chromium, isolated context** (`isolated: true`): light, no new container. The session gets a fresh
  browser context with its own cookies, invisible to other sessions. Its cookies and local storage are saved to
  `STATE_DIR/<session>.json` (mode 600) after every call and restored when Chromium restarts. Session storage and
  IndexedDB are not kept. Its windows show up in the shared web UI, so a human can log in there.
  Add `label: SHOP` to prefix every page title of the session with `[SHOP] `, so its windows can be told
  apart in the shared web UI.
- **Dedicated Chromium**: duplicate the browser and gate services and add their two variables. Full isolation,
  including the web UI, at the cost of one more browser in memory.

At most one session per Chromium can use the browser's own profile (no `isolated`).

### One tab per agent

If the MCP gateway forwards the caller's identity in `x-paperclip-agent-id` (header name configurable with
`AGENT_HEADER`), each agent drives its own tab inside the session: agents of the same session share cookies and
logins without navigating each other's pages. Without the header, all callers share the session's current tab.

## Recommendations

- Only log in to the sites the agent needs in a session. Never your bank or your mailbox: whoever drives the
  browser acts on your behalf on every logged-in site.
- Prefer `allowlist` mode.
- Some sites detect automation: the human then finishes in the web UI.

## License

MIT
