FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY guarded_browser_mcp ./guarded_browser_mcp
# Playwright without a bundled browser: it connects over CDP to each session's Chromium
RUN pip install --no-cache-dir .
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('MCP_PORT', '8765'), timeout=8)"]
CMD ["guarded-browser-mcp"]
