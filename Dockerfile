FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY guarded_browser_mcp ./guarded_browser_mcp
# Playwright without a bundled browser: it connects over CDP to each session's Chromium
RUN pip install --no-cache-dir .
EXPOSE 8765
CMD ["guarded-browser-mcp"]
