# Warden image: Python for the app, Node + uv so the catalog's npx/uvx MCP servers
# can actually spawn on the host. Without this, only the built-in servers and
# remote-HTTP servers connect.
FROM python:3.12-slim

# Node 20 (for npx-based MCP servers) + build basics
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir uv          # provides uvx for Python MCP servers

COPY . .

# Unique per image build (independent of Render git vars) so the build number
# increments on every deploy. Runs whenever the copied code changes.
RUN date -u +%Y%m%dT%H%M%SZ > /app/BUILD_ID

ENV PORT=8000
# shell form so $PORT (set by Render) expands
CMD gunicorn app:app --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:$PORT
