#!/bin/bash
# Start AgentKMS dev server and seed secrets, then drop to interactive shell

agentkms-dev serve --rate-limit 0 &>/dev/null &
sleep 1

# Seed demo secrets (best-effort, silent)
agentkms-dev secrets set generic/db/prod host=db.prod.internal port=5432 password=s3cret-pg-pass user=app_service &>/dev/null
agentkms-dev secrets set generic/app/config jwt_secret=hmac-demo-key-2026 session_timeout=3600 &>/dev/null
agentkms-dev secrets set generic/github token=ghp_demo1234567890abcdef &>/dev/null
agentkms-dev secrets set llm/anthropic api_key=sk-demo-anthropic-key-for-testing &>/dev/null
agentkms-dev secrets set llm/openai api_key=sk-demo-openai-key-for-testing &>/dev/null

exec bash "$@"
