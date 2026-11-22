# PromptWall

PromptWall is a two-service, OpenAI-compatible reverse proxy for LLM applications.
The Java service handles authentication, rate limiting, upstream forwarding, and audit
APIs. The Python service inspects prompts and redacts sensitive response data.

## Architecture

```text
Client
  |
  | POST /v1/chat/completions
  v
Java proxy (:8080)
  |- inbound inspection --> Python service (:8000)
  |- blocked requests --> 403
  |- approved requests --> upstream LLM
  |- outbound redaction --> Python service (:8000)
  v
Sanitized response
```

## Features

- Inbound heuristic jailbreak and prompt-injection detection
- Base64 and hex normalization checks
- Outbound email, phone, SSN, credit-card, and API-secret redaction
- In-memory sliding-window rate limiting
- Optional PromptWall API-key authentication
- OpenAI-compatible `/v1/chat/completions` endpoint
- Audit log and dashboard endpoints
- Java and Python unit tests

## Requirements

- Python 3.11+
- Java 21+
- An OpenAI-compatible upstream API

## Run locally

### 1. Start the Python security service

```powershell
cd security-service
python -m pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

### 2. Start the Java proxy

Open another terminal:

```powershell
cd promptwall-java
copy .env.example .env
.\run.ps1
```

### 3. Test the proxy

```powershell
$body = @{
  model = "gpt-4o-mini"
  messages = @(@{
    role = "user"
    content = "Hello, what can you do?"
  })
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8080/v1/chat/completions" `
  -ContentType "application/json" `
  -Body $body
```

Open `http://127.0.0.1:8080/dashboard` for the audit dashboard.

## Configuration

Java proxy variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Proxy port |
| `SECURITY_SERVICE_URL` | `http://127.0.0.1:8000` | Python service URL |
| `UPSTREAM_URL` | `https://api.openai.com/v1/chat/completions` | LLM endpoint |
| `LLM_API_KEY` | none | Upstream API key |
| `PROMPTWALL_API_KEY` | none | Optional proxy API key |
| `RATE_LIMIT_REQUESTS` | `60` | Requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window length |

Python service variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8000` | Security service port |

Set `LLM_API_KEY` and `UPSTREAM_URL` before calling the proxy.

## Tests

```powershell
cd security-service
python -m unittest discover -s tests -v
```

```powershell
cd promptwall-java
.\test.ps1
```

