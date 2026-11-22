# 🛡️ PromptWall (or VeilProxy)
**Zero-Trust AI Security & Data Loss Prevention (DLP) Reverse Proxy for LLM Applications**

PromptWall is a drop-in middleware reverse proxy that sits between client applications and Large Language Model (LLM) APIs (OpenAI, Anthropic, local models). It inspects incoming user prompts in real time to block prompt injections and jailbreaks, while scrubbing outgoing AI responses to prevent accidental leaks of Personally Identifiable Information (PII) and API secrets.



---

## 🚨 The Problem
Modern AI-powered applications face critical security risks outlined in the **OWASP Top 10 for LLMs**:
1. **Prompt Injection & Jailbreaks:** Malicious users manipulate system prompts to bypass guardrails, extract proprietary instructions, or trigger unauthorized tool calls.
2. **Sensitive Data Exposure (DLP):** LLMs integrated with RAG (Retrieval-Augmented Generation) or internal databases frequently leak customer PII (emails, phone numbers, SINs/SSNs, credit cards) or hardcoded API keys in their responses.
3. **Denial of Wallet (DoW):** Unfiltered token flooding and automated abuse can drain startup API credits overnight.

Enterprise solutions are priced out of reach for early-stage startups and small businesses. **PromptWall** solves this with a lightweight, self-hostable, and low-latency security layer.

---

## ✨ Key Features
* **🔌 1-Line Drop-In Integration:** Compatible with standard OpenAI SDKs—simply swap the `base_url` to route traffic through PromptWall.
* **🛡️ Inbound Jailbreak & Injection Shield:** Uses heuristic pattern matching, encoding normalization (Base64/hex decoding), and lightweight ML classifiers to block adversarial prompts before they reach the LLM.
* **🧹 Outbound PII & Secret Redaction:** Scans streaming and non-streaming LLM responses using Regex and Named Entity Recognition (NER) to automatically mask sensitive data (`[REDACTED_EMAIL]`, `[REDACTED_API_KEY]`).
* **⚡ Rate Limiting & Token Quotas:** Redis-backed sliding-window rate limiting per API key or client IP to prevent Denial of Wallet attacks.
* **📊 Audit Logging & Security Dashboard:** Real-time visibility into blocked attacks, latency overhead, and compliance audit trails.

---

## 🏗️ System Architecture

```text
[Client App] 
     │  (1) POST /v1/chat/completions
     ▼
┌─────────────────────────────────────────────────────────┐
│                   PromptWall Proxy                      │
│  1. Auth & Redis Rate Limiter                           │
│  2. Input Sanitizer & Prompt Injection Classifier       │
└────┬───────────────────────────────────────────────┬────┘
     │ (Blocked: HTTP 403)                           │ (Clean: Forward Request)
     ▼                                               ▼
[Audit Logs]                                  [Upstream LLM API]
                                              (OpenAI / Anthropic)
                                                     │
     ┌───────────────────────────────────────────────┘
     │  (2) Raw LLM Response
     ▼
┌─────────────────────────────────────────────────────────┐
│              Outbound DLP & PII Scrubber                │
│  • Microsoft Presidio (NER) + Regex Secret Detection    │
└────┬────────────────────────────────────────────────────┘
     │  (3) Sanitized Safe Response
     ▼
[Client App]
