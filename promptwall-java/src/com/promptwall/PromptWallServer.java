package com.promptwall;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class PromptWallServer {
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final Map<String, Deque<Long>> REQUESTS = new ConcurrentHashMap<>();
    private static final List<Map<String, Object>> AUDIT_LOG = Collections.synchronizedList(new ArrayList<>());

    private final int port;
    private final String securityUrl;
    private final String upstreamUrl;
    private final String llmApiKey;
    private final String promptWallApiKey;
    private final int rateLimitRequests;
    private final long rateLimitWindowMillis;

    public PromptWallServer() {
        port = integerEnvironment("PORT", 8080);
        securityUrl = environment("SECURITY_SERVICE_URL", "http://127.0.0.1:8000");
        upstreamUrl = environment("UPSTREAM_URL", "https://api.openai.com/v1/chat/completions");
        llmApiKey = environment("LLM_API_KEY", "");
        promptWallApiKey = environment("PROMPTWALL_API_KEY", "");
        rateLimitRequests = integerEnvironment("RATE_LIMIT_REQUESTS", 60);
        rateLimitWindowMillis = integerEnvironment("RATE_LIMIT_WINDOW_SECONDS", 60) * 1000L;
    }

    public void start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", exchange -> route(exchange));
        server.setExecutor(null);
        server.start();
    }

    private void route(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if ("GET".equals(exchange.getRequestMethod()) && ("/".equals(path) || "/app".equals(path))) {
            sendDashboard(exchange);
        } else if ("GET".equals(exchange.getRequestMethod()) && "/health".equals(path)) {
            sendJson(exchange, 200, "{\"status\":\"ok\",\"service\":\"promptwall-java\"}");
        } else if ("GET".equals(exchange.getRequestMethod()) && "/dashboard".equals(path)) {
            sendDashboard(exchange);
        } else if ("GET".equals(exchange.getRequestMethod()) && "/v1/audit/logs".equals(path)) {
            sendJson(exchange, 200, auditJson());
        } else if ("POST".equals(exchange.getRequestMethod()) && "/v1/chat/completions".equals(path)) {
            proxyChat(exchange);
        } else {
            sendJson(exchange, 404, "{\"error\":\"Not found\"}");
        }
    }

    private void proxyChat(HttpExchange exchange) throws IOException {
        String clientKey = exchange.getRemoteAddress().getAddress().getHostAddress();
        if (!promptWallApiKey.isBlank()) {
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization == null || !authorization.equals("Bearer " + promptWallApiKey)) {
                audit(clientKey, "authentication_error", "Rejected");
                sendJson(exchange, 401, "{\"error\":{\"message\":\"Invalid PromptWall API key\",\"type\":\"authentication_error\"}}");
                return;
            }
        }
        if (!allowRequest(clientKey)) {
            audit(clientKey, "rate_limit_error", "Rejected");
            sendJson(exchange, 429, "{\"error\":{\"message\":\"Rate limit exceeded\",\"type\":\"rate_limit_error\"}}");
            return;
        }

        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        try {
            HttpResponse<String> inspection = HTTP.send(
                HttpRequest.newBuilder(URI.create(securityUrl + "/inspect"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build(),
                HttpResponse.BodyHandlers.ofString()
            );
            if (inspection.statusCode() >= 400) {
                audit(clientKey, "security_service_error", "Rejected");
                sendJson(exchange, 502, "{\"error\":{\"message\":\"Security service unavailable\",\"type\":\"service_error\"}}");
                return;
            }
            if (inspection.body().contains("\"blocked\":true")) {
                audit(clientKey, "prompt_injection", "Blocked");
                sendJson(exchange, 403, "{\"error\":{\"message\":\"Request blocked by PromptWall\",\"type\":\"content_filter\"}}");
                return;
            }

            HttpRequest.Builder upstream = HttpRequest.newBuilder(URI.create(upstreamUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
            if (!llmApiKey.isBlank()) {
                upstream.header("Authorization", "Bearer " + llmApiKey);
            }
            HttpResponse<String> response = HTTP.send(upstream.build(), HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 400) {
                audit(clientKey, "upstream_error", "Forwarded");
                sendResponse(exchange, response.statusCode(), "application/json", response.body());
                return;
            }

            String redacted = redact(response.body());
            audit(clientKey, "allowed", "Sanitized");
            sendResponse(exchange, response.statusCode(), "application/json", redacted);
        } catch (IOException | InterruptedException exception) {
            Thread.currentThread().interrupt();
            audit(clientKey, "proxy_error", "Rejected");
            sendJson(exchange, 502, "{\"error\":{\"message\":\"PromptWall proxy could not complete the request\",\"type\":\"service_error\"}}");
        }
    }

    private boolean allowRequest(String clientKey) {
        try {
            String payload = "{\"client\":\"" + clientKey.replace("\"", "\\\"")
                + "\",\"limit\":" + rateLimitRequests
                + ",\"window_seconds\":" + (rateLimitWindowMillis / 1000L) + "}";
            HttpResponse<String> response = HTTP.send(
                HttpRequest.newBuilder(URI.create(securityUrl + "/rate-limit/check"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build(),
                HttpResponse.BodyHandlers.ofString()
            );
            if (response.statusCode() < 400) {
                return response.body().contains("\"allowed\":true");
            }
        } catch (IOException | InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
        long now = System.currentTimeMillis();
        Deque<Long> timestamps = REQUESTS.computeIfAbsent(clientKey, ignored -> new ArrayDeque<>());
        synchronized (timestamps) {
            while (!timestamps.isEmpty() && now - timestamps.peekFirst() > rateLimitWindowMillis) {
                timestamps.removeFirst();
            }
            if (timestamps.size() >= rateLimitRequests) {
                return false;
            }
            timestamps.addLast(now);
            return true;
        }
    }

    private String redact(String text) throws IOException, InterruptedException {
        String payload = "{\"text\":" + Json.quote(text) + "}";
        HttpResponse<String> response = HTTP.send(
            HttpRequest.newBuilder(URI.create(securityUrl + "/redact"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() >= 400) {
            return text;
        }
        return Json.stringField(response.body(), "sanitized");
    }

    private void audit(String client, String event, String result) {
        AUDIT_LOG.add(Map.of(
            "timestamp", Instant.now().toString(),
            "client", client,
            "event", event,
            "result", result
        ));
    }

    private String auditJson() {
        StringBuilder json = new StringBuilder("[");
        synchronized (AUDIT_LOG) {
            for (int i = 0; i < AUDIT_LOG.size(); i++) {
                if (i > 0) json.append(",");
                Map<String, Object> item = AUDIT_LOG.get(i);
                json.append("{")
                    .append("\"timestamp\":").append(Json.quote(String.valueOf(item.get("timestamp")))).append(",")
                    .append("\"client\":").append(Json.quote(String.valueOf(item.get("client")))).append(",")
                    .append("\"event\":").append(Json.quote(String.valueOf(item.get("event")))).append(",")
                    .append("\"result\":").append(Json.quote(String.valueOf(item.get("result"))))
                    .append("}");
            }
        }
        return json.append("]").toString();
    }

    private void sendDashboard(HttpExchange exchange) throws IOException {
        String html = """
            <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>PromptWall Demo</title>
            <style>:root{color-scheme:dark}body{font-family:Arial;margin:0;background:#08111f;color:#e2e8f0}.wrap{max-width:1100px;margin:auto;padding:28px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}section{background:#111827;border:1px solid #263449;border-radius:12px;padding:18px}textarea{width:100%;min-height:150px;box-sizing:border-box;background:#0b1220;color:white;border:1px solid #334155;border-radius:8px;padding:12px}button{background:#06b6d4;border:0;border-radius:8px;padding:10px 16px;color:#06202a;font-weight:bold;cursor:pointer}pre{white-space:pre-wrap;background:#0b1220;padding:12px;border-radius:8px;min-height:100px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #334155;padding:8px;text-align:left}th{background:#1e293b}h1{color:#67e8f9}@media(max-width:800px){.grid{grid-template-columns:1fr}}</style></head>
            <body><div class="wrap"><h1>PromptWall Demo</h1><div class="grid"><section><h2>Chat test</h2><textarea id="prompt" placeholder="Enter a prompt..."></textarea><p><button onclick="sendPrompt()">Send through proxy</button></p><pre id="response">Response will appear here</pre></section><section><h2>Audit log</h2><table><thead><tr><th>Time</th><th>Event</th><th>Result</th></tr></thead><tbody id="rows"></tbody></table></section></div></div>
            <script>
            async function sendPrompt(){const prompt=document.getElementById('prompt').value;document.getElementById('response').textContent='Waiting...';try{const r=await fetch('/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:'demo',messages:[{role:'user',content:prompt}]})});const text=await r.text();document.getElementById('response').textContent=r.status+'\\n'+text;loadLogs()}catch(e){document.getElementById('response').textContent=e}}
            async function loadLogs(){const items=await(await fetch('/v1/audit/logs')).json();document.getElementById('rows').innerHTML=items.slice().reverse().map(x=>`<tr><td>${x.timestamp}</td><td>${x.event}</td><td>${x.result}</td></tr>`).join('')||'<tr><td colspan="3">No audit events yet</td></tr>'}loadLogs();
            </script></body></html>
            """;
        sendResponse(exchange, 200, "text/html; charset=utf-8", html);
    }

    private static void sendJson(HttpExchange exchange, int status, String body) throws IOException {
        sendResponse(exchange, status, "application/json", body);
    }

    private static void sendResponse(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }

    private static String environment(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static int integerEnvironment(String name, int fallback) {
        try {
            return Integer.parseInt(environment(name, String.valueOf(fallback)));
        } catch (NumberFormatException exception) {
            return fallback;
        }
    }

    public static void main(String[] args) throws IOException {
        PromptWallServer server = new PromptWallServer();
        server.start();
        System.out.println("PromptWall Java proxy listening on port " + server.port);
    }
}
