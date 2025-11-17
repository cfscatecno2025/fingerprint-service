package fingerprint.service;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class HttpJson {
  public static void commonHeaders(HttpExchange ex) {
    ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
    ex.getResponseHeaders().add("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    ex.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
    ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
  }

  public static void ok(HttpExchange ex, String json) throws IOException {
    commonHeaders(ex);
    byte[] b = json.getBytes(StandardCharsets.UTF_8);
    ex.sendResponseHeaders(200, b.length);
    ex.getResponseBody().write(b);
    ex.close();
  }

  public static void bad(HttpExchange ex, int code, String msg) throws IOException {
    commonHeaders(ex);
    String safe = (msg == null || msg.isBlank()) ? "Unknown error" : msg;
    String json = "{\"ok\":false,\"error\":\"" + safe.replace("\"","\\\"") + "\"}";
    byte[] b = json.getBytes(StandardCharsets.UTF_8);
    ex.sendResponseHeaders(code, b.length);
    ex.getResponseBody().write(b);
    ex.close();
  }

  public static String readBody(HttpExchange ex) throws IOException {
    return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
  }
}
