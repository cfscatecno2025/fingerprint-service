package fingerprint.service;

//commit fork

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class App {
    private static final Gson GSON = new Gson();

    public static void main(String[] args) throws Exception {
        int port = 8787; // http://127.0.0.1:8787
        FingerEngine engine = new FingerEngine();

        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);

        // Contexto "catch-all" para rutas inexistentes asi no cae en falla
        srv.createContext("/api/", ex -> {
            if (handleCorsPreflight(ex)) return;
            HttpJson.bad(ex, 404, "Not Found");
        });

        srv.createContext("/api/ping", ex -> {
            if (handleCorsPreflight(ex)) return;
            HttpJson.ok(ex, "{\"ok\":true,\"ts\":\"" + Instant.now() + "\"}");
        });

        srv.createContext("/api/device/open", ex -> {
            if (handleCorsPreflight(ex)) return;
            try {
                engine.open();
                HttpJson.ok(ex, "{\"ok\":true}");
            } catch (Exception e) {
                HttpJson.bad(ex, 500, e.getMessage());
            }
        });

        srv.createContext("/api/device/close", ex -> {
            if (handleCorsPreflight(ex)) return;
            try {
                engine.close();
                HttpJson.ok(ex, "{\"ok\":true}");
            } catch (Exception e) {
                HttpJson.bad(ex, 500, e.getMessage());
            }
        });
        // POST /api/enroll -> { ok, template }
        srv.createContext("/api/enroll", ex -> {
            if (handleCorsPreflight(ex)) return;
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { HttpJson.bad(ex, 405, "POST only"); return; }
            try {
                String tpl = engine.enroll();
                Map<String, Object> r = new HashMap<>();
                r.put("ok", true);
                r.put("template", tpl);
                HttpJson.ok(ex, GSON.toJson(r));
            } catch (Exception e) {
                HttpJson.bad(ex, 500, e.getMessage());
            }
        });

        // POST /api/verify  { "template":"base64" }
        srv.createContext("/api/verify", ex -> {
            if (handleCorsPreflight(ex)) return;
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { HttpJson.bad(ex, 405, "POST only"); return; }
            try {
                String body = HttpJson.readBody(ex);
                @SuppressWarnings("unchecked")
                Map<String, Object> in = GSON.fromJson(body, Map.class);
                String stored = (String) in.get("template");

                FingerEngine.MatchResult res = engine.verify(stored);
                HttpJson.ok(ex, GSON.toJson(Map.of(
                        "ok", true,
                        "match", res.ok,
                        "score", res.score
                )));
            } catch (Exception e) {
                HttpJson.bad(ex, 500, e.getMessage());
            }
        });

        // POST /api/identify  { "entries":[{"idEmpleado":1001,"templateBase64":"..."}] }
        srv.createContext("/api/identify", ex -> {
            if (handleCorsPreflight(ex)) return;
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { HttpJson.bad(ex, 405, "POST only"); return; }
            try {
                String body = HttpJson.readBody(ex);
                IdentReq req = GSON.fromJson(body, IdentReq.class);

                FingerEngine.MatchResult res = engine.identify(req.entries);
                HttpJson.ok(ex, GSON.toJson(Map.of(
                        "ok", true,
                        "match", res.ok,
                        "score", res.score,
                        "idEmpleado", res.id
                )));
            } catch (Exception e) {
                HttpJson.bad(ex, 500, e.getMessage());
            }
        });
// GET /api/debug/selftest  -> hace 2 capturas seguidas del mismo dedo y las compara (CHAR vs CHAR)
srv.createContext("/api/debug/selftest", ex -> {
    try {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) { HttpJson.bad(ex, 405, "GET only"); return; }
        // 1) Captura A
        var a = engine.captureOne(); // CHAR A
        // 2) Captura B
        var b = engine.captureOne(); // CHAR B

        byte[] A = java.util.Base64.getDecoder().decode(a.templateBase64);
        byte[] B = java.util.Base64.getDecoder().decode(b.templateBase64);
        int score = com.zkteco.biometric.FingerprintSensorEx.DBMatch(engine.dbHandle, A, B);

        Map<String,Object> r = new HashMap<>();
        r.put("ok", true);
        r.put("charA_bytes", A.length);
        r.put("charB_bytes", B.length);
        r.put("match_score_A_vs_B", score);
        HttpJson.ok(ex, GSON.toJson(r));
    } catch (Exception e) { HttpJson.bad(ex, 500, e.getMessage()); }
});

// GET /api/debug/info -> tamaños y estado
srv.createContext("/api/debug/info", ex -> {
    try {
        Map<String,Object> r = new HashMap<>();
        r.put("ok", true);
        r.put("ready", engine.isReady());
        r.put("imgW", engine.getImgW());
        r.put("imgH", engine.getImgH());
        HttpJson.ok(ex, GSON.toJson(r));
    } catch (Exception e) { HttpJson.bad(ex, 500, e.getMessage()); }
});

        srv.setExecutor(null);
        srv.start();
        System.out.println("FP Service escuchando en http://127.0.0.1:" + port);
    }

    // Manejo uniforme de CORS/OPTIONS
    private static boolean handleCorsPreflight(HttpExchange ex) throws java.io.IOException {
        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            HttpJson.commonHeaders(ex);
            ex.sendResponseHeaders(204, -1);
            ex.close();
            return true;
        }
        return false;
    }

    // Para deserializar el JSON de /identify
    static class IdentReq {
        FingerEngine.TemplateEntry[] entries;
    }
}
