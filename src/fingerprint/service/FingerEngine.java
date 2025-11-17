package fingerprint.service;

import com.zkteco.biometric.FingerprintSensorEx;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;

public class FingerEngine {

    private long devHandle = 0;
    long dbHandle  = 0;
    private final AtomicBoolean ready = new AtomicBoolean(false);

    private int imgW = 0;
    private int imgH = 0;

    // ==== Ajustes de captura / matching ====
    /** Tiempo total de espera para capturar una huella (ms). */
    private static final int ACQ_TIMEOUT_MS  = 8000;  // 8 s
    /** Intervalo entre reintentos de captura (ms). */
    private static final int ACQ_POLL_MS     = 60;    // ~60 ms
    /** Umbral de coincidencia (ajústalo 40–80 según calidad). */
    private static final int MATCH_THRESHOLD = 60;

    /* ===== Helpers demo → int/byte[] ===== */
    private static int byteArrayToInt(byte[] bytes) {
        int number = bytes[0] & 0xFF;
        number |= ((bytes[1] << 8) & 0xFF00);
        number |= ((bytes[2] << 16) & 0xFF0000);
        number |= ((bytes[3] << 24) & 0xFF000000);
        return number;
    }

    private void ensure() {
        if (!ready.get()) throw new IllegalStateException("Lector no abierto");
    }

    /** Bucle de captura con espera: reintenta hasta timeout; retorna 0 si capturó. */
    private int acquireWithWait(byte[] imgBuf, byte[] tplBuf, int[] tplLen, int timeoutMs) {
        long end = System.currentTimeMillis() + Math.max(1000, timeoutMs);
        int ret;
        do {
            ret = FingerprintSensorEx.AcquireFingerprint(devHandle, imgBuf, tplBuf, tplLen);
            if (ret == 0) return 0; // capturado OK
            // -8 suele indicar "no hay dedo / timed out parcial" ⇒ reintentar
            try { Thread.sleep(ACQ_POLL_MS); } catch (InterruptedException ignored) {}
        } while (System.currentTimeMillis() < end);
        return ret; // no se logró capturar a tiempo
    }

    /* ==================== Ciclo de vida ==================== */

    public synchronized void open() {
        if (ready.get()) return;

        int ret = FingerprintSensorEx.Init();
        if (ret != 0) throw new RuntimeException("Init falló: ret=" + ret);

        int cnt = FingerprintSensorEx.GetDeviceCount();
        if (cnt <= 0) {
            FingerprintSensorEx.Terminate();
            throw new RuntimeException("No hay dispositivos conectados");
        }

        devHandle = FingerprintSensorEx.OpenDevice(0);
        if (devHandle == 0) {
            FingerprintSensorEx.Terminate();
            throw new RuntimeException("OpenDevice falló");
        }

        dbHandle = FingerprintSensorEx.DBInit();
        if (dbHandle == 0) {
            FingerprintSensorEx.CloseDevice(devHandle);
            FingerprintSensorEx.Terminate();
            throw new RuntimeException("DBInit falló");
        }

        // (Opcional) Intentar fijar tipo de plantilla (v10). Si no existe el parámetro, se ignora.
        try {
            byte[] val = new byte[]{ 10, 0, 0, 0 }; // tipo 10 (v10)
            FingerprintSensorEx.SetParameters(devHandle, 2007, val, 4);
            FingerprintSensorEx.SetParameters(devHandle, 10101, val, 4);
            System.out.println("[open] NTemplateType intentado = 10 (v10)");
        } catch (Throwable __) {
            System.err.println("[open] No se pudo forzar NTemplateType (se continúa con default)");
        }

        // Leer ancho/alto de imagen
        byte[] paramValue = new byte[4];
        int[] size = new int[]{4};

        FingerprintSensorEx.GetParameters(devHandle, 1, paramValue, size);
        imgW = byteArrayToInt(paramValue);

        Arrays.fill(paramValue, (byte) 0);
        FingerprintSensorEx.GetParameters(devHandle, 2, paramValue, size);
        imgH = byteArrayToInt(paramValue);

        ready.set(true);
        System.out.printf("[open] img=%dx%d%n", imgW, imgH);
    }

    public synchronized void close() {
        if (!ready.get()) return;
        try {
            if (dbHandle != 0) FingerprintSensorEx.DBFree(dbHandle);
            if (devHandle != 0) FingerprintSensorEx.CloseDevice(devHandle);
            FingerprintSensorEx.Terminate();
        } finally {
            dbHandle = 0;
            devHandle = 0;
            ready.set(false);
        }
    }

    public boolean isReady() { return ready.get(); }
    public int getImgW() { ensure(); return imgW; }
    public int getImgH() { ensure(); return imgH; }

    /* =================== Capturas / Plantillas =================== */

    /** Adquiere una imagen + plantilla una sola vez (como en AcquireFingerprint del demo). */
    public synchronized EnrollSample captureOne() {
        ensure();
        byte[] imgBuf = new byte[imgW * imgH];
        byte[] tplBuf = new byte[2048];
        int[] tplLen = new int[]{tplBuf.length};

        int ret = acquireWithWait(imgBuf, tplBuf, tplLen, 10000);
        if (ret != 0) throw new RuntimeException("AcquireFingerprint falló (ret=" + ret + ")");

        String tplB64 = Base64.getEncoder().encodeToString(Arrays.copyOf(tplBuf, tplLen[0]));
        String imgB64 = Base64.getEncoder().encodeToString(imgBuf);
        return new EnrollSample(tplB64, imgB64, tplLen[0]);
    }

    /** Captura 3 veces y fusiona con DBMerge; devuelve la plantilla REGISTRADA (Base64). */
    public synchronized String enroll() {
        ensure();

        byte[] imgBuf = new byte[imgW * imgH];

        // 3 capturas como en el demo (regtemparray[3][2048])
        byte[][] regs = new byte[3][2048];
        int idx = 0;

        while (idx < 3) {
            byte[] tpl = new byte[2048];
            int[] tplLen = new int[]{tpl.length};
            int ret = acquireWithWait(imgBuf, tpl, tplLen, 10000); // espera hasta 10 s por toma
            if (ret != 0) {
                System.out.println("[enroll] AcquireFingerprint ret=" + ret);
                continue; // reintenta esta vuelta
            }

            // Validar mismo dedo: si hay una captura previa, usar DBMatch
            if (idx > 0) {
                int score = FingerprintSensorEx.DBMatch(dbHandle, regs[idx - 1], tpl);
                if (score <= 0) {
                    // dedo distinto o mala toma; repetir sin avanzar índice
                    continue;
                }
            }
            System.arraycopy(tpl, 0, regs[idx], 0, tplLen[0]);
            idx++;
            try { Thread.sleep(300); } catch (InterruptedException ignored) {}
        }

        // Fusionar
        byte[] reg = new byte[2048];
        int[] regLen = new int[]{reg.length};
        int m = FingerprintSensorEx.DBMerge(dbHandle, regs[0], regs[1], regs[2], reg, regLen);
        if (m != 0) throw new RuntimeException("DBMerge falló (ret=" + m + ")");

        return Base64.getEncoder().encodeToString(Arrays.copyOf(reg, regLen[0]));
    }

    /** Verifica la huella en vivo contra una plantilla base64 almacenada. */
    public synchronized MatchResult verify(String storedBase64) {
        ensure();
        if (storedBase64 == null || storedBase64.isEmpty())
            return new MatchResult(false, 0);

        byte[] imgBuf = new byte[imgW * imgH];
        byte[] liveTpl = new byte[2048];
        int[] liveLen = new int[]{liveTpl.length};

        int ret = acquireWithWait(imgBuf, liveTpl, liveLen, ACQ_TIMEOUT_MS);
        if (ret != 0) {
            System.out.println("[verify] AcquireFingerprint ret=" + ret);
            return new MatchResult(false, 0); // no se capturó a tiempo
        }

        byte[] storedTpl = Base64.getDecoder().decode(storedBase64);
        int score = FingerprintSensorEx.DBMatch(dbHandle, storedTpl, liveTpl);
        boolean ok = (score >= MATCH_THRESHOLD);
        return new MatchResult(ok, score);
    }

    /** Identifica contra un set de plantillas (id + b64). Devuelve id si hay match. */
    public synchronized MatchResult identify(TemplateEntry[] entries) {
        ensure();
        if (entries == null || entries.length == 0) return new MatchResult(false, 0, null);

        // limpiar DB y cargar entradas con su ID (como hace el demo)
        FingerprintSensorEx.DBClear(dbHandle);
        for (TemplateEntry e : entries) {
            if (e == null || e.templateBase64 == null) continue;
            byte[] tpl = Base64.getDecoder().decode(e.templateBase64);
            int retAdd = FingerprintSensorEx.DBAdd(dbHandle, e.idEmpleado, tpl);
            if (retAdd != 0) {
                System.out.println("[identify] DBAdd id=" + e.idEmpleado + " ret=" + retAdd);
            }
        }

        // capturar vivo
        byte[] imgBuf = new byte[imgW * imgH];
        byte[] liveTpl = new byte[2048];
        int[] liveLen = new int[]{liveTpl.length};
        int ret = acquireWithWait(imgBuf, liveTpl, liveLen, ACQ_TIMEOUT_MS);
        if (ret != 0) {
            System.out.println("[identify] AcquireFingerprint ret=" + ret);
            return new MatchResult(false, 0, null);
        }

        int[] outId = new int[1];
        int[] outScore = new int[1];
        ret = FingerprintSensorEx.DBIdentify(dbHandle, liveTpl, outId, outScore);
        if (ret == 0 && outScore[0] >= MATCH_THRESHOLD) {
            return new MatchResult(true, outScore[0], outId[0]);
        } else {
            return new MatchResult(false, (ret==0?outScore[0]:0), null);
        }
    }

    /* ================= DTOs simples ================= */

    public static class EnrollSample {
        public final String templateBase64;
        public final String imageBase64;
        public final int templateBytes;

        public EnrollSample(String tplB64, String imgB64, int len) {
            this.templateBase64 = tplB64;
            this.imageBase64 = imgB64;
            this.templateBytes = len;
        }
    }

    public static class TemplateEntry {
        public final int idEmpleado;
        public final String templateBase64;
        public TemplateEntry(int idEmpleado, String templateBase64) {
            this.idEmpleado = idEmpleado;
            this.templateBase64 = templateBase64;
        }
    }

    public static class MatchResult {
        public final boolean ok;
        public final int score;
        public final Integer id; // sólo para identify
        public MatchResult(boolean ok, int score) { this(ok, score, null); }
        public MatchResult(boolean ok, int score, Integer id) {
            this.ok = ok; this.score = score; this.id = id;
        }
    }
}
