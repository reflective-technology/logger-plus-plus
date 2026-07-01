# CyberEyes Syslog Exporter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `CyberEyesSyslogExporter` to Logger++ that streams completed HTTP log entries to CyberEyes as RFC 3164 BSD syslog messages in the `suricata pcap` field format, over TCP or UDP.

**Architecture:** An abstract `CyberEyesExporter` base class owns all pcap field mapping and RFC 3164 message formatting as package-private static methods (testable without Burp). `CyberEyesSyslogExporter` extends it and handles TCP/UDP socket transport with per-protocol status reporting. The UI follows the existing `ElasticExporter` pattern: a control panel with a live status area and a separate config dialog.

**Tech Stack:** Java 17, Burp Montoya API, Burp Extender Utilities (`PanelBuilder`, `ComponentGroup`, `Preferences`), Lombok, Log4j2, JUnit 5.10, Mockito 5.11.

## Global Constraints

- Java 17 (`sourceCompatibility`/`targetCompatibility` in `build.gradle`)
- Package: `com.nccgroup.loggerplusplus.exports` for all new production classes
- Test package: `com.nccgroup.loggerplusplus.exports` in `src/test/java/`
- Syslog PRI fixed at `<13>` (facility=1/user, severity=5/notice)
- App tag fixed as `pcap` (mimics `suricata pcap` log source)
- Syslog timestamp format: RFC 3164 `MMM DD HH:mm:ss` with space-padded day, English locale
- TCP: `\n`-delimited messages (RFC 6587 non-transparent framing), persistent socket, reconnect-once-then-drop, shutdown after 5 consecutive drops
- UDP: `DatagramSocket`, fire-and-forget, `sentCount` only — no dropped counter (delivery is undetectable)
- Panel status is protocol-adaptive: TCP shows `Sent` + `Dropped`, UDP shows `Sent (best-effort)` only
- Preference keys defined in `Globals.java`, registered in `LoggerPreferenceFactory.registerSettings()`
- UI follows `ElasticExporterConfigDialog` / `ElasticExporterControlPanel` pattern using `PanelBuilder` + `ComponentGroup`
- Constructor guards Swing creation with `GraphicsEnvironment.isHeadless()` so unit tests can instantiate the exporter

---

### Task 1: Build config, preference keys, and preference registration

**Files:**
- Modify: `build.gradle`
- Modify: `src/main/java/com/nccgroup/loggerplusplus/util/Globals.java`
- Modify: `src/main/java/com/nccgroup/loggerplusplus/preferences/LoggerPreferenceFactory.java`

**Interfaces:**
- Produces: `Globals.PREF_CYBEREYES_*` string constants and `Globals.CyberEyesProtocol` enum — consumed by every subsequent task

- [ ] **Step 1: Add JUnit 5 and Mockito to build.gradle**

Add to the `dependencies` block (after existing `testRuntimeOnly`):

```groovy
testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
testImplementation 'org.mockito:mockito-core:5.11.0'
testImplementation 'org.mockito:mockito-junit-jupiter:5.11.0'
testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
```

Add after the `dependencies` block:

```groovy
test {
    useJUnitPlatform()
}
```

- [ ] **Step 2: Add preference key constants and CyberEyesProtocol enum to Globals.java**

In `src/main/java/com/nccgroup/loggerplusplus/util/Globals.java`, add after the `PREF_PREVIOUS_ELASTIC_FIELDS` line (line 76):

```java
public static final String PREF_CYBEREYES_ADDRESS = "cybereyesAddress";
public static final String PREF_CYBEREYES_PORT = "cybereyesPort";
public static final String PREF_CYBEREYES_PROTOCOL = "cybereyesProtocol";
public static final String PREF_CYBEREYES_SYSLOG_HOSTNAME = "cybereyesSyslogHostname";
public static final String PREF_CYBEREYES_FILTER = "cybereyesFilter";
public static final String PREF_CYBEREYES_FILTER_PROJECT_PREVIOUS = "cybereyesFilterProjectPrevious";
public static final String PREF_CYBEREYES_AUTOSTART_GLOBAL = "cybereyesAutostartGlobal";
public static final String PREF_CYBEREYES_AUTOSTART_PROJECT = "cybereyesAutostartProject";

public enum CyberEyesProtocol { TCP, UDP }
```

- [ ] **Step 3: Register CyberEyes preferences in LoggerPreferenceFactory**

In `src/main/java/com/nccgroup/loggerplusplus/preferences/LoggerPreferenceFactory.java`, add after the `PREF_ELASTIC_AUTOSTART_PROJECT` registration (line 118):

```java
// CyberEyes syslog exporter
prefs.registerSetting(PREF_CYBEREYES_ADDRESS, String.class, "127.0.0.1");
prefs.registerSetting(PREF_CYBEREYES_PORT, Integer.class, 514);
prefs.registerSetting(PREF_CYBEREYES_PROTOCOL, Globals.CyberEyesProtocol.class, Globals.CyberEyesProtocol.TCP);
prefs.registerSetting(PREF_CYBEREYES_SYSLOG_HOSTNAME, String.class, defaultSyslogHostname());
prefs.registerSetting(PREF_CYBEREYES_FILTER, String.class, "", Preferences.Visibility.GLOBAL);
prefs.registerSetting(PREF_CYBEREYES_FILTER_PROJECT_PREVIOUS, String.class, null, Preferences.Visibility.PROJECT);
prefs.registerSetting(PREF_CYBEREYES_AUTOSTART_GLOBAL, Boolean.class, false);
prefs.registerSetting(PREF_CYBEREYES_AUTOSTART_PROJECT, Boolean.class, false, Preferences.Visibility.PROJECT);
```

Add this private helper at the bottom of `LoggerPreferenceFactory`:

```java
private String defaultSyslogHostname() {
    try {
        return java.net.InetAddress.getLocalHost().getHostName();
    } catch (java.net.UnknownHostException e) {
        return "burp";
    }
}
```

- [ ] **Step 4: Verify compilation**

```bash
./gradlew compileJava
```

Expected: `BUILD SUCCESSFUL`

- [ ] **Step 5: Commit**

```bash
git add build.gradle \
    src/main/java/com/nccgroup/loggerplusplus/util/Globals.java \
    src/main/java/com/nccgroup/loggerplusplus/preferences/LoggerPreferenceFactory.java
git commit -m "feat(cybereyes): add preference keys, protocol enum, and JUnit 5 test dependency"
```

---

### Task 2: CyberEyesExporter — pcap field mapping and RFC 3164 formatting

**Files:**
- Create: `src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesExporter.java`
- Create: `src/test/java/com/nccgroup/loggerplusplus/exports/CyberEyesExporterTest.java`

**Interfaces:**
- Consumes: `Globals.CyberEyesProtocol`, `Globals.PREF_CYBEREYES_FILTER` from Task 1; `AutomaticLogExporter`, `ExportController`, `Preferences`, `LogEntry`, `LogEntryField`, `LogTableFilter` from existing codebase
- Produces:
  - `abstract class CyberEyesExporter extends AutomaticLogExporter`
  - `static String formatSyslogTimestamp(Date date)` — package-private; e.g. `"Jul  1 10:22:11"`
  - `static String formatField(String key, Object value)` — package-private; `key="value"` or `key=42`
  - `static String buildBodyFromMap(LinkedHashMap<String, Object> fields)` — package-private; space-separated pairs
  - `protected String buildSyslogHeader(String hostname, Date date)` — e.g. `"<13>Jul  1 10:22:11 host pcap: "`
  - `protected String buildSyslogMessage(String syslogHostname, LogEntry entry)` — full RFC 3164 line
  - `protected LinkedHashMap<String, Object> buildPcapFields(LogEntry entry)` — ordered field map
  - `protected void setFilter(String filterString)`
  - `protected boolean passesFilter(LogEntry entry)`
  - `protected String getRequestHeader(LogEntry entry, String name)` — case-insensitive
  - `protected String getResponseHeader(LogEntry entry, String name)` — case-insensitive

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/com/nccgroup/loggerplusplus/exports/CyberEyesExporterTest.java`:

```java
package com.nccgroup.loggerplusplus.exports;

import com.nccgroup.loggerplusplus.logentry.LogEntry;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class CyberEyesExporterTest {

    // Concrete subclass just for testing — all abstract methods are no-ops
    private static final CyberEyesExporter EXPORTER = new CyberEyesExporter(null, null) {
        @Override void setup() {}
        @Override void shutdown() {}
        @Override public void exportNewEntry(LogEntry e) {}
        @Override public void exportUpdatedEntry(LogEntry e) {}
    };

    // ---- formatSyslogTimestamp ----

    @Test
    void formatSyslogTimestamp_singleDigitDay_twoSpacesPadded() {
        Calendar cal = Calendar.getInstance();
        cal.set(2026, Calendar.JULY, 1, 10, 22, 11);
        String result = CyberEyesExporter.formatSyslogTimestamp(cal.getTime());
        // "Jul  1 HH:mm:ss" — two spaces before single-digit day
        assertTrue(result.startsWith("Jul  1 "), "Expected space-padded day, got: " + result);
    }

    @Test
    void formatSyslogTimestamp_doubleDigitDay_oneSpace() {
        Calendar cal = Calendar.getInstance();
        cal.set(2026, Calendar.JUNE, 30, 9, 37, 54);
        String result = CyberEyesExporter.formatSyslogTimestamp(cal.getTime());
        assertTrue(result.startsWith("Jun 30 "), "Expected no extra space for two-digit day, got: " + result);
    }

    @Test
    void formatSyslogTimestamp_monthIsEnglish() {
        Calendar cal = Calendar.getInstance();
        cal.set(2026, Calendar.JANUARY, 5, 0, 0, 0);
        String result = CyberEyesExporter.formatSyslogTimestamp(cal.getTime());
        assertTrue(result.startsWith("Jan"), "Month must be English, got: " + result);
    }

    // ---- formatField ----

    @Test
    void formatField_string_quoted() {
        assertEquals("http_method=\"GET\"", CyberEyesExporter.formatField("http_method", "GET"));
    }

    @Test
    void formatField_null_emptyQuotes() {
        assertEquals("uri_query=\"\"", CyberEyesExporter.formatField("uri_query", null));
    }

    @Test
    void formatField_emptyString_emptyQuotes() {
        assertEquals("x_forwarded_for=\"\"", CyberEyesExporter.formatField("x_forwarded_for", ""));
    }

    @Test
    void formatField_integer_unquoted() {
        assertEquals("status=200", CyberEyesExporter.formatField("status", 200));
    }

    @Test
    void formatField_short_unquoted() {
        assertEquals("dest_port=443", CyberEyesExporter.formatField("dest_port", (short) 443));
    }

    @Test
    void formatField_long_unquoted() {
        assertEquals("bytes_in=1024", CyberEyesExporter.formatField("bytes_in", 1024L));
    }

    // ---- buildBodyFromMap ----

    @Test
    void buildBodyFromMap_orderedFields_spaceSeparated() {
        LinkedHashMap<String, Object> fields = new LinkedHashMap<>();
        fields.put("http_method", "GET");
        fields.put("status", 200);
        fields.put("uri_path", "/index.html");
        assertEquals(
            "http_method=\"GET\" status=200 uri_path=\"/index.html\"",
            CyberEyesExporter.buildBodyFromMap(fields)
        );
    }

    @Test
    void buildBodyFromMap_emptyMap_emptyString() {
        assertEquals("", CyberEyesExporter.buildBodyFromMap(new LinkedHashMap<>()));
    }

    // ---- buildSyslogHeader ----

    @Test
    void buildSyslogHeader_startsWithPri() {
        String header = EXPORTER.buildSyslogHeader("burp-host", new Date());
        assertTrue(header.startsWith("<13>"), "Must start with PRI <13>");
    }

    @Test
    void buildSyslogHeader_containsHostnameAndTag() {
        String header = EXPORTER.buildSyslogHeader("burp-host", new Date());
        assertTrue(header.contains(" burp-host pcap: "), "Must contain hostname and pcap tag");
    }

    @Test
    void buildSyslogHeader_endsWithColonSpace() {
        String header = EXPORTER.buildSyslogHeader("burp-host", new Date());
        assertTrue(header.endsWith(": "), "Must end with ': ' before message body");
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
./gradlew test --tests "com.nccgroup.loggerplusplus.exports.CyberEyesExporterTest"
```

Expected: FAIL — `CyberEyesExporter` does not exist yet.

- [ ] **Step 3: Implement CyberEyesExporter**

Create `src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesExporter.java`:

```java
package com.nccgroup.loggerplusplus.exports;

import burp.api.montoya.http.message.HttpHeader;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import lombok.extern.log4j.Log4j2;

import java.text.SimpleDateFormat;
import java.util.*;

@Log4j2
public abstract class CyberEyesExporter extends AutomaticLogExporter {

    protected LogTableFilter logFilter;

    protected CyberEyesExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
    }

    // --- Package-private static methods: testable without Burp ---

    static String formatSyslogTimestamp(Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        String month = new SimpleDateFormat("MMM", Locale.ENGLISH).format(date);
        int day = cal.get(Calendar.DAY_OF_MONTH);
        String time = new SimpleDateFormat("HH:mm:ss").format(date);
        return String.format("%s %2d %s", month, day, time);
    }

    static String formatField(String key, Object value) {
        if (value instanceof Number) {
            return key + "=" + value;
        }
        return key + "=\"" + (value != null ? value.toString() : "") + "\"";
    }

    static String buildBodyFromMap(LinkedHashMap<String, Object> fields) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Object> entry : fields.entrySet()) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(formatField(entry.getKey(), entry.getValue()));
        }
        return sb.toString();
    }

    // --- Protected instance methods ---

    protected String buildSyslogHeader(String hostname, Date date) {
        return "<13>" + formatSyslogTimestamp(date) + " " + hostname + " pcap: ";
    }

    protected String buildSyslogMessage(String syslogHostname, LogEntry entry) {
        Date requestTime = entry.getRequestDateTime();
        if (requestTime == null) requestTime = new Date();
        return buildSyslogHeader(syslogHostname, requestTime) + buildBodyFromMap(buildPcapFields(entry));
    }

    protected LinkedHashMap<String, Object> buildPcapFields(LogEntry entry) {
        SimpleDateFormat isoFmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        isoFmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date requestTime = entry.getRequestDateTime();

        LinkedHashMap<String, Object> fields = new LinkedHashMap<>();
        fields.put("time", requestTime != null ? isoFmt.format(requestTime) : "");
        fields.put("src",                   str(entry.getValueByKey(LogEntryField.CLIENT_IP)));
        fields.put("dest",                  str(entry.getValueByKey(LogEntryField.HOSTNAME)));
        fields.put("dest_port",             entry.getValueByKey(LogEntryField.PORT));
        fields.put("http_method",           str(entry.getValueByKey(LogEntryField.METHOD)));
        fields.put("version",               str(entry.getValueByKey(LogEntryField.REQUEST_HTTP_VERSION)));
        fields.put("uri_path",              str(entry.getValueByKey(LogEntryField.PATH)));
        fields.put("uri_query",             str(entry.getValueByKey(LogEntryField.QUERY)));
        fields.put("file_extension",        str(entry.getValueByKey(LogEntryField.EXTENSION)));
        fields.put("url_domain",            str(entry.getValueByKey(LogEntryField.HOSTNAME)));
        fields.put("request_connection",    getRequestHeader(entry, "Connection"));
        fields.put("http_user_agent",       getRequestHeader(entry, "User-Agent"));
        fields.put("http_accept",           getRequestHeader(entry, "Accept"));
        fields.put("http_referrer",         str(entry.getValueByKey(LogEntryField.REFERRER)));
        fields.put("x_forwarded_for",       getRequestHeader(entry, "X-Forwarded-For"));
        fields.put("request_content_type",  str(entry.getValueByKey(LogEntryField.REQUEST_CONTENT_TYPE)));
        fields.put("request_content_length",getRequestHeader(entry, "Content-Length"));
        fields.put("bytes_in",              entry.getRequestBytes().length);
        fields.put("status",                entry.getValueByKey(LogEntryField.STATUS));
        fields.put("response_content_type", str(entry.getValueByKey(LogEntryField.RESPONSE_CONTENT_TYPE)));
        fields.put("response_content_length",getResponseHeader(entry, "Content-Length"));
        fields.put("authorization",         getRequestHeader(entry, "Authorization"));
        fields.put("host",                  str(entry.getValueByKey(LogEntryField.HOSTNAME)));
        fields.put("etag",                  getResponseHeader(entry, "ETag"));
        fields.put("last_modified",         getResponseHeader(entry, "Last-Modified"));
        fields.put("server",                getResponseHeader(entry, "Server"));
        fields.put("http_accept_language",  getRequestHeader(entry, "Accept-Language"));
        fields.put("location",              getResponseHeader(entry, "Location"));
        fields.put("set_cookie",            getResponseHeader(entry, "Set-Cookie"));
        fields.put("cookie",                str(entry.getValueByKey(LogEntryField.SENTCOOKIES)));
        fields.put("x_forwarded_host",      getRequestHeader(entry, "X-Forwarded-Host"));
        fields.put("x_powered_by",          getResponseHeader(entry, "X-Powered-By"));
        fields.put("bytes_out",             entry.getResponseBytes().length);
        fields.put("duration",              entry.getValueByKey(LogEntryField.RTT));
        fields.put("body_bytes_out",        entry.getValueByKey(LogEntryField.RESPONSE_BODY_LENGTH));
        fields.put("body_bytes_in",         entry.getValueByKey(LogEntryField.REQUEST_BODY_LENGTH));
        fields.put("request_header",        str(entry.getValueByKey(LogEntryField.REQUEST_HEADERS)));
        return fields;
    }

    protected void setFilter(String filterString) {
        if (filterString == null || filterString.isBlank()) {
            this.logFilter = null;
            return;
        }
        try {
            this.logFilter = new LogTableFilter(filterString);
        } catch (ParseException e) {
            log.error("CyberEyes: invalid filter, proceeding without filter", e);
            this.logFilter = null;
        }
    }

    protected boolean passesFilter(LogEntry entry) {
        return logFilter == null || logFilter.getFilterExpression().matches(entry);
    }

    protected String getRequestHeader(LogEntry entry, String name) {
        List<HttpHeader> headers = entry.getRequestHeaders();
        if (headers == null) return "";
        return headers.stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(HttpHeader::value)
                .findFirst().orElse("");
    }

    protected String getResponseHeader(LogEntry entry, String name) {
        List<HttpHeader> headers = entry.getResponseHeaders();
        if (headers == null) return "";
        return headers.stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(HttpHeader::value)
                .findFirst().orElse("");
    }

    private String str(Object value) {
        return value != null ? value.toString() : "";
    }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
./gradlew test --tests "com.nccgroup.loggerplusplus.exports.CyberEyesExporterTest"
```

Expected: `BUILD SUCCESSFUL` — all 12 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesExporter.java \
    src/test/java/com/nccgroup/loggerplusplus/exports/CyberEyesExporterTest.java
git commit -m "feat(cybereyes): add CyberEyesExporter with pcap field mapping and RFC 3164 formatting"
```

---

### Task 3: CyberEyesSyslogExporter — TCP/UDP transport

**Files:**
- Create: `src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogExporter.java`
- Create: `src/test/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogExporterTest.java`

**Interfaces:**
- Consumes: `CyberEyesExporter` from Task 2; `Globals.PREF_CYBEREYES_*`, `Globals.CyberEyesProtocol` from Task 1; `ExportPanelProvider`, `ExportController`, `Preferences`, `LogEntry`, `Status` from existing codebase
- Produces:
  - `class CyberEyesSyslogExporter extends CyberEyesExporter implements ExportPanelProvider`
  - `void setup() throws Exception` — connects socket, resets counters
  - `void shutdown() throws Exception` — closes socket
  - `synchronized void sendTcp(String message)` — package-private; reconnect-once-then-drop; updates counters
  - `void sendUdp(String message)` — package-private; fire-and-forget
  - `public int getSentCount()`
  - `public int getDroppedCount()` — TCP only; UDP always 0
  - `public ExportController getExportController()`
  - `void notifyControlPanel(int sent, int dropped, String errorMessage)` — no-op until Task 5 wires in the panel

- [ ] **Step 1: Write failing tests**

Create `src/test/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogExporterTest.java`:

```java
package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.util.Globals;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import static com.nccgroup.loggerplusplus.util.Globals.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CyberEyesSyslogExporterTest {

    @Mock Preferences preferences;
    @Mock ExportController exportController;

    private ServerSocket server;
    private int port;
    private CyberEyesSyslogExporter exporter;

    @BeforeEach
    void setUp() throws Exception {
        server = new ServerSocket(0);
        port = server.getLocalPort();

        // Stub only what setup() reads — constructor skips UI in headless mode
        lenient().when(preferences.getSetting(PREF_CYBEREYES_FILTER)).thenReturn("");
        lenient().when(preferences.getSetting(PREF_CYBEREYES_FILTER_PROJECT_PREVIOUS)).thenReturn("");
        lenient().when(preferences.getSetting(PREF_CYBEREYES_PROTOCOL)).thenReturn(Globals.CyberEyesProtocol.TCP);
        lenient().when(preferences.getSetting(PREF_CYBEREYES_ADDRESS)).thenReturn("127.0.0.1");
        lenient().when(preferences.getSetting(PREF_CYBEREYES_PORT)).thenReturn(port);

        exporter = new CyberEyesSyslogExporter(exportController, preferences);
    }

    @AfterEach
    void tearDown() throws Exception {
        try { exporter.shutdown(); } catch (Exception ignored) {}
        try { server.close(); } catch (IOException ignored) {}
    }

    @Test
    void tcpSetup_connectsToServer() throws Exception {
        Future<Socket> clientFuture = Executors.newSingleThreadExecutor().submit(server::accept);
        exporter.setup();
        Socket client = clientFuture.get(2, TimeUnit.SECONDS);
        assertNotNull(client);
        client.close();
    }

    @Test
    void tcpSend_success_incrementsSentOnly() throws Exception {
        Future<String> received = receiveLineAsync(server);
        exporter.setup();

        exporter.sendTcp("<13>Jul  1 10:22:11 host pcap: http_method=\"GET\"");

        String line = received.get(2, TimeUnit.SECONDS);
        assertTrue(line.contains("http_method=\"GET\""));
        assertEquals(1, exporter.getSentCount());
        assertEquals(0, exporter.getDroppedCount());
    }

    @Test
    void tcpSend_connectionDropped_reconnectSucceeds_noDropCount() throws Exception {
        // Server accepts initial connection, drops it, then accepts the reconnect
        AtomicReference<String> received = new AtomicReference<>();
        CountDownLatch dropped = new CountDownLatch(1);

        Thread serverThread = new Thread(() -> {
            try {
                Socket first = server.accept();
                first.close();          // simulate connection drop
                dropped.countDown();
                Socket second = server.accept();  // reconnect
                received.set(new BufferedReader(
                    new InputStreamReader(second.getInputStream(), StandardCharsets.UTF_8)).readLine());
                second.close();
            } catch (IOException ignored) {}
        });
        serverThread.start();

        exporter.setup();
        dropped.await(2, TimeUnit.SECONDS);
        Thread.sleep(50); // let OS propagate the close

        exporter.sendTcp("<13>Jul  1 10:22:11 host pcap: http_method=\"GET\"");

        serverThread.join(3000);
        assertNotNull(received.get(), "Server should have received the message after reconnect");
        assertEquals(1, exporter.getSentCount());
        assertEquals(0, exporter.getDroppedCount());
    }

    @Test
    void tcpSend_reconnectFails_incrementsDroppedCount() throws Exception {
        Future<Socket> firstClient = Executors.newSingleThreadExecutor().submit(server::accept);
        exporter.setup();
        Socket client = firstClient.get(2, TimeUnit.SECONDS);
        client.close();
        server.close(); // no server to reconnect to

        Thread.sleep(50);
        exporter.sendTcp("<13>Jul  1 10:22:11 host pcap: http_method=\"GET\"");

        assertEquals(0, exporter.getSentCount());
        assertEquals(1, exporter.getDroppedCount());
    }

    @Test
    void tcpSend_fiveConsecutiveFailures_callsShutdown() throws Exception {
        Future<Socket> firstClient = Executors.newSingleThreadExecutor().submit(server::accept);
        exporter.setup();
        firstClient.get(2, TimeUnit.SECONDS).close();
        server.close();
        Thread.sleep(50);

        for (int i = 0; i < 5; i++) {
            exporter.sendTcp("message " + i);
        }

        assertEquals(5, exporter.getDroppedCount());
        // After 5th failure, shutdown() is called — socket should be null
        assertFalse(exporter.isTcpConnected());
    }

    // Helper: accept one connection and read one line in background
    private Future<String> receiveLineAsync(ServerSocket ss) {
        return Executors.newSingleThreadExecutor().submit(() -> {
            Socket client = ss.accept();
            String line = new BufferedReader(
                new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8)).readLine();
            client.close();
            return line;
        });
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
./gradlew test --tests "com.nccgroup.loggerplusplus.exports.CyberEyesSyslogExporterTest"
```

Expected: FAIL — `CyberEyesSyslogExporter` does not exist yet.

- [ ] **Step 3: Implement CyberEyesSyslogExporter**

Create `src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogExporter.java`:

```java
package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.Globals;
import lombok.extern.log4j.Log4j2;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import static com.nccgroup.loggerplusplus.util.Globals.*;

@Log4j2
public class CyberEyesSyslogExporter extends CyberEyesExporter implements ExportPanelProvider {

    private Socket tcpSocket;
    private PrintWriter tcpWriter;
    private int consecutiveFailures = 0;
    private DatagramSocket udpSocket;

    // Cached during setup() so sendTcp() doesn't need to read preferences
    private String cachedHost;
    private int cachedPort;

    private final AtomicInteger sentCount = new AtomicInteger(0);
    private final AtomicInteger droppedCount = new AtomicInteger(0);

    private CyberEyesSyslogControlPanel controlPanel;

    protected CyberEyesSyslogExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);

        // Skip UI and autostart in headless environments (e.g. unit tests)
        if (preferences == null || GraphicsEnvironment.isHeadless()) return;

        boolean autostartGlobal = (boolean) preferences.getSetting(PREF_CYBEREYES_AUTOSTART_GLOBAL);
        boolean autostartProject = (boolean) preferences.getSetting(PREF_CYBEREYES_AUTOSTART_PROJECT);
        if (autostartGlobal || autostartProject) {
            try {
                exportController.enableExporter(this);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(LoggerPlusPlus.instance.getLoggerFrame(),
                        "Could not start CyberEyes exporter: " + e.getMessage(),
                        "CyberEyes Exporter", JOptionPane.ERROR_MESSAGE);
                log.error("Could not automatically start CyberEyes exporter:", e);
            }
        }
        controlPanel = new CyberEyesSyslogControlPanel(this);
    }

    @Override
    void setup() throws Exception {
        String filterString = preferences.getSetting(PREF_CYBEREYES_FILTER);
        String prevFilter = preferences.getSetting(PREF_CYBEREYES_FILTER_PROJECT_PREVIOUS);

        if (prevFilter != null && !Objects.equals(prevFilter, filterString)) {
            int res = JOptionPane.showConfirmDialog(LoggerPlusPlus.instance.getLoggerFrame(),
                    "The CyberEyes export filter has changed since last run.\nDo you want to continue?",
                    "CyberEyes Export Filter", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (res == JOptionPane.NO_OPTION) throw new Exception("Export cancelled.");
        }

        setFilter(filterString);
        sentCount.set(0);
        droppedCount.set(0);
        consecutiveFailures = 0;

        cachedHost = preferences.getSetting(PREF_CYBEREYES_ADDRESS);
        cachedPort = (int) preferences.getSetting(PREF_CYBEREYES_PORT);
        Globals.CyberEyesProtocol protocol = preferences.getSetting(PREF_CYBEREYES_PROTOCOL);

        if (protocol == Globals.CyberEyesProtocol.TCP) {
            connectTcp(cachedHost, cachedPort);
        } else {
            udpSocket = new DatagramSocket();
        }
    }

    private void connectTcp(String host, int port) throws IOException {
        tcpSocket = new Socket(host, port);
        tcpWriter = new PrintWriter(
            new OutputStreamWriter(tcpSocket.getOutputStream(), StandardCharsets.UTF_8), true);
    }

    @Override
    public void exportNewEntry(LogEntry logEntry) { sendIfReady(logEntry); }

    @Override
    public void exportUpdatedEntry(LogEntry updatedEntry) { sendIfReady(updatedEntry); }

    private void sendIfReady(LogEntry entry) {
        if (entry.getStatus() != Status.PROCESSED) return;
        if (!passesFilter(entry)) return;
        String syslogHostname = preferences.getSetting(PREF_CYBEREYES_SYSLOG_HOSTNAME);
        String message = buildSyslogMessage(syslogHostname, entry);
        Globals.CyberEyesProtocol protocol = preferences.getSetting(PREF_CYBEREYES_PROTOCOL);
        if (protocol == Globals.CyberEyesProtocol.TCP) {
            sendTcp(message);
        } else {
            sendUdp(message);
        }
    }

    // Package-private for testing
    synchronized void sendTcp(String message) {
        try {
            writeTcp(message);
            consecutiveFailures = 0;
            notifyControlPanel(sentCount.incrementAndGet(), droppedCount.get(), null);
        } catch (IOException sendEx) {
            try {
                closeTcp();
                connectTcp(cachedHost, cachedPort);
                writeTcp(message);
                consecutiveFailures = 0;
                notifyControlPanel(sentCount.incrementAndGet(), droppedCount.get(), null);
            } catch (IOException reconnectEx) {
                consecutiveFailures++;
                int dropped = droppedCount.incrementAndGet();
                log.error("CyberEyes TCP send failed ({}/5): {}", consecutiveFailures, reconnectEx.getMessage());
                notifyControlPanel(sentCount.get(), dropped, reconnectEx.getMessage());
                if (consecutiveFailures >= 5) {
                    SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(
                            JOptionPane.getFrameForComponent(controlPanel),
                            "CyberEyes exporter could not connect after 5 attempts. Shutting down.",
                            "CyberEyes Exporter - Connection Failed", JOptionPane.ERROR_MESSAGE)
                    );
                    try { shutdown(); } catch (Exception ignored) {}
                }
            }
        }
    }

    private void writeTcp(String message) throws IOException {
        if (tcpWriter == null) throw new IOException("Not connected");
        tcpWriter.println(message);
        if (tcpWriter.checkError()) throw new IOException("PrintWriter error after write");
    }

    // Package-private for testing
    void sendUdp(String message) {
        try {
            byte[] data = (message + "\n").getBytes(StandardCharsets.UTF_8);
            InetAddress address = InetAddress.getByName(cachedHost);
            udpSocket.send(new DatagramPacket(data, data.length, address, cachedPort));
            notifyControlPanel(sentCount.incrementAndGet(), -1, null);
        } catch (IOException e) {
            log.error("CyberEyes UDP local socket error: {}", e.getMessage());
        }
    }

    private synchronized void closeTcp() {
        try { if (tcpWriter != null) tcpWriter.close(); } catch (Exception ignored) {}
        try { if (tcpSocket != null) tcpSocket.close(); } catch (Exception ignored) {}
        tcpWriter = null;
        tcpSocket = null;
    }

    @Override
    void shutdown() throws Exception {
        closeTcp();
        if (udpSocket != null && !udpSocket.isClosed()) {
            udpSocket.close();
            udpSocket = null;
        }
    }

    @Override
    public JComponent getExportPanel() { return controlPanel; }

    public ExportController getExportController() { return exportController; }

    public int getSentCount() { return sentCount.get(); }
    public int getDroppedCount() { return droppedCount.get(); }

    // Package-private: tests can override; real panel wired in Task 5
    void notifyControlPanel(int sent, int dropped, String errorMessage) {
        if (controlPanel != null) controlPanel.updateStatus(sent, dropped, errorMessage);
    }

    // Package-private for testing: true if TCP socket is open
    boolean isTcpConnected() {
        return tcpSocket != null && !tcpSocket.isClosed();
    }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
./gradlew test --tests "com.nccgroup.loggerplusplus.exports.CyberEyesSyslogExporterTest"
```

Expected: `BUILD SUCCESSFUL` — all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogExporter.java \
    src/test/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogExporterTest.java
git commit -m "feat(cybereyes): add CyberEyesSyslogExporter with TCP/UDP transport and counter tracking"
```

---

### Task 4: CyberEyesSyslogConfigDialog

**Files:**
- Create: `src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogConfigDialog.java`

**Interfaces:**
- Consumes: `CyberEyesSyslogExporter.getPreferences()` from Task 3; `Globals.PREF_CYBEREYES_*`, `Globals.CyberEyesProtocol` from Task 1; `PanelBuilder`, `ComponentGroup`, `Alignment` from BurpExtenderUtilities; `LogTableFilter`, `ParseException`, `StringUtils` from existing codebase

- [ ] **Step 1: Implement CyberEyesSyslogConfigDialog**

Create `src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogConfigDialog.java`:

```java
package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.*;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.util.Globals;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Objects;

import static com.nccgroup.loggerplusplus.util.Globals.*;

public class CyberEyesSyslogConfigDialog extends JDialog {

    CyberEyesSyslogConfigDialog(Frame owner, CyberEyesSyslogExporter exporter) {
        super(owner, "CyberEyes Exporter Configuration", true);
        this.setLayout(new BorderLayout());

        Preferences preferences = exporter.getPreferences();

        JTextField addressField = PanelBuilder.createPreferenceTextField(preferences, PREF_CYBEREYES_ADDRESS);

        JSpinner portSpinner = PanelBuilder.createPreferenceSpinner(preferences, PREF_CYBEREYES_PORT);
        ((SpinnerNumberModel) portSpinner.getModel()).setMinimum(1);
        ((SpinnerNumberModel) portSpinner.getModel()).setMaximum(65535);
        portSpinner.setEditor(new JSpinner.NumberEditor(portSpinner, "#"));

        JRadioButton tcpButton = new JRadioButton("TCP");
        JRadioButton udpButton = new JRadioButton("UDP");
        ButtonGroup protocolGroup = new ButtonGroup();
        protocolGroup.add(tcpButton);
        protocolGroup.add(udpButton);
        Globals.CyberEyesProtocol current = preferences.getSetting(PREF_CYBEREYES_PROTOCOL);
        (current == Globals.CyberEyesProtocol.TCP ? tcpButton : udpButton).setSelected(true);
        tcpButton.addActionListener(e ->
            preferences.setSetting(PREF_CYBEREYES_PROTOCOL, Globals.CyberEyesProtocol.TCP));
        udpButton.addActionListener(e ->
            preferences.setSetting(PREF_CYBEREYES_PROTOCOL, Globals.CyberEyesProtocol.UDP));
        JPanel protocolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        protocolPanel.add(tcpButton);
        protocolPanel.add(udpButton);

        JTextField syslogHostnameField = PanelBuilder.createPreferenceTextField(
            preferences, PREF_CYBEREYES_SYSLOG_HOSTNAME);

        // Offer to restore previous filter if it changed
        String prevFilter = preferences.getSetting(PREF_CYBEREYES_FILTER_PROJECT_PREVIOUS);
        String curFilter  = preferences.getSetting(PREF_CYBEREYES_FILTER);
        if (prevFilter != null && !Objects.equals(prevFilter, curFilter)) {
            int res = JOptionPane.showConfirmDialog(LoggerPlusPlus.instance.getLoggerFrame(),
                    "The CyberEyes log filter changed since last run.\n" +
                    "Previously: " + prevFilter + "\nCurrent: " + curFilter +
                    "\nRestore previous?",
                    "CyberEyes Log Filter", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (res == JOptionPane.YES_OPTION) {
                preferences.setSetting(PREF_CYBEREYES_FILTER, prevFilter);
            }
        }

        JTextField filterField = PanelBuilder.createPreferenceTextField(preferences, PREF_CYBEREYES_FILTER);
        filterField.setMinimumSize(new Dimension(400, 0));

        JCheckBox autostartGlobal  = PanelBuilder.createPreferenceCheckBox(preferences, PREF_CYBEREYES_AUTOSTART_GLOBAL);
        JCheckBox autostartProject = PanelBuilder.createPreferenceCheckBox(preferences, PREF_CYBEREYES_AUTOSTART_PROJECT);
        autostartProject.setEnabled(!(boolean) preferences.getSetting(PREF_CYBEREYES_AUTOSTART_GLOBAL));
        preferences.addSettingListener((source, settingName, newValue) -> {
            if (Objects.equals(settingName, PREF_CYBEREYES_AUTOSTART_GLOBAL)) {
                autostartProject.setEnabled(!(boolean) newValue);
                if ((boolean) newValue) preferences.setSetting(PREF_CYBEREYES_AUTOSTART_PROJECT, true);
            }
        });

        ComponentGroup connectionGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Connection");
        connectionGroup.addComponentWithLabel("Address: ", addressField);
        connectionGroup.addComponentWithLabel("Port: ", portSpinner);
        connectionGroup.addComponentWithLabel("Protocol: ", protocolPanel);
        connectionGroup.addComponentWithLabel("Syslog Hostname: ", syslogHostnameField);

        ComponentGroup optionsGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Options");
        optionsGroup.add(PanelBuilder.build(new Component[][]{
                new JComponent[]{new JLabel("Log Filter: "), filterField},
                new JComponent[]{new JLabel("Autostart (All Projects): "), autostartGlobal},
                new JComponent[]{new JLabel("Autostart (This Project): "), autostartProject},
        }, new int[][]{{0,1},{0,1},{0,1}}, Alignment.FILL, 1, 1));

        PanelBuilder panelBuilder = new PanelBuilder();
        panelBuilder.setComponentGrid(new JComponent[][]{
                new JComponent[]{connectionGroup},
                new JComponent[]{optionsGroup}
        });
        int[][] weights = new int[][]{{1},{1}};
        panelBuilder.setGridWeightsY(weights).setGridWeightsX(weights)
                    .setAlignment(Alignment.CENTER).setInsetsX(5).setInsetsY(5);

        this.add(panelBuilder.build(), BorderLayout.CENTER);
        this.setMinimumSize(new Dimension(500, 280));
        this.pack();
        this.setResizable(true);
        this.setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);

        this.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                String filter = preferences.getSetting(PREF_CYBEREYES_FILTER);
                if (!StringUtils.isBlank(filter)) {
                    try {
                        new LogTableFilter(filter);
                    } catch (ParseException ex) {
                        JOptionPane.showMessageDialog(CyberEyesSyslogConfigDialog.this,
                                "Invalid log filter: " + ex.getMessage(),
                                "CyberEyes Configuration", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                }
                CyberEyesSyslogConfigDialog.this.dispose();
            }
        });
    }
}
```

- [ ] **Step 2: Verify compilation**

```bash
./gradlew compileJava
```

Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogConfigDialog.java
git commit -m "feat(cybereyes): add CyberEyesSyslogConfigDialog"
```

---

### Task 5: CyberEyesSyslogControlPanel

**Files:**
- Create: `src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogControlPanel.java`

**Interfaces:**
- Consumes: `CyberEyesSyslogExporter.getExportController()`, `.getPreferences()`, `.getSentCount()`, `.getDroppedCount()` from Task 3; `CyberEyesSyslogConfigDialog` from Task 4; `Globals.CyberEyesProtocol`, `Globals.PREF_CYBEREYES_*` from Task 1; `PanelBuilder`, `Alignment` from BurpExtenderUtilities
- Produces:
  - `class CyberEyesSyslogControlPanel extends JPanel`
  - `void updateStatus(int sent, int dropped, String errorMessage)` — called by `CyberEyesSyslogExporter.notifyControlPanel()`; uses `SwingUtilities.invokeLater`; `dropped == -1` signals UDP (hides dropped label)

- [ ] **Step 1: Implement CyberEyesSyslogControlPanel**

Create `src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogControlPanel.java`:

```java
package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.util.Globals;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ExecutionException;

public class CyberEyesSyslogControlPanel extends JPanel {

    private static final String START_TEXT    = "Start CyberEyes Exporter";
    private static final String STOP_TEXT     = "Stop CyberEyes Exporter";
    private static final String STARTING_TEXT = "Starting CyberEyes Exporter...";
    private static final String STOPPING_TEXT = "Stopping CyberEyes Exporter...";

    private final CyberEyesSyslogExporter exporter;
    private final JToggleButton exportButton;
    private final JButton configButton;
    private final JLabel statusDot;
    private final JLabel sentLabel;
    private final JLabel droppedLabel;
    private final JLabel lastSentLabel;
    private final JLabel errorLabel;

    public CyberEyesSyslogControlPanel(CyberEyesSyslogExporter exporter) {
        this.exporter = exporter;
        this.setLayout(new BorderLayout());

        configButton = new JButton(new AbstractAction("Configure CyberEyes Exporter") {
            @Override
            public void actionPerformed(ActionEvent e) {
                new CyberEyesSyslogConfigDialog(LoggerPlusPlus.instance.getLoggerFrame(), exporter)
                        .setVisible(true);
                // Sync project-previous filter after dialog closes
                String newFilter = exporter.getPreferences().getSetting(Globals.PREF_CYBEREYES_FILTER);
                exporter.getPreferences().setSetting(Globals.PREF_CYBEREYES_FILTER_PROJECT_PREVIOUS, newFilter);
            }
        });

        exportButton = new JToggleButton(START_TEXT);
        exportButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean starting = exportButton.isSelected();
                exportButton.setEnabled(false);
                exportButton.setText(starting ? STARTING_TEXT : STOPPING_TEXT);
                new SwingWorker<Boolean, Void>() {
                    Exception exception;
                    @Override
                    protected Boolean doInBackground() {
                        try {
                            if (starting) exporter.getExportController().enableExporter(exporter);
                            else          exporter.getExportController().disableExporter(exporter);
                            return true;
                        } catch (Exception ex) {
                            this.exception = ex;
                            return false;
                        }
                    }
                    @Override
                    protected void done() {
                        try {
                            boolean success = get();
                            boolean running = starting ^ !success;
                            exportButton.setSelected(running);
                            configButton.setEnabled(!running);
                            exportButton.setText(running ? STOP_TEXT : START_TEXT);
                            applyConnectionState(running ? ConnectionState.CONNECTED : ConnectionState.IDLE);
                            if (exception != null) {
                                JOptionPane.showMessageDialog(CyberEyesSyslogControlPanel.this,
                                        "Could not start CyberEyes exporter: " + exception.getMessage(),
                                        "CyberEyes Exporter", JOptionPane.ERROR_MESSAGE);
                            }
                        } catch (InterruptedException | ExecutionException ex) {
                            ex.printStackTrace();
                        }
                        exportButton.setEnabled(true);
                    }
                }.execute();
            }
        });

        statusDot     = new JLabel("● Idle");
        sentLabel     = new JLabel("Sent: 0");
        droppedLabel  = new JLabel("Dropped: 0");
        lastSentLabel = new JLabel("Last sent: —");
        errorLabel    = new JLabel(" ");
        statusDot.setForeground(Color.GRAY);
        errorLabel.setForeground(Color.RED);

        JPanel statsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        statsRow.add(statusDot);
        statsRow.add(sentLabel);
        statsRow.add(droppedLabel);
        statsRow.add(lastSentLabel);

        this.add(PanelBuilder.build(new JComponent[][]{
                new JComponent[]{configButton},
                new JComponent[]{exportButton},
                new JComponent[]{statsRow},
                new JComponent[]{errorLabel},
        }, new int[][]{{1},{1},{1},{1}}, Alignment.FILL, 1.0, 1.0), BorderLayout.CENTER);

        this.setBorder(BorderFactory.createTitledBorder("CyberEyes Exporter"));

        if (isExporterEnabled()) {
            exportButton.setSelected(true);
            exportButton.setText(STOP_TEXT);
            configButton.setEnabled(false);
            applyConnectionState(ConnectionState.CONNECTED);
        }
    }

    /**
     * Called from CyberEyesSyslogExporter after each send attempt.
     * dropped == -1 signals UDP mode (no dropped counter shown).
     */
    public void updateStatus(int sent, int dropped, String errorMessage) {
        SwingUtilities.invokeLater(() -> {
            if (dropped < 0) {
                // UDP: best-effort label, no dropped counter
                sentLabel.setText("Sent (best-effort): " + sent);
                droppedLabel.setVisible(false);
            } else {
                sentLabel.setText("Sent: " + sent);
                droppedLabel.setVisible(true);
                droppedLabel.setText("Dropped: " + dropped);
            }
            lastSentLabel.setText("Last sent: " +
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
            if (errorMessage != null) {
                errorLabel.setText("Error: " + errorMessage);
                applyConnectionState(ConnectionState.ERROR);
            } else {
                errorLabel.setText(" ");
                applyConnectionState(ConnectionState.CONNECTED);
            }
        });
    }

    private void applyConnectionState(ConnectionState state) {
        switch (state) {
            case CONNECTED -> { statusDot.setText("● Connected"); statusDot.setForeground(new Color(0, 150, 0)); }
            case ERROR     -> { statusDot.setText("● Error");     statusDot.setForeground(Color.RED); }
            case IDLE      -> { statusDot.setText("● Idle");      statusDot.setForeground(Color.GRAY); }
        }
    }

    private boolean isExporterEnabled() {
        return exporter.getExportController() != null
            && exporter.getExportController().getEnabledExporters().contains(exporter);
    }

    private enum ConnectionState { CONNECTED, ERROR, IDLE }
}
```

- [ ] **Step 2: Verify compilation**

```bash
./gradlew compileJava
```

Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add src/main/java/com/nccgroup/loggerplusplus/exports/CyberEyesSyslogControlPanel.java
git commit -m "feat(cybereyes): add CyberEyesSyslogControlPanel with protocol-adaptive status display"
```

---

### Task 6: Wire into ExportController and verify full build

**Files:**
- Modify: `src/main/java/com/nccgroup/loggerplusplus/exports/ExportController.java:26-31`

**Interfaces:**
- Consumes: `CyberEyesSyslogExporter` from Task 3

- [ ] **Step 1: Register CyberEyesSyslogExporter in ExportController.initializeExporters()**

In `ExportController.java`, in the `initializeExporters()` method, add after the `ElasticExporter` line:

```java
this.exporters.put(CyberEyesSyslogExporter.class, new CyberEyesSyslogExporter(this, preferences));
```

- [ ] **Step 2: Run all tests**

```bash
./gradlew test
```

Expected: `BUILD SUCCESSFUL` — all tests pass (formatting tests + TCP transport tests).

- [ ] **Step 3: Build the full jar**

```bash
./gradlew jar
```

Expected: `BUILD SUCCESSFUL` — jar created in `releases/`.

- [ ] **Step 4: Manual verification in Burp Suite**

1. Load the jar: Burp → Extensions → Add → select `releases/logger-plus-plus.jar`
2. Open Logger++ tab → navigate to the Exporter panel
3. Confirm "CyberEyes Exporter" section appears with Configure button, Start/Stop toggle, and status row
4. Start a local TCP listener: `nc -lk 127.0.0.1 9514`
5. Click "Configure CyberEyes Exporter" → set Host `127.0.0.1`, Port `9514`, Protocol TCP, leave Syslog Hostname as default
6. Click "Start CyberEyes Exporter" — dot turns green "● Connected", Sent: 0
7. Browse any HTTP site through Burp proxy
8. Verify syslog lines appear in the `nc` output matching the format:
   ```
   <13>Jul  1 10:22:11 your-hostname pcap: time="2026-07-01T10:22:11Z" src="127.0.0.1" dest="10.46.3.58" ...
   ```
9. Confirm "Sent" counter increments in the panel after each request
10. For UDP: change Protocol to UDP, restart, run `nc -lku 127.0.0.1 9514`, verify panel shows "Sent (best-effort)" with no Dropped label

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/nccgroup/loggerplusplus/exports/ExportController.java
git commit -m "feat(cybereyes): wire CyberEyesSyslogExporter into ExportController"
```
