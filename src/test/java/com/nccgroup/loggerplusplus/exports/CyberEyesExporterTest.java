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

    // ---- formatField: adversarial string values ----

    @Test
    void formatField_stringWithDoubleQuote_escaped() {
        assertEquals("user_agent=\"Mozilla\\\"Gecko\\\"\"",
            CyberEyesExporter.formatField("user_agent", "Mozilla\"Gecko\""));
    }

    @Test
    void formatField_stringWithNewline_escaped() {
        assertEquals("request_header=\"GET / HTTP/1.1\\r\\nHost: example.com\"",
            CyberEyesExporter.formatField("request_header", "GET / HTTP/1.1\r\nHost: example.com"));
    }

    @Test
    void formatField_stringWithBackslash_escaped() {
        assertEquals("path=\"C:\\\\Users\\\\test\"",
            CyberEyesExporter.formatField("path", "C:\\Users\\test"));
    }

    // ---- buildBodyFromMap: adversarial values flow through correctly ----

    @Test
    void buildBodyFromMap_valueWithSpecialChars_properlyEscaped() {
        LinkedHashMap<String, Object> fields = new LinkedHashMap<>();
        fields.put("request_header", "GET / HTTP/1.1\r\nHost: example.com\r\n");
        fields.put("status", 200);
        String result = CyberEyesExporter.buildBodyFromMap(fields);
        assertEquals(
            "request_header=\"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\" status=200",
            result
        );
        // Critical invariant: no literal newlines in the output (would corrupt syslog framing)
        assertFalse(result.contains("\n"), "Output must not contain literal newlines");
        assertFalse(result.contains("\r"), "Output must not contain literal carriage returns");
    }

    // ---- buildSyslogHeader: full structure ----

    @Test
    void buildSyslogHeader_fullStructure() {
        Calendar cal = Calendar.getInstance();
        cal.set(2026, Calendar.JULY, 1, 10, 22, 11);
        String header = EXPORTER.buildSyslogHeader("test-host", cal.getTime());
        // Must start with PRI, contain timestamp pattern, hostname, and tag
        assertTrue(header.startsWith("<13>"), "Must start with PRI <13>");
        assertTrue(header.contains("test-host"), "Must contain hostname");
        assertTrue(header.contains(" pcap: "), "Must contain pcap tag with trailing space");
        assertTrue(header.endsWith(": "), "Must end with ': '");
        // Must not contain newlines
        assertFalse(header.contains("\n"), "Header must not contain newlines");
    }
}
