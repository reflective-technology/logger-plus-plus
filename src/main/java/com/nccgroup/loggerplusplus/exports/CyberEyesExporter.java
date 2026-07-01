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

    protected volatile LogTableFilter logFilter;

    protected CyberEyesExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
    }

    // --- Package-private static methods: testable without Burp ---

    static String formatSyslogTimestamp(Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        String month = new SimpleDateFormat("MMM", Locale.ENGLISH).format(date);
        int day = cal.get(Calendar.DAY_OF_MONTH);
        String time = new SimpleDateFormat("HH:mm:ss", Locale.ENGLISH).format(date);
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
        fields.put("src",                    str(entry.getValueByKey(LogEntryField.CLIENT_IP)));
        fields.put("dest",                   str(entry.getValueByKey(LogEntryField.HOSTNAME)));
        fields.put("dest_port",              entry.getValueByKey(LogEntryField.PORT));
        fields.put("http_method",            str(entry.getValueByKey(LogEntryField.METHOD)));
        fields.put("version",                str(entry.getValueByKey(LogEntryField.REQUEST_HTTP_VERSION)));
        fields.put("uri_path",               str(entry.getValueByKey(LogEntryField.PATH)));
        fields.put("uri_query",              str(entry.getValueByKey(LogEntryField.QUERY)));
        fields.put("file_extension",         str(entry.getValueByKey(LogEntryField.EXTENSION)));
        fields.put("url_domain",             str(entry.getValueByKey(LogEntryField.HOSTNAME)));
        fields.put("request_connection",     getRequestHeader(entry, "Connection"));
        fields.put("http_user_agent",        getRequestHeader(entry, "User-Agent"));
        fields.put("http_accept",            getRequestHeader(entry, "Accept"));
        fields.put("http_referrer",          str(entry.getValueByKey(LogEntryField.REFERRER)));
        fields.put("x_forwarded_for",        getRequestHeader(entry, "X-Forwarded-For"));
        fields.put("request_content_type",   str(entry.getValueByKey(LogEntryField.REQUEST_CONTENT_TYPE)));
        fields.put("request_content_length", getRequestHeader(entry, "Content-Length"));
        byte[] reqBytes = entry.getRequestBytes();
        fields.put("bytes_in",               reqBytes != null ? reqBytes.length : 0);
        fields.put("status",                 entry.getValueByKey(LogEntryField.STATUS));
        fields.put("response_content_type",  str(entry.getValueByKey(LogEntryField.RESPONSE_CONTENT_TYPE)));
        fields.put("response_content_length",getResponseHeader(entry, "Content-Length"));
        fields.put("authorization",          getRequestHeader(entry, "Authorization"));
        fields.put("host",                   str(entry.getValueByKey(LogEntryField.HOSTNAME)));
        fields.put("etag",                   getResponseHeader(entry, "ETag"));
        fields.put("last_modified",          getResponseHeader(entry, "Last-Modified"));
        fields.put("server",                 getResponseHeader(entry, "Server"));
        fields.put("http_accept_language",   getRequestHeader(entry, "Accept-Language"));
        fields.put("location",               getResponseHeader(entry, "Location"));
        fields.put("set_cookie",             getResponseHeader(entry, "Set-Cookie"));
        fields.put("cookie",                 str(entry.getValueByKey(LogEntryField.SENTCOOKIES)));
        fields.put("x_forwarded_host",       getRequestHeader(entry, "X-Forwarded-Host"));
        fields.put("x_powered_by",           getResponseHeader(entry, "X-Powered-By"));
        byte[] respBytes = entry.getResponseBytes();
        fields.put("bytes_out",              respBytes != null ? respBytes.length : 0);
        fields.put("duration",               entry.getValueByKey(LogEntryField.RTT));
        fields.put("body_bytes_out",         entry.getValueByKey(LogEntryField.RESPONSE_BODY_LENGTH));
        fields.put("body_bytes_in",          entry.getValueByKey(LogEntryField.REQUEST_BODY_LENGTH));
        fields.put("request_header",         str(entry.getValueByKey(LogEntryField.REQUEST_HEADERS)));
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
