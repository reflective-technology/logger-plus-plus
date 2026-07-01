# CyberEyes Syslog Exporter Design

**Date:** 2026-07-01
**Status:** Approved

## Overview

Add a new automatic log exporter to Logger++ that streams completed HTTP log entries to CyberEyes via RFC 3164 BSD syslog over TCP or UDP. The exporter mimics the `suricata pcap` log source format that CyberEyes already understands, so no additional CyberEyes-side configuration is required for the default on-premise deployment (Vector listening on port 514).

A second transport (HTTP bulk API) for SaaS CyberEyes and on-prem deployments with the HTTP input enabled is deferred and will be added as `CyberEyesHttpExporter` once the syslog transport is stable.

## Architecture

### New files

```
src/main/java/com/nccgroup/loggerplusplus/exports/
  CyberEyesExporter.java             — abstract base: field mapping + filter logic
  CyberEyesSyslogExporter.java       — TCP/UDP socket + RFC 3164 message formatting
  CyberEyesSyslogControlPanel.java   — start/stop toggle + configure button
  CyberEyesSyslogConfigDialog.java   — host, port, protocol, hostname, filter, autostart
```

### Modified files

- `ExportController.java` — register `CyberEyesSyslogExporter` in `initializeExporters()`
- `Globals.java` — add `PREF_CYBEREYES_*` preference key constants

### Future addition (HTTP bulk)

`CyberEyesHttpExporter.java` + its UI will extend `CyberEyesExporter` and drop in alongside the syslog exporter with no further changes to the base.

## Class Design

### `CyberEyesExporter` (abstract)

Extends `AutomaticLogExporter`. Owns:
- Field mapping from `LogEntry` to the pcap key=value map (see Field Mapping below)
- Optional `LogTableFilter` — only entries matching the filter are forwarded
- Helper `getRequestHeader(LogEntry, String)` and `getResponseHeader(LogEntry, String)` using `equalsIgnoreCase` for case-insensitive header lookup

Subclasses implement `setup()`, `shutdown()`, and `sendEntry(String syslogMessage)`.

### `CyberEyesSyslogExporter`

Extends `CyberEyesExporter`. Responsibilities:
- Maintain a persistent TCP socket (or stateless UDP socket)
- On `exportNewEntry` / `exportUpdatedEntry`: if entry is `Status.PROCESSED` and passes filter, build the RFC 3164 message and call `sendEntry()`
- TCP failure handling (per entry):
  1. Send fails → attempt one immediate reconnect
  2. Reconnect succeeds → reset consecutive-failure counter, resend entry
  3. Reconnect fails → drop entry, increment dropped counter, increment consecutive-failure counter
  4. Consecutive-failure counter hits 5 → show dialog, call `shutdown()`
- UDP: `DatagramSocket`, fire-and-forget; log and increment dropped counter on error
- Tracks `sentCount` (atomic integer, both protocols) and `droppedCount` (atomic integer, TCP only); notifies control panel after each update
- No batching — syslog is a streaming protocol; entries are sent immediately

### `CyberEyesSyslogControlPanel`

Extends `JPanel`. Contains:
- "Configure CyberEyes Exporter" button → opens `CyberEyesSyslogConfigDialog`
- Toggle button: "Start / Stop CyberEyes Exporter" (uses `SwingWorker` to avoid blocking EDT)
- Status area (updated live by the exporter, layout adapts to protocol):
  - Connection state indicator: green dot "Connected" / red dot "Disconnected" / grey "Idle"
  - **TCP:** `Sent: 1,042` and `Dropped: 3` — dropped counts entries where reconnect also failed
  - **UDP:** `Sent (best-effort): 1,042` — no dropped counter; UDP delivery is undetectable
  - Last sent timestamp: `Last sent: 2026-07-01 10:22:11`
  - Last error message: `Error: Connection refused` (TCP only; cleared on successful send)

### `CyberEyesSyslogConfigDialog`

Extends `JDialog`. Fields:
- Host (text, default `127.0.0.1`)
- Port (spinner, default `514`)
- Protocol radio: TCP / UDP
- Syslog hostname (text, default `InetAddress.getLocalHost().getHostName()`)
- Filter expression (text, same as ElasticExporter config)
- Autostart: global checkbox + project-level checkbox

## Syslog Message Format

**RFC 3164 structure:**
```
<13>Jul  1 10:22:11 burp-host pcap: time="2026-07-01T10:22:11Z" src="127.0.0.1" ...
```

| Part | Value |
|---|---|
| PRI | `<13>` fixed (facility=1 user, severity=5 notice) |
| Timestamp | `MMM DD HH:mm:ss` — space-padded day (`Jul  1`, not `Jul 01`) |
| Hostname | Configurable; default `InetAddress.getLocalHost().getHostName()` |
| App tag | `pcap` fixed, followed by `: ` before message body |
| Message body | `key="value"` for strings, `key=123` unquoted for integers/floats |

**String encoding rules:**
- String values: always double-quoted, empty string `""` for null or missing
- Integer/float values: unquoted (e.g., `status=200`, `duration=191`)
- `request_header` value: raw header block with `\r\n` embedded, double-quoted

**TCP framing:** newline `\n` appended after each message (RFC 6587 non-transparent framing — what Vector expects).
**UDP framing:** none; each datagram is one complete message.

## Field Mapping

All fields from the CyberEyes `cybereyes-web-v2-pcap` OpenSearch template, mapped to Logger++ sources:

| pcap field | Source | Access method |
|---|---|---|
| `time` | `REQUEST_TIME` | `getValueByKey(REQUEST_TIME)` → format as `yyyy-MM-dd'T'HH:mm:ss'Z'` |
| `src` | `CLIENT_IP` | `getValueByKey(CLIENT_IP)` — as-is from Burp proxy |
| `dest` | `HOSTNAME` | `getValueByKey(HOSTNAME)` |
| `src_port` | *(omitted)* | Burp does not expose ephemeral client port |
| `dest_port` | `PORT` | `getValueByKey(PORT)` — unquoted integer |
| `http_method` | `METHOD` | `getValueByKey(METHOD)` |
| `version` | `REQUEST_HTTP_VERSION` | `getValueByKey(REQUEST_HTTP_VERSION)` — parsed from request line |
| `uri_path` | `PATH` | `getValueByKey(PATH)` |
| `uri_query` | `QUERY` | `getValueByKey(QUERY)` |
| `file_extension` | `EXTENSION` | `getValueByKey(EXTENSION)` |
| `url_domain` | `HOSTNAME` | `getValueByKey(HOSTNAME)` |
| `host` | `HOSTNAME` | `getValueByKey(HOSTNAME)` |
| `http_user_agent` | request header | `getRequestHeader(entry, "User-Agent")` |
| `http_accept` | request header | `getRequestHeader(entry, "Accept")` |
| `http_accept_language` | request header | `getRequestHeader(entry, "Accept-Language")` |
| `http_referrer` | `REFERRER` | `getValueByKey(REFERRER)` |
| `request_connection` | request header | `getRequestHeader(entry, "Connection")` |
| `request_content_type` | `REQUEST_CONTENT_TYPE` | `getValueByKey(REQUEST_CONTENT_TYPE)` |
| `request_content_length` | request header | `getRequestHeader(entry, "Content-Length")` — empty string for requests without body |
| `x_forwarded_for` | request header | `getRequestHeader(entry, "X-Forwarded-For")` |
| `x_forwarded_host` | request header | `getRequestHeader(entry, "X-Forwarded-Host")` |
| `authorization` | request header | `getRequestHeader(entry, "Authorization")` |
| `cookie` | `SENTCOOKIES` | `getValueByKey(SENTCOOKIES)` |
| `bytes_in` | raw request | `logEntry.getRequestBytes().length` — unquoted |
| `body_bytes_in` | `REQUEST_BODY_LENGTH` | `getValueByKey(REQUEST_BODY_LENGTH)` — unquoted |
| `request_header` | `REQUEST_HEADERS` | `getValueByKey(REQUEST_HEADERS)` — raw block, quoted |
| `status` | `STATUS` | `getValueByKey(STATUS)` — unquoted integer |
| `response_content_type` | `RESPONSE_CONTENT_TYPE` | `getValueByKey(RESPONSE_CONTENT_TYPE)` |
| `response_content_length` | response header | `getResponseHeader(entry, "Content-Length")` |
| `server` | response header | `getResponseHeader(entry, "Server")` |
| `etag` | response header | `getResponseHeader(entry, "ETag")` |
| `last_modified` | response header | `getResponseHeader(entry, "Last-Modified")` |
| `location` | response header | `getResponseHeader(entry, "Location")` |
| `set_cookie` | response header | `getResponseHeader(entry, "Set-Cookie")` |
| `x_powered_by` | response header | `getResponseHeader(entry, "X-Powered-By")` |
| `bytes_out` | raw response | `logEntry.getResponseBytes().length` — unquoted |
| `body_bytes_out` | `RESPONSE_BODY_LENGTH` | `getValueByKey(RESPONSE_BODY_LENGTH)` — unquoted |
| `duration` | `RTT` | `getValueByKey(RTT)` — unquoted integer (ms) |

## Preferences Keys (to add to Globals.java)

```java
PREF_CYBEREYES_ADDRESS              // String, default "127.0.0.1"
PREF_CYBEREYES_PORT                 // Integer, default 514
PREF_CYBEREYES_PROTOCOL             // Enum TCP/UDP, default TCP
PREF_CYBEREYES_SYSLOG_HOSTNAME      // String, default local hostname
PREF_CYBEREYES_FILTER               // String, default ""
PREF_CYBEREYES_FILTER_PROJECT_PREVIOUS // String, for filter-change warning
PREF_CYBEREYES_AUTOSTART_GLOBAL     // Boolean, default false
PREF_CYBEREYES_AUTOSTART_PROJECT    // Boolean, default false
```

## Error Handling

- **TCP connection failure on setup:** throw exception → ExportController shows dialog, exporter does not start
- **TCP send failure during operation:** attempt one immediate reconnect; if reconnect also fails, drop entry, increment `droppedCount` and consecutive-failure counter; after 5 consecutive failures show dialog and call `shutdown()`; successful send resets consecutive-failure counter to 0
- **UDP send failure:** UDP delivery is undetectable — no dropped counter. Local `IOException` from `send()` is logged only.
- **Filter parse error:** log error, proceed without filter (consistent with ElasticExporter)
- **Filter change warning:** same dialog as ElasticExporter — warn if current filter differs from last-used project filter
- **Panel refresh:** control panel updates status labels via `SwingUtilities.invokeLater` after each send attempt (success or drop)

## Out of Scope

- HTTP bulk API transport (`CyberEyesHttpExporter`) — deferred to a follow-up
- TLS/SSL for syslog (not used in default CyberEyes on-prem setup)
- Message size enforcement (RFC 3164 1024-byte limit not enforced — CyberEyes/Vector accepts larger messages as seen in the sample)
