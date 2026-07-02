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
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
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

    // Forward reference — wired in Task 5
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

        if (!GraphicsEnvironment.isHeadless()
                && prevFilter != null
                && !Objects.equals(prevFilter, filterString)) {
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
        SocketChannel channel = SocketChannel.open(new InetSocketAddress(host, port));
        tcpSocket = channel.socket();
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
            // First failure: attempt reconnect once
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
                    if (!GraphicsEnvironment.isHeadless()) {
                        SwingUtilities.invokeLater(() ->
                                JOptionPane.showMessageDialog(
                                        JOptionPane.getFrameForComponent(controlPanel),
                                        "CyberEyes exporter could not connect after 5 attempts. Shutting down.",
                                        "CyberEyes Exporter - Connection Failed",
                                        JOptionPane.ERROR_MESSAGE)
                        );
                    }
                    try { shutdown(); } catch (Exception ignored) {}
                }
            }
        }
    }

    private void writeTcp(String message) throws IOException {
        if (tcpWriter == null) throw new IOException("Not connected");
        // Non-blocking EOF/RST pre-check — replaces the 5 ms SO_TIMEOUT read.
        // A received FIN makes read() return -1 immediately (zero blocking time).
        // A received RST makes read() throw IOException.  0 bytes = connection alive.
        SocketChannel channel = (tcpSocket != null) ? tcpSocket.getChannel() : null;
        if (channel != null) {
            channel.configureBlocking(false);
            try {
                int n = channel.read(ByteBuffer.allocate(1));
                if (n == -1) throw new IOException("Connection closed by remote (EOF)");
                // n == 0: no pending data, connection alive; n > 0: unexpected server data, discard
            } finally {
                channel.configureBlocking(true);
            }
        }
        tcpWriter.print(message + "\n");
        if (tcpWriter.checkError()) throw new IOException("PrintWriter error after write");
    }

    // Package-private for testing
    void sendUdp(String message) {
        if (udpSocket == null) {
            log.error("CyberEyes UDP socket not initialized");
            return;
        }
        try {
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
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

    // Package-private: no-op until Task 5 wires in the panel
    void notifyControlPanel(int sent, int dropped, String errorMessage) {
        if (controlPanel != null) controlPanel.updateStatus(sent, dropped, errorMessage);
    }

    // Package-private for testing: true if TCP socket is open
    boolean isTcpConnected() {
        return tcpSocket != null && !tcpSocket.isClosed();
    }
}
