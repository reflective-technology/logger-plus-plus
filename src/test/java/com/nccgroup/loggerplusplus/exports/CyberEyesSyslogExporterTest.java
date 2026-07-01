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
