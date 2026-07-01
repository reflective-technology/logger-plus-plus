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
        }, new int[][]{{1}, {1}, {1}, {1}}, Alignment.FILL, 1.0, 1.0), BorderLayout.CENTER);

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
            case CONNECTED:
                statusDot.setText("● Connected");
                statusDot.setForeground(new Color(0, 150, 0));
                break;
            case ERROR:
                statusDot.setText("● Error");
                statusDot.setForeground(Color.RED);
                break;
            case IDLE:
                statusDot.setText("● Idle");
                statusDot.setForeground(Color.GRAY);
                break;
        }
    }

    private boolean isExporterEnabled() {
        return exporter.getExportController() != null
                && exporter.getExportController().getEnabledExporters().contains(exporter);
    }

    private enum ConnectionState { CONNECTED, ERROR, IDLE }
}
