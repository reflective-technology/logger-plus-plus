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
