/**
 * JOSEPH - JavaScript Object Signing and Encryption Pentesting Helper
 * Copyright (C) 2016 Dennis Detering
 * <p>
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * <p>
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package eu.dety.burp.joseph.attacks.invalid_curve.gui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;
import eu.dety.burp.joseph.attacks.invalid_curve.ChineseRemainder;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import javax.swing.text.DefaultEditorKit;
import java.awt.*;
import java.util.ArrayList;
import java.util.Objects;

public class InvalidCurveAttackerResultWindow extends JFrame {
    private static final Logger loggerInstance = Logger.getInstance();
    private InvalidCurveTable table;
    private JProgressBar progressBar = new JProgressBar();
    private JTextField resultField;
    private JLabel resultDescriptionField = new JLabel();
    private boolean canceled = false;
    private byte spinner = 0;
    private char[] icons = { '◴', '◷', '◶', '◵' };

    public InvalidCurveAttackerResultWindow(String caption, final IBurpExtenderCallbacks callbacks) {
        super(caption);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setSize(1000, 800);
        this.setResizable(true);
        // Create request and response viewer editors
        final IMessageEditor requestViewer;
        final IMessageEditor responseViewer;
        requestViewer = callbacks.createMessageEditor(null, false);
        responseViewer = callbacks.createMessageEditor(null, false);

        // Create result table
        table = new InvalidCurveTable(new InvalidCurveTableModel(new ArrayList<>()));

        // Add selection changed listener to update request and response viewer
        table.getSelectionModel().addListSelectionListener(evt -> {
            if (table.getSelectedRow() < 0)
                return;

            InvalidCurveTableEntry entry = table.getEntryByRow(table.getSelectedRow());

            requestViewer.setMessage(entry.getMessage().getRequest(), true);
            responseViewer.setMessage(entry.getMessage().getResponse(), false);
        });

        // Create context menu
        JPopupMenu menu = new JPopupMenu();

        // Send to Intruder
        JMenuItem itemIntruder = new JMenuItem("Send to Intruder");
        itemIntruder.addActionListener(evt -> {
            loggerInstance.log(table.getClass(), "Send to intruder clicked", Logger.LogLevel.DEBUG);

            InvalidCurveTableEntry entry = table.getEntryByRow(table.getSelectedRow());

            IHttpService messageHttpService = entry.getMessage().getHttpService();
            boolean isHttps = false;
            if (Objects.equals(messageHttpService.getProtocol(), "https")) {
                isHttps = true;
            }

            callbacks.sendToIntruder(messageHttpService.getHost(), messageHttpService.getPort(), isHttps, entry.getMessage().getRequest());

        });
        menu.add(itemIntruder);

        // Send to Repeater
        JMenuItem itemRepeater = new JMenuItem("Send to Repeater");
        itemRepeater.addActionListener(evt -> {
            loggerInstance.log(table.getClass(), "Send to repeater clicked", Logger.LogLevel.DEBUG);

            InvalidCurveTableEntry entry = table.getEntryByRow(table.getSelectedRow());

            IHttpService messageHttpService = entry.getMessage().getHttpService();
            boolean isHttps = false;
            if (Objects.equals(messageHttpService.getProtocol(), "https")) {
                isHttps = true;
            }

            callbacks.sendToRepeater(messageHttpService.getHost(), messageHttpService.getPort(), isHttps, entry.getMessage().getRequest(), "JWS");

        });
        menu.add(itemRepeater);
        table.setComponentPopupMenu(menu);

        // main split pane for the view section
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JScrollPane viewScrollPane = new JScrollPane(table, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BorderLayout());


        // tabs with request/response viewers
        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Response", responseViewer.getComponent());

        bottomPanel.add(tabs, BorderLayout.CENTER);

        // Add progress bar
        progressBar.setStringPainted(true);
        resultField = new JTextField();
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButton.setEnabled(false);
                cancelButtonActionPerformed(evt);
            }
        });


        Action action = resultField.getActionMap().get(DefaultEditorKit.beepAction);
        action.setEnabled(false);
        cancelButton.setEnabled(true);
        cancelButton.setVisible(true);
        resultField.setVisible(true);
        resultField.setVisible(true);
        resultDescriptionField.setVisible(true);
        JPanel resultPanel = new JPanel();
        resultPanel.setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridwidth = 0;
        gridBagConstraints.gridheight = 0;
        gridBagConstraints.weightx = 0;
        gridBagConstraints.weighty = 0;
        resultPanel.add(new JSeparator(), gridBagConstraints);
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridheight = 1;
        gridBagConstraints.weightx = 0;
        gridBagConstraints.weighty = 0;
        resultPanel.add(resultDescriptionField, gridBagConstraints);
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = 4;
        gridBagConstraints.gridheight = 1;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 0;
        resultPanel.add(resultField, gridBagConstraints);
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridheight = 1;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        resultPanel.add(progressBar, gridBagConstraints);
        gridBagConstraints.gridx = 3;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridheight = 1;
        gridBagConstraints.weightx = 0;
        gridBagConstraints.weighty = 1.0;
        resultPanel.add(cancelButton, gridBagConstraints);

        bottomPanel.add(resultPanel, BorderLayout.SOUTH);
        splitPane.setLeftComponent(viewScrollPane);
        splitPane.setRightComponent(bottomPanel);

        this.add(splitPane);
        this.setVisible(true);
    }

    /**
     * Add new {@link InvalidCurveTableEntry} to table
     *
     * @param tableEntry
     *            {@link InvalidCurveTableEntry} table entry
     */
    public void addEntry(InvalidCurveTableEntry tableEntry) {
        this.table.addEntry(tableEntry);
    }

    /**
     * Add new {@link InvalidCurveTableEntry} to table
     *
     * @param request
     *            number of already performed requests
     * @param all
     *            amount of requests to be performed
     */
    public void setProgressBarValue(int request, int all) {
        float percentage = 0;

        if (request == all) {
            this.progressBar.setValue(100);
            this.progressBar.setString("Finished (" + all + " Responses)");
            return;
        }
        // Calculate percentage of current status
        try {
            percentage = ((float) request / (float) all) * 100f;

        } catch (Exception e) {
            loggerInstance.log(getClass(), e.getMessage(), Logger.LogLevel.ERROR);
        }
        this.progressBar.setString("Request " + request + " of " + all + " (" + Math.ceil(percentage) + "%)");
        this.progressBar.setValue((int) percentage);
        this.progressBar.updateUI();
    }

    public void nextSpin() {
        ++spinner;
        spinner %= icons.length;
        setResultDescription("\tCalculating private key: " + icons[spinner]);
    }

    /**
     * Set text message of attack result
     *
     * @param text
     *            String value of the result
     */
    public void setResultText(String text) {
        resultField.setText(text);
    }

    public void setResultDescription(String text) {

        resultDescriptionField.setText(text);
    }

    public boolean isCanceled() {
        return canceled;
    }

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {
        loggerInstance.log(getClass(), "Attack canceled.", Logger.LogLevel.INFO);
        this.canceled = true;
        ChineseRemainder.getInstance().setCancel(canceled);
    }

}
