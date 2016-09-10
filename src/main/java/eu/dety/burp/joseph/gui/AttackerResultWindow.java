/**
 * JOSEPH - JavaScript Object Signing and Encryption Pentesting Helper
 * Copyright (C) 2016 Dennis Detering
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package eu.dety.burp.joseph.gui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;
import eu.dety.burp.joseph.gui.table.Table;
import eu.dety.burp.joseph.gui.table.TableEntry;
import eu.dety.burp.joseph.gui.table.TableModel;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Objects;

/**
 * Attacker Result Window
 * <p>
 * Window holding a table with every {@link burp.IHttpRequestResponse} entry of the attack.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class AttackerResultWindow extends JFrame {
    private static final Logger loggerInstance = Logger.getInstance();
    private Table table;
    private JProgressBar progressBar = new JProgressBar();
    private JTabbedPane topTabs;


    public AttackerResultWindow(String caption, final IBurpExtenderCallbacks callbacks) {
        super(caption);

        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setSize(1000, 800);
        this.setResizable(true);

        // Create request and response viewer editors
        final IMessageEditor requestViewer;
        final IMessageEditor responseViewer;
        requestViewer = callbacks.createMessageEditor(null ,false);
        responseViewer = callbacks.createMessageEditor(null, false);

        // Create result table
        table = new Table(new TableModel(new ArrayList<TableEntry>()));

        // Add selection changed listener to update request and response viewer editors
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent evt) {
                loggerInstance.log(table.getClass(), "Selection changed", Logger.LogLevel.DEBUG);

                TableEntry entry = table.getEntryByRow(table.getSelectedRow());

                requestViewer.setMessage(entry.getMessage().getRequest(), true);
                responseViewer.setMessage(entry.getMessage().getResponse(), false);
            }
        });

        // Create context menu
        JPopupMenu menu = new JPopupMenu();

        // Send to Intruder
        JMenuItem itemIntruder = new JMenuItem("Send to Intruder");
        itemIntruder.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent evt) {
                loggerInstance.log(table.getClass(), "Send to intruder clicked", Logger.LogLevel.DEBUG);

                TableEntry entry = table.getEntryByRow(table.getSelectedRow());

                IHttpService messageHttpService = entry.getMessage().getHttpService();
                boolean isHttps = false;
                if (Objects.equals(messageHttpService.getProtocol(), "https")) { isHttps = true; }

                callbacks.sendToIntruder(messageHttpService.getHost(), messageHttpService.getPort(), isHttps, entry.getMessage().getRequest());

            }
        });
        menu.add(itemIntruder);

        // Send to Repeater
        JMenuItem itemRepeater = new JMenuItem("Send to Repeater");
        itemRepeater.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent evt) {
                loggerInstance.log(table.getClass(), "Send to repeater clicked", Logger.LogLevel.DEBUG);

                TableEntry entry = table.getEntryByRow(table.getSelectedRow());

                IHttpService messageHttpService = entry.getMessage().getHttpService();
                boolean isHttps = false;
                if (Objects.equals(messageHttpService.getProtocol(), "https")) { isHttps = true; }

                callbacks.sendToRepeater(messageHttpService.getHost(), messageHttpService.getPort(), isHttps, entry.getMessage().getRequest(), "JWT");

            }
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
        bottomPanel.add(progressBar, BorderLayout.SOUTH);

        splitPane.setLeftComponent(viewScrollPane);
        splitPane.setRightComponent(bottomPanel);

        topTabs = new JTabbedPane();
        topTabs.addTab("Results", null, splitPane, null);


        this.add(topTabs);
        this.setVisible(true);
    }

    /**
     * Add new {@link TableEntry} to table
     * @param tableEntry {@link TableEntry} table entry
     */
    public void addEntry(TableEntry tableEntry) {
        this.table.addEntry(tableEntry);
    }

    /**
     * Add new {@link TableEntry} to table
     * @param request number of already performed requests
     * @param all amount of requests to be performed
     */
    public void setProgressBarValue(int request, int all) {
        // If all requests have been performed, set to 100% and change text to "finished"
        if(request == all) {
            this.progressBar.setValue(100);
            this.progressBar.setString("Finished (" + all + " Requests)");
            return;
        }

        // Calculate percentage of current status
        int percentage = 0;
        try {
            percentage = 100 / all * request;
        } catch (Exception e) {
            loggerInstance.log(getClass(), e.getMessage(), Logger.LogLevel.ERROR);
        }

        // Sett percentage value and text
        this.progressBar.setValue(percentage);
        this.progressBar.setString("Request " + request + " of " + all + " (" + percentage + "%)");
    }

    /**
     * Add new tab to this window
     * @param tab {@link JPanel} new tab to add
     */
    public void addTab(String caption, JPanel tab) {
        topTabs.addTab(caption, null, tab, null);
    }

    /**
     * Set enabled status of a specific tab
     * @param index Index of the tab
     * @param status Boolean value of the enabled status
     */
    public void setTabEnabled(int index, boolean status) {
        topTabs.setEnabledAt(index, status);
    }

}
