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
import burp.IMessageEditor;
import eu.dety.burp.joseph.gui.table.Table;
import eu.dety.burp.joseph.gui.table.TableEntry;
import eu.dety.burp.joseph.gui.table.TableHelper;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.util.ArrayList;

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

    public AttackerResultWindow(String caption, IBurpExtenderCallbacks callbacks) {
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
        table = new Table(new TableHelper(new ArrayList<TableEntry>()));

        // Add selection changed listener to update request and response viewer editors
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent evt) {
                loggerInstance.log(table.getClass(), "Selection changed", Logger.LogLevel.DEBUG);

                TableEntry entry = table.getTableList().get(table.getSelectedRow());

                requestViewer.setMessage(entry.getMessage().getRequest(), true);
                responseViewer.setMessage(entry.getMessage().getResponse(), false);
            }
        });

        // main split pane for the view section
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        JScrollPane viewScrollPane = new JScrollPane(table, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // tabs with request/response viewers
        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Response", responseViewer.getComponent());
        splitPane.setLeftComponent(viewScrollPane);
        splitPane.setRightComponent(tabs);

        JTabbedPane topTabs;
        topTabs = new JTabbedPane();
        topTabs.addTab("Results", null, splitPane, null);

        this.add(topTabs);
        this.setVisible(true);
    }

    public void addEntry(TableEntry tableEntry) {
        this.table.addEntry(tableEntry);
    }

}
