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
package eu.dety.burp.joseph.gui.table;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

/**
 * Base class for tables.
 * @author Dennis Detering
 * @version 1.0
 */
public class Table extends JTable {
    private TableModel tableModel;
    private ArrayList<TableEntry> tableEntries;

    /**
     * Create a new Table.
     * @param tableModel The helper to organise the table entries.
     */
    public Table(TableModel tableModel) {
        super(tableModel);
        this.tableModel = tableModel;
        this.tableEntries = tableModel.getTableEntries();

        // Add mouseListener to select row on mouse click
        final Table parent = this;
        this.addMouseListener(new MouseAdapter() {
            public void mouseReleased(MouseEvent event) {
                // selects the row at which point the mouse is clicked
                Point point = event.getPoint();
                int currentRow = parent.rowAtPoint(point);
                parent.setRowSelectionInterval(currentRow, currentRow);
            }
        });

        // Enable sorting
        TableRowSorter<javax.swing.table.TableModel> sorter = new TableRowSorter<>();
        sorter.setModel(this.getModel());
        this.setRowSorter(sorter);
        this.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
    }

    /**
     * Get the {@link TableModel}.
     * @return The {@link TableModel} related to the table.
     */
    public TableModel getTableModel() {
        return tableModel;
    }

    /**
     * Get all {@link TableEntry}s
     * @return Get a list of table entries
     */
    public ArrayList<TableEntry> getTableList() {
        return tableEntries;
    }

    /**
     * Update the table the full history.
     * @param entry {@link TableEntry}
     */
    public void addEntry(TableEntry entry) {
        tableModel.addRow(entry);
    }

    /**
     * Get the {@link TableEntry} at specific index.
     * @param index The index.
     * @return {@link TableEntry}
     */
    public TableEntry getEntry(int index){
        return tableEntries.get(index);
    }

}
