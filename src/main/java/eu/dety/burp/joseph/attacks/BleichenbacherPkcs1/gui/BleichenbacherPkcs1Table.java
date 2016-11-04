package eu.dety.burp.joseph.attacks.BleichenbacherPkcs1.gui;

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

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

/**
 * Base class for tables.
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class BleichenbacherPkcs1Table extends JTable {
    private BleichenbacherPkcs1TableModel tableModel;
    private ArrayList<BleichenbacherPkcs1TableEntry> tableEntries;

    /**
     * Create a new Table.
     * 
     * @param tableModel
     *            The helper to organise the table entries.
     */
    public BleichenbacherPkcs1Table(BleichenbacherPkcs1TableModel tableModel) {
        super(tableModel);
        this.tableModel = tableModel;
        this.tableEntries = tableModel.getTableEntries();

        // Add mouseListener to select row on mouse click
        final BleichenbacherPkcs1Table parent = this;
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
     * Get the {@link BleichenbacherPkcs1TableModel}.
     * 
     * @return The {@link BleichenbacherPkcs1TableModel} related to the table.
     */
    public BleichenbacherPkcs1TableModel getTableModel() {
        return tableModel;
    }

    /**
     * Get all {@link BleichenbacherPkcs1TableEntry}s
     * 
     * @return Get a list of table entries
     */
    public ArrayList<BleichenbacherPkcs1TableEntry> getTableList() {
        return tableEntries;
    }

    /**
     * Update the table the full history.
     * 
     * @param entry
     *            {@link BleichenbacherPkcs1TableEntry}
     */
    public void addEntry(BleichenbacherPkcs1TableEntry entry) {
        tableModel.addRow(entry);
    }

    /**
     * Get the {@link BleichenbacherPkcs1TableEntry} at specific index.
     * 
     * @param index
     *            The index.
     * @return {@link BleichenbacherPkcs1TableEntry}
     */
    public BleichenbacherPkcs1TableEntry getEntry(int index) {
        return tableEntries.get(index);
    }

    /**
     * Get the {@link BleichenbacherPkcs1TableEntry} by row index.
     * 
     * @param index
     *            The row index.
     * @return {@link BleichenbacherPkcs1TableEntry}
     */
    public BleichenbacherPkcs1TableEntry getEntryByRow(int index) {
        return tableEntries.get(convertRowIndexToModel(index));
    }

}
