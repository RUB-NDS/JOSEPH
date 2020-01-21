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

import javax.swing.*;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

public class InvalidCurveTable extends JTable {
    private InvalidCurveTableModel tableModel;

    public InvalidCurveTable(InvalidCurveTableModel tableModel) {
        super(tableModel);
        this.tableModel = tableModel;
        // Add mouseListener to select row on mouse click
        final InvalidCurveTable parent = this;
        this.addMouseListener(new MouseAdapter() {
            public void mouseReleased(MouseEvent event) {
                // selects the row at which point the mouse is clicked
                Point point = event.getPoint();
                int currentRow = parent.rowAtPoint(point);
                parent.setRowSelectionInterval(currentRow, currentRow);
            }
        });

        // Enable sorting
        TableRowSorter<TableModel> sorter = new TableRowSorter<>();
        sorter.setModel(this.getModel());
        this.setRowSorter(sorter);
        this.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
    }

    /**
     * Get the {@link InvalidCurveTableModel}.
     *
     * @return The {@link InvalidCurveTableModel} related to the table.
     */
    public InvalidCurveTableModel getTableModel() {
        return tableModel;
    }

    /**
     * Get all {@link InvalidCurveTableEntry}s
     *
     * @return Get a list of table entries
     */
    public List<InvalidCurveTableEntry> getTableList() {
        return tableModel.getTableEntries();
    }

    /**
     * Update the table the full history.
     *
     * @param entry
     *            {@link InvalidCurveTableEntry}
     */
    public void addEntry(InvalidCurveTableEntry entry) {
        tableModel.addRow(entry);
    }

    /**
     * Get the {@link InvalidCurveTableEntry} at specific index.
     *
     * @param index
     *            The index.
     * @return {@link InvalidCurveTableEntry}
     */
    public InvalidCurveTableEntry getEntry(int index) {
        return tableModel.getTableEntries().get(index);
    }

    /**
     * Get the {@link InvalidCurveTableEntry} by row index.
     *
     * @param index
     *            The row index.
     * @return {@link InvalidCurveTableEntry}
     */
    public InvalidCurveTableEntry getEntryByRow(int index) {
        return tableModel.getTableEntries().get(convertRowIndexToModel(index));
    }

}
