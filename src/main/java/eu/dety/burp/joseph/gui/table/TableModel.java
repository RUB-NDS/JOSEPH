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
package eu.dety.burp.joseph.gui.table;

import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

/**
 * Helper class for the attack table.
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class TableModel extends AbstractTableModel {
    private static final Logger loggerInstance = Logger.getInstance();
    private ArrayList<TableEntry> tableEntries;
    private String[] columnName = { "#", "Payload type", "Payload", "Status", "Length", "Time", "Comment" };

    /**
     * Construct a new table helper
     * 
     * @param tableEntries
     *            A list of table entries.
     */
    public TableModel(ArrayList<TableEntry> tableEntries) {
        this.tableEntries = tableEntries;
    }

    /**
     * Get the tableEntries list.
     * 
     * @return The list of {@link TableEntry}.
     */
    public ArrayList<TableEntry> getTableEntries() {
        return tableEntries;
    }

    /**
     * Add a row to the tableEntries list.
     * 
     * @param entry
     *            The new table row.
     * @return True if successful, false otherwise.
     */
    public boolean addRow(TableEntry entry) {
        try {
            int row = tableEntries.size();
            tableEntries.add(entry);
            fireTableRowsInserted(row, row);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    /**
     * Remove all entries from the tableEntries list.
     * 
     * @return True if all entries cleared, false otherwise.
     */
    public boolean clear() {
        try {
            tableEntries.clear();
            fireTableDataChanged();
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    /**
     * Get the number of rows.
     * 
     * @return Number of rows.
     */
    @Override
    public int getRowCount() {
        return tableEntries.size();
    }

    /**
     * Get the number of columns
     * 
     * @return Number of columns.
     */
    @Override
    public int getColumnCount() {
        return columnName.length;
    }

    /**
     * Get the name of the column at a specific index.
     * 
     * @param columnIndex
     *            Index of the column.
     * @return The name of the column.
     */
    @Override
    public String getColumnName(int columnIndex) {
        try {
            return columnName[columnIndex];
        } catch (Exception e) {
            loggerInstance.log(getClass(), e.getMessage(), Logger.LogLevel.ERROR);
            return "";
        }
    }

    /**
     * Get the value at a position.
     * 
     * @param rowIndex
     *            The row.
     * @param columnIndex
     *            The column.
     * @return Value for the specified entry. Null if not found.
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TableEntry entry = tableEntries.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return entry.getEntryIndex();
            case 1:
                return entry.getPayloadType();
            case 2:
                return entry.getPayload();
            case 3:
                return entry.getStatus();
            case 4:
                return entry.getLength();
            case 5:
                return entry.getTime();
            case 6:
                return entry.getComment();
            default:
                return null;
        }
    }
}
