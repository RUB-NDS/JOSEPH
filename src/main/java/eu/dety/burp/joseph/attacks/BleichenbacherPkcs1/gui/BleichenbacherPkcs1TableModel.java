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
package eu.dety.burp.joseph.attacks.BleichenbacherPkcs1.gui;

import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class BleichenbacherPkcs1TableModel extends AbstractTableModel {
    private static final Logger loggerInstance = Logger.getInstance();
    private ArrayList<BleichenbacherPkcs1TableEntry> tableEntries;
    private String[] columnName = {"#", "Payload type", "Payload", "Status", "Length", "Time", "PKCS1 Conform?"};

    
    /**
     * Construct a new table helper
     * @param tableEntries A list of table entries.
     */
    public BleichenbacherPkcs1TableModel(ArrayList<BleichenbacherPkcs1TableEntry> tableEntries) {
        this.tableEntries = tableEntries;
    }

    /**
     * Get the tableEntries list.
     * @return The list of {@link BleichenbacherPkcs1TableEntry}.
     */
    public ArrayList<BleichenbacherPkcs1TableEntry> getTableEntries(){
        return tableEntries;
    }

    /**
     * Add a row to the tableEntries list.
     * @param entry The new table row.
     * @return True if successful, false otherwise.
     */
    public boolean addRow(BleichenbacherPkcs1TableEntry entry) {
        try {
            int row = tableEntries.size();
            tableEntries.add(entry);
            fireTableRowsInserted(row, row);
        } catch(Exception e) {
            return false;
        }
        return true;
    }

    /**
     * Remove all entries from the tableEntries list.
     * @return True if all entries cleared, false otherwise.
     */
    public boolean clear() {
        try {
            tableEntries.clear();
            fireTableDataChanged();
        } catch(Exception e) {
            return false;
        }
        return true;
    }

    /**
     * Get the number of rows.
     * @return Number of rows.
     */
    @Override
    public int getRowCount()
    {
        return tableEntries.size();
    }

    /**
     * Get the number of columns
     * @return Number of columns.
     */
    @Override
    public int getColumnCount()
    {
        return columnName.length;
    }

    /**
     * Get the name of the column at a specific index.
     * @param columnIndex Index of the column.
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
     * Get the class of the column value at a specific index.
     * @param column Index of the column.
     * @return The class of the column value.
     */
    @Override
    public Class getColumnClass(int column) {

        switch (column)
        {
            case 0:
                return Integer.class;
            case 3:
                return Short.class;
            case 6:
                return Boolean.class;
            default:
                return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return (column == 6);
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {

        if(columnIndex == 6) {
            BleichenbacherPkcs1TableEntry entry = tableEntries.get(rowIndex);
            entry.setIsValid((boolean)value);
            fireTableCellUpdated(rowIndex, columnIndex);
        }

    }

    /**
     * Get the value at a position.
     * @param rowIndex The row.
     * @param columnIndex The column.
     * @return Value for the specified entry. Null if not found.
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        BleichenbacherPkcs1TableEntry entry = tableEntries.get(rowIndex);

        switch (columnIndex)
        {
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
                return entry.getIsValid();
            default:
                return null;
        }
    }
}
