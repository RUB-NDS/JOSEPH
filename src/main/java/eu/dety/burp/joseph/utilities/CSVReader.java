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
package eu.dety.burp.joseph.utilities;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Chinese Remainder implementation to calculate the targets private key.
 * 
 * @author Vincent Unsel
 * @version 1.0
 */
public class CSVReader {
    private static final Logger loggerInstance = Logger.getInstance();
    private String location;
    private InputStreamReader reader;
    private CSVRecord currentLineRecord;
    private Iterable<CSVRecord> records;
    private Iterator<CSVRecord> it;
    private String index;

    private CSVReader() {
    }

    public CSVReader(String location) {
        changeLocation(location);
    }

    public boolean changeLocation(String file) {
        this.location = file;
        reader = new InputStreamReader(this.getClass().getClassLoader().getResourceAsStream(file));
        try {
            records = CSVFormat.RFC4180.parse(reader);
            it = records.iterator();
        } catch (FileNotFoundException e) {
            loggerInstance.log(getClass(), "Error File not found: " + e.getMessage(), Logger.LogLevel.ERROR);
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            loggerInstance.log(getClass(), "Error IO exception: " + e.getMessage(), Logger.LogLevel.ERROR);
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Resets the current loaded file to the start.
     */
    public void restart() {
        index = null;
        currentLineRecord = null;
        closeFile();
        changeLocation(location);
    }

    /**
     * Close the stream reader
     */
    public void closeFile() {
        try {
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Checks, whether the file contains another record.
     * 
     * @return hasNext
     */
    public boolean hasNext() {
        return it.hasNext();
    }

    /**
     * Get the next line and increment the current record.
     * 
     * @return currentLineRecord
     */
    public Iterable<String> next() {
        currentLineRecord = it.next();
        return currentLineRecord;
    }

    /**
     * Get the current record.
     * 
     * @return currentLineRecord
     */
    public Iterable<String> getCurrentRecord() {
        if (currentLineRecord == null && this.hasNext()) {
            return this.next();
        }
        return currentLineRecord;
    }

    /**
     * Get all lines that equal the next value in the specified column.
     * 
     * @param column
     *            comma separated value column
     * @return listOfLineRecords
     */
    public List<? super Iterable<String>> getEqualLinesFromColumn(int column) {
        if (!it.hasNext() && index.equals(((CSVRecord) getCurrentRecord()).get(column))) {
            return null;
        }
        List<? super Iterable<String>> result = new ArrayList<>();
        index = ((CSVRecord) getCurrentRecord()).get(column);
        result.add(currentLineRecord);
        while (it.hasNext() && index.equals(((CSVRecord) next()).get(column))) {
            result.add(currentLineRecord);
        }
        return result;
    }

    /**
     * Get all lines that equal the next value in the first column.
     * 
     * @return listOfLineRecords
     */
    public List<? super Iterable<String>> getEqualLinesFirstColumn() {
        return getEqualLinesFromColumn(0);
    }
}
