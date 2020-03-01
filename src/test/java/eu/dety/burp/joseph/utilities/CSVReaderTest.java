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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.NoSuchElementException;

import static org.junit.Assert.*;

public class CSVReaderTest {
    private CSVReader csvr;

    @Before
    public void setUp() {
        String path = "invalidPoints_P-256Test.csv";
        csvr = new CSVReader(path);
    }

    @After
    public void tearDown() {
        csvr.closeFile();
    }

    @Test
    public void getCurrentRecordTest() {
        Iterable<String> testcase = csvr.getCurrentRecord();
        assertNotNull(testcase);

    }

    @Test
    public void nextTest() {
        assertNotNull(csvr.next());
        for (int i = 0; i < 9; ++i)
            csvr.next();
        try {
            csvr.next();
        } catch (NoSuchElementException e) {
            assertTrue(true);
        }
    }

    @Test
    public void hasNextTest() {
        assertTrue(csvr.hasNext());
        for (int i = 0; i < 10; ++i)
            csvr.next();
        assertFalse(csvr.hasNext());
    }

    @Test
    public void getEqualLinesFromColumnTest() {
        List<? super Iterable<String>> testcase0 = csvr.getEqualLinesFromColumn(0);
        List<? super Iterable<String>> testcase1 = csvr.getEqualLinesFromColumn(0);
        List<? super Iterable<String>> testcase2 = csvr.getEqualLinesFromColumn(0);
        List<? super Iterable<String>> testcase3 = csvr.getEqualLinesFromColumn(0);
        assertNotNull(testcase0);
        assertEquals(testcase1.size(), 3);
        assertFalse(testcase2.isEmpty());
        assertEquals(testcase3.size(), 2);
        assertNull(csvr.getEqualLinesFromColumn(0));
    }

    @Test
    public void restartTest() {
        Iterable<String> testcase = csvr.getCurrentRecord();
        csvr.next();
        csvr.restart();
        Iterable<String> expected = csvr.getCurrentRecord();
        assertEquals(testcase.toString(), expected.toString());
    }

}
