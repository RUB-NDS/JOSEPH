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
package eu.dety.burp.joseph;

import burp.IParameter;

/**
 * Simple class implementing {@link IParameter} to mock Burp's behavior for parameters to be able to write according unit tests.
 */
public class BurpParameterMock implements IParameter {
    private String name;
    private String value;
    private byte type;

    public BurpParameterMock(String name, String value, byte type) {
        this.name = name;
        this.value = value;
        this.type = type;
    }

    @Override
    public byte getType() {
        return this.type;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getValue() {
        return this.value;
    }

    @Override
    public int getNameStart() {
        return 0;
    }

    @Override
    public int getNameEnd() {
        return this.name.length();
    }

    @Override
    public int getValueStart() {
        return this.name.length() + 1;
    }

    @Override
    public int getValueEnd() {
        return this.name.length() + 1 + this.value.length();
    }
}
