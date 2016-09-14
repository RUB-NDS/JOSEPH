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
package eu.dety.burp.joseph.utilities;

import burp.IParameter;

public class JoseParameter {
    private IParameter parameter = null;
    private String header = null;
    private OriginType originType = null;
    private JoseType joseType = null;

    /**
     * Construct with {@link IParameter} input
     */
    public JoseParameter(IParameter parameter) {
        this.originType = OriginType.Parameter;
        this.parameter = parameter;
    }

    /**
     * Construct with header string input
     */
    public JoseParameter(String header) {
        this.originType = OriginType.Header;
        this.header = header;
    }

    /**
     *  Origin of the parameter, might be one of:
     *  <li>{@link #Parameter}</li>
     *  <li>{@link #Header}</li>
     */
    public enum OriginType {
        Parameter, Header
    }

    /**
     *  Jose type of the parameter, might be one of:
     *  <li>{@link #Jws}</li>
     *  <li>{@link #Jwe}</li>
     */
    public enum JoseType {
        Jws, Jwe
    }

    /**
     * Return according origin type
     * @return {@link OriginType}
     */
    public OriginType getOriginType() {
        return this.originType;
    }

    /**
     * Return according jose type
     * @return {@link JoseType}
     */
    public JoseType getJoseType() {
        return this.joseType;
    }

    /**
     * Return the name of the parameter/header
     * @return The name as string
     */
    public String getName() {
        return (this.getOriginType() == OriginType.Parameter) ? parameter.getName() : header.split(":", 2)[0];
    }

    /**
     * Return the full value of the parameter/header
     * @return The value as string
     */
    public String getValue() {
        return (this.getOriginType() == OriginType.Parameter) ? parameter.getValue().trim() : header.split(":", 2)[1].trim();
    }

    /**
     * Return the extracted jose value of the parameter/header
     * @return The jose value as string
     */
    public String getJoseValue() {
        return (this.getOriginType() == OriginType.Parameter) ? Finder.getJwtValue(parameter.getValue()) : Finder.getJwtValue(header);
    }

    /**
     * Return the {@link IParameter} type
     * @return The parameter type as Byte
     */
    public Byte getParameterType() {
        return (this.getOriginType() == OriginType.Parameter) ? parameter.getType() : null;
    }

}
