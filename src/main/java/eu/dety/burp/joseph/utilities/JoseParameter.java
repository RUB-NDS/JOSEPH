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

import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;

import java.util.Arrays;
import java.util.List;

public class JoseParameter {
    private IParameter parameter = null;
    private String header = null;
    private OriginType originType = null;
    private JoseType joseType = null;

    /**
     * Construct with {@link IParameter} input
     */
    public JoseParameter(IParameter parameter, JoseType joseType) {
        this.originType = OriginType.PARAMETER;
        this.parameter = parameter;
        this.joseType = joseType;
    }

    /**
     * Construct with header string input
     */
    public JoseParameter(String header, JoseType joseType) {
        this.originType = OriginType.HEADER;
        this.header = header;
        this.joseType = joseType;
    }

    /**
     *  Origin of the parameter, might be one of:
     *  <li>{@link #PARAMETER}</li>
     *  <li>{@link #HEADER}</li>
     */
    public enum OriginType {
        PARAMETER, HEADER
    }

    /**
     *  Jose type of the parameter, might be one of:
     *  <li>{@link #JWS}</li>
     *  <li>{@link #JWE}</li>
     */
    public enum JoseType {
        UNKNOWN, JWS, JWE
    }

    /**
     * Get according origin type
     * @return {@link OriginType}
     */
    public OriginType getOriginType() {
        return this.originType;
    }

    /**
     * Get according jose type
     * @return {@link JoseType}
     */
    public JoseType getJoseType() {
        return this.joseType;
    }

    /**
     * Get the name of the parameter/header
     * @return The name as string
     */
    public String getName() {
        return (this.getOriginType() == OriginType.PARAMETER) ? parameter.getName() : header.split(":", 2)[0];
    }

    /**
     * Get the full value of the parameter/header
     * @return The value as string
     */
    public String getValue() {
        return (this.getOriginType() == OriginType.PARAMETER) ? parameter.getValue().trim() : header.split(":", 2)[1].trim();
    }

    /**
     * Get the extracted jose value of the parameter/header
     * @return The jose value as string
     */
    public String getJoseValue() {
        return (this.getOriginType() == OriginType.PARAMETER) ? Finder.getJoseValue(parameter.getValue()) : Finder.getJoseValue(header);
    }

    /**
     * Get the {@link IParameter} type
     * @return The parameter type as Byte
     */
    public Byte getParameterType() {
        return (this.getOriginType() == OriginType.PARAMETER) ? parameter.getType() : null;
    }

    /**
     * Update a given request
     * @param request The original request as byte array
     * @param parameter {@link JoseParameter} parameter with JOSE value
     * @param helpers {@link IExtensionHelpers} Burp extension helpers
     * @param newValue Value as string to update request with
     * @return The updated request as byte array
     */
    public static byte[] updateRequest(byte[] request, JoseParameter parameter, IExtensionHelpers helpers, String newValue) {

        switch(parameter.getOriginType()) {
            // Update the request with the new header value
            case HEADER:
                IRequestInfo requestInfo = helpers.analyzeRequest(request);
                List<String> headers = requestInfo.getHeaders();

                for (int i = 0; i < headers.size(); i++) {
                    if (headers.get(i).startsWith(parameter.getName())) {
                        headers.set(i, headers.get(i).replace(parameter.getJoseValue(), newValue));
                        break;
                    }
                }

                request =  helpers.buildHttpMessage(headers, Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length));
                break;

            // Update the request with the new parameter value
            case PARAMETER:
                IParameter tmpParameter = helpers.buildParameter(parameter.getName(), newValue, parameter.getParameterType());
                request = helpers.updateParameter(request, tmpParameter);
                break;
        }

        return request;

    }


}
