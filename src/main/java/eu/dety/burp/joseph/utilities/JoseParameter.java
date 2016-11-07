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

import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;

import java.util.Arrays;
import java.util.List;

public class JoseParameter {
    private IParameter parameter = null;
    private String header = null;
    private String direct = null;
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
     * Construct with string input and determine JoseType
     * 
     * @throws InvalidJoseValueException
     */
    public JoseParameter(String input) throws InvalidJoseValueException {
        this.originType = OriginType.DIRECT;

        if (Finder.checkJwsPattern(input)) {
            this.joseType = JoseType.JWS;
        } else if (Finder.checkJwePattern(input)) {
            this.joseType = JoseType.JWE;
        } else {
            throw new InvalidJoseValueException("Could not parse the given input, no valid JOSE pattern detected!");
        }

        this.direct = input;
    }

    /**
     * Origin of the parameter, might be one of: <li>{@link #PARAMETER}</li> <li>
     * {@link #HEADER}</li> <li>{@link #DIRECT}</li>
     */
    public enum OriginType {
        PARAMETER,
        HEADER,
        DIRECT
    }

    /**
     * Jose type of the parameter, might be one of: <li>{@link #JWS}</li> <li>
     * {@link #JWE}</li>
     */
    public enum JoseType {
        UNKNOWN,
        JWS,
        JWE
    }

    /**
     * Get according origin type
     * 
     * @return {@link OriginType}
     */
    public OriginType getOriginType() {
        return this.originType;
    }

    /**
     * Get according jose type
     * 
     * @return {@link JoseType}
     */
    public JoseType getJoseType() {
        return this.joseType;
    }

    /**
     * Get the name of the parameter/header
     * 
     * @return The name as string
     */
    public String getName() {
        switch (this.getOriginType()) {
            case PARAMETER:
                return parameter.getName();
            case HEADER:
                return header.split(":", 2)[0];
            case DIRECT:
            default:
                return null;
        }
    }

    /**
     * Get the full value of the parameter/header
     * 
     * @return The value as string
     */
    public String getValue() {
        switch (this.getOriginType()) {
            case PARAMETER:
                return parameter.getValue().trim();
            case HEADER:
                return header.split(":", 2)[1].trim();
            case DIRECT:
                return direct;
            default:
                return null;
        }
    }

    /**
     * Get the extracted jose value of the parameter/header
     * 
     * @return The jose value as string
     */
    public String getJoseValue() {
        switch (this.getOriginType()) {
            case PARAMETER:
                return Finder.getJoseValue(parameter.getValue());
            case HEADER:
                return Finder.getJoseValue(header);
            case DIRECT:
                return Finder.getJoseValue(direct);
            default:
                return null;
        }
    }

    /**
     * Get the components of the jose value
     * 
     * @return Jose value components as string array
     */
    public String[] getComponents() {
        return Decoder.getComponents(this.getJoseValue());
    }

    /**
     * Get the {@link IParameter} type
     * 
     * @return The parameter type as Byte
     */
    public Byte getParameterType() {
        return (this.getOriginType() == OriginType.PARAMETER) ? parameter.getType() : null;
    }

    /**
     * Update a given request
     * 
     * @param request
     *            The original request as byte array
     * @param parameter
     *            {@link JoseParameter} parameter with JOSE value
     * @param helpers
     *            {@link IExtensionHelpers} Burp extension helpers
     * @param newValue
     *            Value as string to update request with
     * @return The updated request as byte array
     */
    public static byte[] updateRequest(byte[] request, JoseParameter parameter, IExtensionHelpers helpers, String newValue) {

        switch (parameter.getOriginType()) {
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

                request = helpers.buildHttpMessage(headers, Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length));
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
