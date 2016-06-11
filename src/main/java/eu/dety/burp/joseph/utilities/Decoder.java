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

import burp.IBurpExtenderCallbacks;

import burp.IExtensionHelpers;
import org.apache.commons.codec.binary.Base64;

import org.apache.commons.lang3.StringUtils;

/**
 * Decoder.
 * Help functions to decode JOSE values from different representations.
 * @author Dennis Detering
 * @version 1.0
 */
public class Decoder {
    private static final Logger loggerInstance = Logger.getInstance();
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    /**
     * Create new Decoder instance
     * @param callbacks {@link IBurpExtenderCallbacks}.
     */
    public Decoder(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * Safe URL encode a byte array to a String
     */
    private String base64UrlEncode(byte[] str) {
        return new String(Base64.encodeBase64URLSafe(str));
    }

    /**
     * Split JOSE value into its separate parts
     * @param input Compact serialization JOSE value
     * @return string array with the separate parts
     */
    public String[] getComponents(String input) {
        return input.split("\\.");
    }

    /**
     * Join separate parts to JOSE value
     * @param input Compact serialization JOSE value
     * @return string array with the separate parts
     */
    public String concatComponents(String[] input) {
        for(String foo: input) {
            loggerInstance.log(getClass(), foo, Logger.DEBUG);
        }
        return StringUtils.join(input, ".");
    }

    /**
     * Decode from base64url representation to JSON string
     * @param input base64url encoded value
     * @return string representation of the base64 decoded and JSON parsed value
     */
    public String getDecoded(String input) {
        String output = "[ERROR]";

        try {
            output = helpers.bytesToString(Base64.decodeBase64(input));
        } catch(Exception e){
            loggerInstance.log(getClass(), e.getMessage(), Logger.ERROR);
        }

        return output;
    }

    /**
     * Encode from JSON string to base64url representation
     * @param input JSON string
     * @return base64url representation of the JSON string
     */
    public String getEncoded(byte[] input) {
        String output = "[ERROR]";

        try {
            String tmp = helpers.bytesToString(input);
            output = base64UrlEncode(helpers.stringToBytes(tmp));
            loggerInstance.log(getClass(), output, Logger.DEBUG);
        } catch(Exception e){
            loggerInstance.log(getClass(), e.getMessage(), Logger.ERROR);
        }

        return output;
    }
}
