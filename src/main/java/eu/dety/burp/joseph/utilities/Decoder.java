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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;

import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * Help functions to encode and decode JOSE values from different representations.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class Decoder {
    private static final Logger loggerInstance = Logger.getInstance();

    /**
     * Safe URL encode a byte array to a String
     *
     * @param input
     *            byte array input
     * @return base64url encoded string
     */
    public static String base64UrlEncode(byte[] input) {
        return new String(Base64.encodeBase64URLSafe(input));
    }

    /**
     * Split JOSE value into its separate parts
     *
     * @param input
     *            Compact serialization JOSE value
     * @return string array with the separate parts
     */
    public static String[] getComponents(String input) {
        return input.split("\\.", -1);
    }

    /**
     * Split JOSE value into its separate parts with fixed length
     *
     * @param input
     *            Compact serialization JOSE value
     * @param assureLength
     *            Assure a certain length of the returned string array
     * @return string array with the separate fixed amount of parts
     */
    public static String[] getComponents(String input, int assureLength) {
        String[] components = input.split("\\.");

        // If length is already correct return the components
        if (components.length == assureLength) {
            return components;
        }

        String[] output = new String[assureLength];
        Arrays.fill(output, "");

        System.arraycopy(components, 0, output, 0, Math.min(components.length, assureLength));

        return output;
    }

    /**
     * Join separate parts to JOSE value
     *
     * @param input
     *            string array of JOSE values in compact serialization
     * @return single string with concatenated components
     */
    public static String concatComponents(String[] input) {
        return StringUtils.join(input, ".");
    }

    /**
     * Decode from base64url representation to string
     *
     * @param input
     *            base64url encoded value
     * @return string representation of the base64 decoded value
     */
    public static String getDecoded(String input) {
        String output = "[ERROR]";

        try {
            output = new String(Base64.decodeBase64(input), Charset.forName("UTF-8"));
        } catch (Exception e) {
            loggerInstance.log(Decoder.class, e.getMessage(), Logger.LogLevel.ERROR);
        }

        return output;
    }

    /**
     * Decode from base64url representation to JSONObject
     *
     * @param input
     *            base64url encoded value
     * @return JSONObject of the parsed value
     */
    public static JSONObject getDecodedJson(String input) {
        String decoded = getDecoded(input);
        JSONObject output = new JSONObject();

        if (decoded.equals("[ERROR]"))
            return output;

        try {
            output = new JSONObject(decoded);
        } catch (Exception e) {
            // decoded is no valid JSON string
            // loggerInstance.log(getClass(), e.getMessage(), Logger.ERROR);
        }

        return output;
    }

    /**
     * Get value by base64url string input and key name
     *
     * @param input
     *            base64url string
     * @param key
     *            Name of the key
     * @return String value according to given key or empty string
     */
    public static String getValueByBase64String(String input, String key) {
        JSONObject jsonObj = Decoder.getDecodedJson(input);

        try {
            return jsonObj.get(key).toString();
        } catch (Exception e) {
            return "";
        }

    }

    /**
     * Decode from jose value to JSONObject array
     *
     * @param input
     *            base64url encoded jose value string
     * @return JSONObject array of the parsed value
     */
    public static JSONObject[] getJsonComponents(String input) {
        String[] components = Decoder.getComponents(input);

        JSONObject[] output = new JSONObject[components.length];
        for (int i = 0; i < components.length; i++) {
            output[i] = Decoder.getDecodedJson(components[i]);
        }

        return output;
    }

    /**
     * Encode from JSON string to base64url representation
     *
     * @param input
     *            JSON byte array
     * @return base64url representation of the JSON string
     */
    public static String getEncoded(byte[] input) {
        String output = "[ERROR]";

        try {
            output = base64UrlEncode(input);
        } catch (Exception e) {
            loggerInstance.log(Decoder.class, e.getMessage(), Logger.LogLevel.ERROR);
        }

        return output;
    }

    /**
     * Encode from JSON string to base64url representation
     *
     * @param input
     *            JSON string
     * @return base64url representation of the JSON string
     */
    public static String getEncoded(String input) {
        String output = "[ERROR]";

        try {
            output = base64UrlEncode(input.getBytes(Charset.forName("UTF-8")));
        } catch (Exception e) {
            loggerInstance.log(Decoder.class, e.getMessage(), Logger.LogLevel.ERROR);
        }

        return output;
    }

    private final static char[] HEXCHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    /**
     * Convert byte array to hex string
     *
     * @param bytes
     *            Byte array input
     * @return Hex string
     */
    public static String bytesToHex(final byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (byte aByte : bytes) {
            // unsigned right shift of the MSBs
            builder.append(HEXCHARS[(aByte & 0xff) >>> 4]);
            // handling the LSBs
            builder.append(HEXCHARS[aByte & 0xf]);
            builder.append(' ');
        }

        return builder.toString().trim();
    }

    /**
     * Convert hex string to byte array
     *
     * @param str
     *            Hex formatted string
     * @return Byte array
     */
    public static byte[] hexToBytes(String str) {
        str = str.replace(" ", "");
        int len = str.length();
        byte[] data = new byte[len / 2];

        try {
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
            }
        } catch (Exception e) {
            data = new byte[0];
        }

        return data;
    }

    public static String byteArrayValueToString(byte[] array) {
        String result = "";
        if (array.length == 0)
            return result;
        for (byte value : array) {
            result += Integer.valueOf(value).toString() + ", ";
        }
        return result.substring(0, result.length() - 2);
    }
}
