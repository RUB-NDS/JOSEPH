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
package eu.dety.burp.joseph.attacks.key_confusion;

import eu.dety.burp.joseph.attacks.AttackRequest;

/**
 * Key Confusion Attack Request
 * <p>
 * Class extending abstract {@link AttackRequest} specifying properties of a single prepared key confusion attack request.
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class KeyConfusionAttackRequest extends AttackRequest {
    private String algorithm = null;
    private String keyValue = null;
    private int keyLength = 0;

    public KeyConfusionAttackRequest(byte[] request, int payloadType, String algorithm, String keyValue, int keyLength) {
        super(request, payloadType);
        this.setAlgorithm(algorithm);
        this.setKeyValue(keyValue);
        this.setKeyLength(keyLength);
        this.setKeyValue(keyValue);
    }

    /**
     * Get the algorithm abbreviation
     * 
     * @return The algorithm value
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Set the algorithm
     * 
     * @param algorithm
     *            The algorithm abbreviation (as defined in JWA)
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Get the key value
     * 
     * @return String representation of the public key
     */
    public String getKeyValue() {
        return keyValue;
    }

    /**
     * Set the public key value
     * 
     * @param keyValue
     *            String representation of the public key
     */
    public void setKeyValue(String keyValue) {
        this.keyValue = keyValue;
    }

    /**
     * Get the key length
     * 
     * @return The key length in bytes
     */
    public int getKeyLength() {
        return keyLength;
    }

    /**
     * Set the key length
     * 
     * @param keyLength
     *            The key length in bytes
     */
    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

}
