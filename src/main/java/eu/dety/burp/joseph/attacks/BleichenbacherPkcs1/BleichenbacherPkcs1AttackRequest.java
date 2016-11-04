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
package eu.dety.burp.joseph.attacks.BleichenbacherPkcs1;

import eu.dety.burp.joseph.attacks.AttackRequest;

/**
 * Bleichenbacher PKCS1 Attack Request
 * <p>
 * Class extending abstract {@link AttackRequest} specifying properties of a single prepared
 * bleichenbacher pkcs1 attack request.
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class BleichenbacherPkcs1AttackRequest extends AttackRequest {
    private byte[] vector;

    private String vectorName;

    public BleichenbacherPkcs1AttackRequest(byte[] request, int payloadType, byte[] vector, String vectorName) {
        super(request, payloadType);
        this.setVector(vector);
        this.setVectorName(vectorName);
    }

    /**
     * Get the attack vector
     * 
     * @return The attack vector value
     */
    public byte[] getVector() {
        return vector;
    }

    /**
     * Set the attack vector
     * 
     * @param vector
     *            The attack vector value
     */
    public void setVector(byte[] vector) {
        this.vector = vector;
    }

    /**
     * Get the attack vector name
     * 
     * @return The attack vector name
     */
    public String getVectorName() {
        return vectorName;
    }

    /**
     * Set the attack name
     * 
     * @param vectorName
     *            The attack vector name
     */
    public void setVectorName(String vectorName) {
        this.vectorName = vectorName;
    }

}
