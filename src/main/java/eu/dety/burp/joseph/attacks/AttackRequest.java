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
package eu.dety.burp.joseph.attacks;

/**
 * Attack Request
 * <p>
 * Abstract class specifying properties of a single prepared attack request
 * 
 * @author Dennis Detering
 * @version 1.0
 */
abstract public class AttackRequest {
    private byte[] request = null;
    private int payloadType = -1;

    public AttackRequest(byte[] request, int payloadType) {
        this.setRequest(request);
        this.setPayloadType(payloadType);
    }

    /**
     * Get the request content
     * 
     * @return byte array request content
     */
    public byte[] getRequest() {
        return request;
    }

    /**
     * Set the request content
     * 
     * @param request
     *            byte array request content
     */
    public void setRequest(byte[] request) {
        this.request = request;
    }

    /**
     * Get the payload type
     * <p>
     * Each {@link IAttackInfo} class should implement an enum PayloadType
     * 
     * @return ordinal value of payload type
     */
    public int getPayloadType() {
        return payloadType;
    }

    /**
     * Set the payload type
     * 
     * @param payloadType
     *            ordinal value of payload type
     */
    public void setPayloadType(int payloadType) {
        this.payloadType = payloadType;
    }
}
