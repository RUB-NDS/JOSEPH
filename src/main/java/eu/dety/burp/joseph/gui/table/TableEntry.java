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
package eu.dety.burp.joseph.gui.table;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

import java.text.SimpleDateFormat;
import java.util.Calendar;

/**
 * Table entry for the attack table.
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class TableEntry {
    private int entryIndex = 0;
    private String payloadType = "";
    private String payload = "";
    private short status = 0;
    private String time = "";
    private String length = "";
    private String comment = "";
    private IHttpRequestResponse requestResponse = null;
    private IExtensionHelpers helpers;

    /**
     * Construct a new table entry.
     * 
     * @param payload
     *            Payload used for the attack request
     * @param requestResponse
     *            The content of the request/response.
     * @param callbacks
     *            Helper provided by the Burp Suite api.
     */
    public TableEntry(int entryIndex, int payloadType, String payload, IHttpRequestResponse requestResponse,
            IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();

        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());

        this.entryIndex = entryIndex;
        this.setPayloadType(payloadType);
        this.payload = payload;
        this.status = responseInfo.getStatusCode();

        // Get current time
        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        this.time = dateFormat.format(calObj.getTime());

        this.length = (new Integer(requestResponse.getResponse().length)).toString();
        this.comment = requestResponse.getComment();
        this.requestResponse = requestResponse;
    }

    /**
     * Get the index of the message.
     * 
     * @return Message index.
     */
    public int getEntryIndex() {
        return entryIndex;
    }

    /**
     * Get the protocol name.
     * 
     * @return The protocol name.
     */
    public String getPayload() {
        return payload;
    }

    /**
     * Get the status code of the response.
     * 
     * @return The status code.
     */
    public short getStatus() {
        return status;
    }

    /**
     * Get the length of the request.
     * 
     * @return The length.
     */
    public String getLength() {
        return length;
    }

    /**
     * Get the time at which the entry was created.
     * 
     * @return The time (XX:XX:XX).
     */
    public String getTime() {
        return time;
    }

    /**
     * Get the comment. Stores additional data for the protocol
     * 
     * @return The comment.
     */
    public String getComment() {
        return comment;
    }

    /**
     * Get the http message.
     * 
     * @return The http message.
     */
    public IHttpRequestResponse getMessage() {
        return requestResponse;
    }

    /**
     * Set the comment.
     * 
     * @param comment
     *            The comment.
     */
    public void setComment(String comment) {
        this.comment = comment;
    }

    /**
     * Get the payload type ordinal value.
     * 
     * @return The payload type ordinal value.
     */
    public String getPayloadType() {
        return payloadType;
    }

    /**
     * Set the payload type hex string representation.
     * 
     * @param payloadType
     *            The hex string representation value of the payload type.
     */
    public void setPayloadType(int payloadType) {
        this.payloadType = (payloadType > -1) ? String.format("0x%02X", payloadType) : "";
    }
}
