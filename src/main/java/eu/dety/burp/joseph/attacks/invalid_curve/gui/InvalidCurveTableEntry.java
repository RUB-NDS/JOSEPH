package eu.dety.burp.joseph.attacks.invalid_curve.gui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import eu.dety.burp.joseph.attacks.invalid_curve.Point;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class InvalidCurveTableEntry {
    private Point point = null;
    private int entryIndex = 0;
    private short status = 0;
    private String time = "";
    private String length = "";
    private IHttpRequestResponse requestResponse = null;
    private IExtensionHelpers helpers;

    /**
     * Construct a new table entry.
     *
     * @param requestResponse
     *            The content of the request/response.
     * @param callbacks
     *            Helper provided by the Burp Suite api.
     */
    public InvalidCurveTableEntry(int entryIndex, Point point, IHttpRequestResponse requestResponse, IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        this.point = point;
        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());

        this.entryIndex = entryIndex;
        this.status = responseInfo.getStatusCode();

        // Get current time
        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        this.time = dateFormat.format(calObj.getTime());

        this.length = (new Integer(requestResponse.getResponse().length)).toString();
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
     * Get the http message.
     *
     * @return The http message.
     */
    public IHttpRequestResponse getMessage() {
        return requestResponse;
    }

    public Point getPoint() {
        return this.point;
    }
}
