package eu.dety.burp.joseph.scanner;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import eu.dety.burp.joseph.utilities.Logger;

import java.io.PrintWriter;

/**
 * HTTP listener to recognize and mark JOSE parameter
 * @author Dennis Detering
 * @version 1.0
 */
public class Marker implements IHttpListener {
    private static Logger loggerInstance = Logger.getInstance();

    private IBurpExtenderCallbacks callbacks;

    public Marker(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        loggerInstance.log(getClass(), (messageIsRequest ? "HTTP request to " : "HTTP response from ") + messageInfo.getHttpService(), Logger.INFO);
    }

}
