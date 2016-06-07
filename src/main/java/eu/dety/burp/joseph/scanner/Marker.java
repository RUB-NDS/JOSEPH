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
package eu.dety.burp.joseph.scanner;

import burp.*;

import eu.dety.burp.joseph.gui.UIPreferences;
import eu.dety.burp.joseph.utilities.Logger;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * HTTP listener to recognize and mark JOSE parameter
 * @author Dennis Detering
 * @version 1.0
 */
public class Marker implements IHttpListener {
    private static final Logger loggerInstance = Logger.getInstance();
    private final IExtensionHelpers helpers;
    private final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    private static final String HIGHLIGHT_COLOR = "cyan";

    public Marker(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse httpRequestResponse) {
        // Only flag messages if highlighting option is set to true and if sent/received by the proxy
        if (UIPreferences.getHighlighting() && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            checkForJwtLocations(httpRequestResponse);
        }
    }

    /**
     * Checks whether given recognition pattern for JWT locations match
     * @param httpRequestResponse {@link IHttpRequestResponse} Object containing the request/response.
     */
    private void checkForJwtLocations(IHttpRequestResponse httpRequestResponse) {
        IRequestInfo requestInfo = helpers.analyzeRequest(httpRequestResponse);
        boolean jwtFound = false;

        // Search for authorization header
        for (String header : requestInfo.getHeaders()) {
            if (header.toUpperCase().startsWith("AUTHORIZATION: BEARER")) {
                loggerInstance.log(getClass(), "Authorization HTTP Header with type bearer found.", Logger.DEBUG);
                jwtFound = checkForJwtPattern(header);
                break;
            }
        }

        if (!jwtFound) {
            // Search for (specific) parameter
            for (IParameter param : requestInfo.getParameters()) {
                if(UIPreferences.getParameterNames().contains(param.getName())) {
                    loggerInstance.log(getClass(), String.format("Possible JWT parameter found: %s.", param.getName()), Logger.DEBUG);
                    jwtFound = checkForJwtPattern(param.getValue());
                    if (jwtFound) break;
                }
            }
        }

        if (jwtFound) {
            markRequestResponse(httpRequestResponse, bundle.getString("REQUEST_RESPONSE_MARKER"));
            loggerInstance.log(getClass(), "JSON Web Token found!", Logger.DEBUG);
        }
    }

    /**
     * Checks whether given JWT candidate matches regex pattern
     * @param jwtCandidate String containing the JWT candidate value.
     * @return boolean whether regex pattern matched or not.
     */
    private boolean checkForJwtPattern(String jwtCandidate) {
        Pattern jwtPattern = Pattern.compile("(ey[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+\\.([a-zA-Z0-9\\-_]+)?([a-zA-Z0-9\\-_\\.]+)*)", Pattern.CASE_INSENSITIVE);
        Matcher jwtMatcher = jwtPattern.matcher(jwtCandidate);

        return jwtMatcher.find();
    }

    /**
     * Highlight recognized request/response and add an informational comment
     * @param httpRequestResponse {@link IHttpRequestResponse} Object containing the request/response.
     * @param message The string used as comment.
     */
    private void markRequestResponse(IHttpRequestResponse httpRequestResponse, String message) {
        httpRequestResponse.setHighlight(HIGHLIGHT_COLOR);

        // Check for existing comment and append new comment, preventing override
        final String oldComment = httpRequestResponse.getComment();
        String comment = (oldComment != null && !oldComment.isEmpty() && !Objects.equals(oldComment, message)) ? String.format("%s, %s", oldComment, message) : message;

        httpRequestResponse.setComment(comment);
    }

}
