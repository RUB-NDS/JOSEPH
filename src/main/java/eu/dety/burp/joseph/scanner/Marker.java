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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import eu.dety.burp.joseph.gui.PreferencesPanel;
import eu.dety.burp.joseph.utilities.Logger;
import eu.dety.burp.joseph.utilities.Finder;

import java.util.Objects;
import java.util.ResourceBundle;


/**
 * HTTP listener to recognize and mark JOSE parameter
 * @author Dennis Detering
 * @version 1.0
 */
public class Marker implements IHttpListener {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");
    private final IExtensionHelpers helpers;

    private static final String HIGHLIGHT_COLOR = "cyan";

    public Marker(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse httpRequestResponse) {
        // Only flag messages if highlighting option is set to true and if sent/received by the proxy
        if (PreferencesPanel.getHighlighting() && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            checkForJoseLocations(httpRequestResponse);
        }
    }

    /**
     * Checks whether given recognition pattern for JWT locations match
     * @param httpRequestResponse {@link IHttpRequestResponse} Object containing the request/response.
     */
    private void checkForJoseLocations(IHttpRequestResponse httpRequestResponse) {
        IRequestInfo requestInfo = helpers.analyzeRequest(httpRequestResponse);
        boolean jwtFound = false;
        boolean jweFound = false;

        // Search for authorization header
        for (String header : requestInfo.getHeaders()) {
            if (header.toUpperCase().startsWith("AUTHORIZATION: BEARER")) {
                loggerInstance.log(getClass(), "Authorization HTTP HEADER with type bearer found.", Logger.LogLevel.DEBUG);
                jwtFound = Finder.checkJwtPattern(header);
                jweFound = Finder.checkJwePattern(header);
                break;
            }
        }

        if (!jwtFound && !jweFound) {
            // Search for (specific) parameter
            for (IParameter param : requestInfo.getParameters()) {
                if(PreferencesPanel.getParameterNames().contains(param.getName())) {
                    loggerInstance.log(getClass(), String.format("Possible JOSE parameter found: %s.", param.getName()), Logger.LogLevel.DEBUG);
                    jwtFound = Finder.checkJwtPattern(param.getValue());
                    jweFound = Finder.checkJwePattern(param.getValue());

                    if (jwtFound || jweFound) break;
                }
            }
        }

        if (jwtFound) {
            markRequestResponse(httpRequestResponse, bundle.getString("JWT"));
            loggerInstance.log(getClass(), "JSON Web Token found!", Logger.LogLevel.DEBUG);
        }

        if (jweFound) {
            markRequestResponse(httpRequestResponse, bundle.getString("JWE"));
            loggerInstance.log(getClass(), "JSON Web Encryption found!", Logger.LogLevel.DEBUG);
        }
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

    /**
     * Get highlight color
     * @return Get the highlight color constant.
     */
    public static String getHighlightColor() {
        return HIGHLIGHT_COLOR;
    }

}
