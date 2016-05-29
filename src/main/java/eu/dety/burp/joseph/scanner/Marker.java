package eu.dety.burp.joseph.scanner;

import burp.*;

import eu.dety.burp.joseph.utilities.Logger;
import static eu.dety.burp.joseph.utilities.ParameterUtilities.parameterListContainsParameterName;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * HTTP listener to recognize and mark JOSE parameter
 * @author Dennis Detering
 * @version 1.0
 */
public class Marker implements IHttpListener {
    private static Logger loggerInstance = Logger.getInstance();
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private static final String HIGHLIGHT_COLOR = "cyan";

    ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    // List of parameter names which might contain JSON Web STEAK content
    // TODO: Move parameter list to configuration (client)?
    private static final Set<String> PARAMETER_NAMES = new HashSet<String>(Arrays.asList(
            new String[]{"access_token", "token"}
    ));

    public Marker(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse httpRequestResponse) {
        // Only flag messages sent/received by the proxy
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            checkForJWTLocations(httpRequestResponse);
        }
    }

    /**
     * Checks whether given recognition pattern for JWT locations match
     * @param httpRequestResponse {@link IHttpRequestResponse} Object containing the request/response.
     */
    private void checkForJWTLocations(IHttpRequestResponse httpRequestResponse) {
        IRequestInfo requestInfo = helpers.analyzeRequest(httpRequestResponse);
        boolean jwtFound = false;

        for (String header : requestInfo.getHeaders()) {
            if (header.toUpperCase().startsWith("AUTHORIZATION: BEARER")) {
                loggerInstance.log(getClass(), "Authorization HTTP Header with type bearer found.", Logger.DEBUG);
                jwtFound = checkForJWTPattern(header);
                break;
            }
        }

        if (!jwtFound) {
            for (IParameter param : requestInfo.getParameters()) {
                if(parameterListContainsParameterName(requestInfo.getParameters(), param.getName())){
                    loggerInstance.log(getClass(), String.format("Possible JWT parameter found: %s.", param.getName()), Logger.DEBUG);
                    jwtFound = checkForJWTPattern(param.getValue());
                    if (jwtFound) break;
                }
            }
        }

        if (jwtFound) {
            markRequestResponse(httpRequestResponse, bundle.getString("REQUEST_RESPONSE_MARKER"));
        }
    }

    /**
     * Checks whether given JWT candidate matches regex pattern
     * @param jwtCandidate String containing the JWT candidate value.
     * @return boolean whether regex pattern matched or not.
     */
    private boolean checkForJWTPattern(String jwtCandidate) {
        Pattern jwtPattern = Pattern.compile("(ey[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+\\.([a-zA-Z0-9\\-_]+)?([a-zA-Z0-9\\-_\\.]+)*)", Pattern.CASE_INSENSITIVE);
        Matcher jwtMatcher = jwtPattern.matcher(jwtCandidate);

        return jwtMatcher.find();
    }

    /**
     * Highlight recognized response and add an informational comment
     * @param httpRequestResponse {@link IHttpRequestResponse} Object containing the request/response.
     * @param message The string used as comment.
     */
    private void markRequestResponse(IHttpRequestResponse httpRequestResponse, String message) {
        httpRequestResponse.setHighlight(HIGHLIGHT_COLOR);

        // Check for existing comment and append new comment, preventing override
        final String oldComment = httpRequestResponse.getComment();
        String comment = (oldComment != null && !oldComment.isEmpty()) ? String.format("%s, %s", oldComment, message) : message;

        httpRequestResponse.setComment(comment);
        loggerInstance.log(getClass(), String.format("Set comment: %s", message), Logger.DEBUG);
    }

}
