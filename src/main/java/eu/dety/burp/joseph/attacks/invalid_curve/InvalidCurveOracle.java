package eu.dety.burp.joseph.attacks.invalid_curve;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import eu.dety.burp.joseph.attacks.invalid_curve.gui.InvalidCurveTableEntry;
import eu.dety.burp.joseph.utilities.Logger;
import org.simmetrics.StringMetric;
import org.simmetrics.metrics.StringMetrics;

/**
 * Invalid Curve Oracle is used to compare responses if they match the valid reference.
 * 
 * @author Vincent Unsel
 * @version 1.0
 */
public class InvalidCurveOracle {
    private static final Logger loggerInstance = Logger.getInstance();
    private IExtensionHelpers helpers;
    private static final double COMPARE_THRESHOLD = 0.9;
    private StringMetric metric = StringMetrics.dice();
    private String validResponse;

    public InvalidCurveOracle(final IBurpExtenderCallbacks callbacks, InvalidCurveTableEntry responseCandidate) {
        this.helpers = callbacks.getHelpers();
        setReferenceResponse(responseCandidate);
    }

    /**
     * Set a reference responses indicating response correctness.
     * 
     * @param {@link InvalidCurveTableEntry} responseCandidate
     */
    private void setReferenceResponse(InvalidCurveTableEntry responseCandidate) {
        validResponse = helpers.bytesToString(responseCandidate.getMessage().getResponse());
    }

    /**
     * Check whether the given response is similar to the reference response.
     * 
     * @param response
     *            byte array with the response
     * @return {@link boolean} status
     */
    public boolean matchValid(byte[] response) {
        float actual = metric.compare(helpers.bytesToString(response), validResponse);
        if (actual >= COMPARE_THRESHOLD) {
            return true;
        }
        return false;
    }

}
