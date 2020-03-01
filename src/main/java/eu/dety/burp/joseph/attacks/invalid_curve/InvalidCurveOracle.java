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
    private double compareThreshold = 0.9;
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
        if (actual >= compareThreshold) {
            return true;
        }
        return false;
    }

    public void setThreshold(double threshold) {
        this.compareThreshold = threshold;
        loggerInstance.log(getClass(), "Changed compare threshold.", Logger.LogLevel.DEBUG);
    }

}
