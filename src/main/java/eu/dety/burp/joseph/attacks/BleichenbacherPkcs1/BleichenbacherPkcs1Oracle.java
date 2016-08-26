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
package eu.dety.burp.joseph.attacks.BleichenbacherPkcs1;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import eu.dety.burp.joseph.attacks.BleichenbacherPkcs1.gui.BleichenbacherPkcs1TableEntry;

import java.util.ArrayList;
import java.util.List;

import eu.dety.burp.joseph.utilities.Logger;
import org.simmetrics.StringMetric;
import org.simmetrics.metrics.StringMetrics;


public class BleichenbacherPkcs1Oracle {
    private static final Logger loggerInstance = Logger.getInstance();
    private IExtensionHelpers helpers;
    private static final double COMPARE_THRESHOLD = 0.9;


    private List<String> validResponses = new ArrayList<>();

    public enum Result {
        VALID,
        INVALID,
        UNDEFINED
    }

    public BleichenbacherPkcs1Oracle(final IBurpExtenderCallbacks callbacks, List<BleichenbacherPkcs1TableEntry> responseCandidates) {
        this.helpers = callbacks.getHelpers();

        buildResponseList(responseCandidates);
    }


    /**
     * Build a list of responses indicating PKCS1 correctness
     * @param responseCandidates List of {@link BleichenbacherPkcs1TableEntry} selected by the user as candidates
     */
    private void buildResponseList(List<BleichenbacherPkcs1TableEntry> responseCandidates) {
        outerloop:
        for (BleichenbacherPkcs1TableEntry entry : responseCandidates) {
            StringMetric metric = StringMetrics.dice();

            double tempScore;
            for (int i = 0; responseCandidates.size() > i; i++) {
                tempScore = metric.compare( helpers.bytesToString(entry.getMessage().getResponse()), validResponses.get(i) );

                // If entry score is higher than threshold, don't add new entry
                if (COMPARE_THRESHOLD <= tempScore) {
                    continue outerloop;
                }
            }

            validResponses.add(helpers.bytesToString(entry.getMessage().getResponse()));
        }
    }

}
