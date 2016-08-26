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
import burp.IHttpRequestResponse;
import burp.IHttpService;
import eu.dety.burp.joseph.attacks.BleichenbacherPkcs1.gui.BleichenbacherPkcs1AttackerResultWindow;
import eu.dety.burp.joseph.attacks.BleichenbacherPkcs1.gui.BleichenbacherPkcs1DecryptionAttackPanel;
import eu.dety.burp.joseph.attacks.BleichenbacherPkcs1.gui.BleichenbacherPkcs1TableEntry;
import eu.dety.burp.joseph.attacks.IAttack;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * Bleichenbacher PKCS1 Attack
 * <p>
 * Perform the Bleichenbacher RSA PKCS#1 v1.5
 * attack against the Content Encryption Key (CEK) of JWE
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class BleichenbacherPkcs1 implements IAttack {
    private static final Logger loggerInstance = Logger.getInstance();
    private BleichenbacherPkcs1Info attackInfo;
    private IBurpExtenderCallbacks callbacks;
    private BleichenbacherPkcs1AttackerResultWindow attackerResultWindow;
    private List<IHttpRequestResponse> responses = new ArrayList<>();
    private IHttpService httpService;

    public BleichenbacherPkcs1(IBurpExtenderCallbacks callbacks, BleichenbacherPkcs1Info attackInfo) {
        this.callbacks = callbacks;
        this.attackInfo = attackInfo;
        this.httpService = this.attackInfo.getRequestResponse().getHttpService();
    }

    @Override
    public  void performAttack() {
        // Create attacker result window
        attackerResultWindow = new BleichenbacherPkcs1AttackerResultWindow(attackInfo.getName(), callbacks);

        // Add original message to result table
        attackerResultWindow.addEntry(new BleichenbacherPkcs1TableEntry(0, -1, "", attackInfo.getRequestResponse(), callbacks));

        attackerResultWindow.addTab("Decryption Attack", new BleichenbacherPkcs1DecryptionAttackPanel());
        attackerResultWindow.setTabEnabled(1, false);


//        // Create a new PKCS1 Oracle instance
//        final BleichenbacherPkcs1Oracle oracle = new BleichenbacherPkcs1Oracle(callbacks);

        // Create new AttackExecutor thread for each prepared request
        for (BleichenbacherPkcs1AttackRequest attackRequest : this.attackInfo.getRequests()) {
            AttackExecutor attackRequestExecutor = new AttackExecutor(attackRequest);
            attackRequestExecutor.execute();
        }
    }

    /**
     * Attack Executor
     * <p>
     * Performs the actual request and updates related widgets
     */
    private class AttackExecutor extends SwingWorker<IHttpRequestResponse, Integer> {
        private BleichenbacherPkcs1AttackRequest attackRequest;

        AttackExecutor(BleichenbacherPkcs1AttackRequest attackRequest) {
            this.attackRequest = attackRequest;
        }

        @Override
        // Fire prepared request and return responses as IHttpRequestResponse
        protected IHttpRequestResponse doInBackground() {
            return callbacks.makeHttpRequest(httpService, attackRequest.getRequest());
        }

        @Override
        // Add response to response list, add new entry to attacker result window table and update process bar
        protected void done() {

            IHttpRequestResponse requestResponse;
            try {
                requestResponse = get();
            } catch (InterruptedException | ExecutionException e) {
                loggerInstance.log(BleichenbacherPkcs1.class, "Failed to get request result: " + e.getMessage(), Logger.LogLevel.ERROR);
                return;
            }

            // Add response to response list
            responses.add(requestResponse);

            // Add new entry to result table
            attackerResultWindow.addEntry(new BleichenbacherPkcs1TableEntry(responses.size(), attackRequest.getPayloadType(), attackRequest.getVectorName(), requestResponse, callbacks));

            // Update the progress bar
            attackerResultWindow.setProgressBarValue(responses.size(), attackInfo.getAmountRequests());

            loggerInstance.log(getClass(), "Attack done, amount responses: " + String.valueOf(responses.size()), Logger.LogLevel.DEBUG);
        }

    }

}
