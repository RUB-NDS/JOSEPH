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
package eu.dety.burp.joseph.attacks.KeyConfusion;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import eu.dety.burp.joseph.attacks.IAttack;
import eu.dety.burp.joseph.gui.AttackerResultWindow;
import eu.dety.burp.joseph.gui.table.TableEntry;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * Key Confusion Attack
 * <p>
 * Perform a key confusion attack by using an RSA public key as MAC secret.
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class KeyConfusion implements IAttack {
    private static final Logger loggerInstance = Logger.getInstance();
    private KeyConfusionInfo attackInfo;
    private IBurpExtenderCallbacks callbacks;
    private AttackerResultWindow attackerResultWindow;
    private List<IHttpRequestResponse> responses = new ArrayList<>();
    private IHttpService httpService;

    public KeyConfusion(IBurpExtenderCallbacks callbacks, KeyConfusionInfo attackInfo) {
        this.callbacks = callbacks;
        this.attackInfo = attackInfo;
        this.httpService = this.attackInfo.getRequestResponse().getHttpService();
    }

    @Override
    public void performAttack() {
        // Create attacker result window
        attackerResultWindow = new AttackerResultWindow(attackInfo.getName(), callbacks);

        // Add original message to result table
        attackerResultWindow.addEntry(new TableEntry(0, -1, "", attackInfo.getRequestResponse(), callbacks));

        // Create new AttackExecutor thread for each prepared request
        for (KeyConfusionAttackRequest attackRequest : this.attackInfo.getRequests()) {
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
        private KeyConfusionAttackRequest attackRequest;

        AttackExecutor(KeyConfusionAttackRequest attackRequest) {
            this.attackRequest = attackRequest;
        }

        @Override
        // Fire prepared request and return responses as IHttpRequestResponse
        protected IHttpRequestResponse doInBackground() {
            return callbacks.makeHttpRequest(httpService, attackRequest.getRequest());
        }

        @Override
        // Add response to response list, add new entry to attacker result
        // window table and update process bar
        protected void done() {

            IHttpRequestResponse requestResponse;
            try {
                requestResponse = get();
            } catch (InterruptedException | ExecutionException e) {
                loggerInstance.log(KeyConfusion.class, "Failed to get request result: " + e.getMessage(),
                        Logger.LogLevel.ERROR);
                return;
            }

            // Add response to response list
            responses.add(requestResponse);

            // Add new entry to result table
            String payload = "Alg: " + attackRequest.getAlgorithm() + " KeyLen: " + attackRequest.getKeyLength();
            attackerResultWindow.addEntry(new TableEntry(responses.size(), attackRequest.getPayloadType(), payload,
                    requestResponse, callbacks));

            // Update the progress bar
            attackerResultWindow.setProgressBarValue(responses.size(), attackInfo.getAmountRequests());

            loggerInstance.log(getClass(), "Attack done, amount responses: " + String.valueOf(responses.size()),
                    Logger.LogLevel.DEBUG);
        }

    }

}
