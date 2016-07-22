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
import java.util.Map;

/**
 * Key Confusion Attack
 * <p>
 * Perform a key confusion attack by
 * using an RSA public key as MAC secret.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class KeyConfusion extends SwingWorker<Integer, Integer> implements IAttack {
    private static final Logger loggerInstance = Logger.getInstance();
    private KeyConfusionInfo attackInfo;
    private IBurpExtenderCallbacks callbacks;
    private AttackerResultWindow attackerResultWindow;
    private List<IHttpRequestResponse> responses = new ArrayList<>();

    public KeyConfusion(IBurpExtenderCallbacks callbacks, KeyConfusionInfo attackInfo) {
        this.callbacks = callbacks;
        this.attackInfo = attackInfo;
    }

    @Override
    public  void performAttack() {
        // Create attacker result window
        attackerResultWindow = new AttackerResultWindow(attackInfo.getName(), callbacks);

        // Add original message to result table
        attackerResultWindow.addEntry(new TableEntry(0, -1, "", attackInfo.getRequestResponse(), callbacks));

        this.execute();
    }

    @Override
    protected Integer doInBackground() throws Exception {
        IHttpService httpService = this.attackInfo.getRequestResponse().getHttpService();

        // Fire each prepared request and store responses in IHttpRequestResponse list
        for (KeyConfusionAttackRequest attackRequest : this.attackInfo.getRequests()) {
            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(httpService, attackRequest.getRequest());
            this.responses.add(requestResponse);

            String payload = "Alg: " + attackRequest.getAlgorithm() + " KeyLen: " + attackRequest.getKeyLength();

            // Add new entry to result table
            attackerResultWindow.addEntry(new TableEntry(this.responses.size(), attackRequest.getPayloadType(), payload, requestResponse, callbacks));

            // Update the progress bar
            attackerResultWindow.setPrograssBarValue(responses.size(), attackInfo.getAmountRequests());
        }
        return null;
    }

    @Override
    protected void done() {
        loggerInstance.log(getClass(), "Attack done, amount responses: " + String.valueOf(responses.size()), Logger.LogLevel.DEBUG);
    }
}
