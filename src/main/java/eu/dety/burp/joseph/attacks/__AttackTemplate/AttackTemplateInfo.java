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
package eu.dety.burp.joseph.attacks.__AttackTemplate;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.attacks.IAttackInfo;
import eu.dety.burp.joseph.utilities.JoseParameter;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Attack Template Attack Info
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class AttackTemplateInfo implements IAttackInfo {
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private JoseParameter parameter;

    // Unique identifier for the attack class
    private static final String id = "attack_template";

    // Full name of the attack
    private static final String name = "Attack Template";

    // Attack description
    private static final String description = "<html>The <em>Attack Template</em> attack description...</html>";

    // Hashmap of available payloads with a verbose name (including the
    // PayloadType)
    private static final HashMap<String, PayloadType> payloads = new HashMap<>();
    static {
        /*
         * ADD YOUR ATTACK PAYLOADS HERE
         */
    }

    // Amount of requests needed
    private static final int amountRequests = 0;

    // Types of payload variation
    enum PayloadType {
        /*
         * ADD YOUR PAYLOAD TYPES HERE
         */
    }

    // List of AttackTemplateAttackRequest objects holding prepared attack
    // requests
    private List<AttackTemplateAttackRequest> requests = new ArrayList<>();

    public AttackTemplateInfo(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public AttackTemplate prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo,
            JoseParameter parameter) throws AttackPreparationFailedException {
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        this.requests.clear();

        try {
            /*
             * ADD YOUR ATTACK PREPARATION LOGIC HERE
             */
        } catch (Exception e) {
            throw new AttackPreparationFailedException("Attack preparation failed. Message: " + e.getMessage());
        }

        return new AttackTemplate(callbacks, this);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public int getAmountRequests() {
        return amountRequests;
    }

    @Override
    public boolean getExtraUI(JPanel extraPanel, GridBagConstraints constraints) {
        /*
         * CHANGE IF EXTRA UI IS NEEDED
         */
        return false;
    }

    @Override
    public boolean isSuitable(JoseParameter.JoseType type, String algorithm) {
        /*
         * CHANGE TO CHECK SUITABILITY
         */
        return true;
    }

    @Override
    public IHttpRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    @Override
    public List<AttackTemplateAttackRequest> getRequests() {
        return this.requests;
    }

    @Override
    public HashMap<String, PayloadType> getPayloadList() {
        return payloads;
    }

    @Override
    public HashMap<String, String> updateValuesByPayload(Enum payloadTypeId, String header, String payload, String signature) {
        HashMap<String, String> result = new HashMap<>();

        /*
         * ADD YOUR ATTACK PAYLOAD LOGIC HERE
         */

        return result;
    }

}
