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
package eu.dety.burp.joseph.attacks;

import burp.*;

import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Logger;

import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import javax.swing.*;

public class KeyConfusionInfo implements IAttackInfo {
    private static final Logger loggerInstance = Logger.getInstance();
    private Decoder joseDecoder;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IParameter parameter;

    // Unique identifier for the attack class
    private static final String id = "key_confusion";
    // Full name of the attack
    private static final String name = "Key Confusion";
    // Attack description
    private static final String description = "Description";
    // List of types this attack is suitable for
    private static final List<String> suitableTypes = Arrays.asList("jwt", "jws");
    // Amount of requests needed
    private static final int amountRequests = 0;

    // List of prepared requests with payload info
    private HashMap<String, byte[]> requests = new HashMap<>();

    @Override
    public KeyConfusion prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) throws AttackPreparationFailedException {
        throw new AttackPreparationFailedException("Attack not yet implemented");
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
    public List<String> getSuitableTypes() {
        return suitableTypes;
    }

    @Override
    public int getAmountRequests() {
        return amountRequests;
    }

    @Override
    public boolean getExtraUI(JPanel extraPanel) {
        GridBagConstraints constraints = new GridBagConstraints();

        // Create combobox and textarea to add public key (in different formats)
        JLabel publicKeyLabel = new JLabel("How to import public key:");
        JComboBox<String> publicKeySelection = new JComboBox<>();
        DefaultComboBoxModel<String> publicKeySelectionListModel = new DefaultComboBoxModel<>();
        JTextArea publicKey = new JTextArea(10, 35);

        publicKeySelectionListModel.addElement("PEM (String)");
        publicKeySelectionListModel.addElement("JWK (JSON)");

        publicKeySelection.setModel(publicKeySelectionListModel);

        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.gridy = 0;
        extraPanel.add(publicKeyLabel, constraints);

        constraints.gridy = 1;
        extraPanel.add(publicKeySelection, constraints);

        constraints.gridy = 2;
        extraPanel.add(publicKey, constraints);

        return true;
    }


    @Override
    public boolean isSuitable(String type, String algorithm) {
        return true;
    }

    @Override
    public IHttpRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    @Override
    public HashMap<String, byte[]> getRequests() {
        return this.requests;
    }
}
