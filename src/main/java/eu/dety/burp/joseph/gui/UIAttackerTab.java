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
package eu.dety.burp.joseph.gui;


import burp.*;

import eu.dety.burp.joseph.attacks.IAttack;
import eu.dety.burp.joseph.attacks.SignatureExclusion;
import eu.dety.burp.joseph.exceptions.AttackNotPreparedException;
import eu.dety.burp.joseph.exceptions.AttackPreparationFailedException;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Finder;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JPanel;
import java.util.*;
import org.json.JSONObject;


/**
 * Attacker tab showing a single message and related attacks
 * @author Dennis Detering
 * @version 1.0
 */
public class UIAttackerTab extends JPanel {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final Finder finder = new Finder();
    private static final Decoder joseDecoder = new Decoder();
    private List<IAttack> registeredAttacks = new ArrayList<>();
    private DefaultComboBoxModel<String> attackListModel = new DefaultComboBoxModel<>();
    private final IExtensionHelpers helpers;

    private IHttpRequestResponse requestResponse;
    private IRequestInfo requestInfo;
    private IParameter parameter = null;
    private String type = "?";
    private String algorithm = "?";

    /**
     * Register Attacks
     *
     * Method called on construction to register all available attacks.
     * Extend this method to extend with your attack.
     */
    private void registerAttacks() {
        registeredAttacks.add(new SignatureExclusion());
        loggerInstance.log(getClass(), "Attack registered: Signature Exclusion", Logger.INFO);
    }

    /**
     * UIAttackerTab constructor
     *
     * Register available attacks, extract "alg" and "typ" header fields and
     * generate attackListModel based on type and suitableness of the attack.
     *
     * @param callbacks {@link IBurpExtenderCallbacks} extender callbacks
     * @param message {@link IHttpRequestResponse} requestResponse message
     */
    public UIAttackerTab(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message) {
        // TODO: Make closable

        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);

        // Register all available attacks
        registerAttacks();

        // Find the JOSE parameter
        for (IParameter param : requestInfo.getParameters()) {
            if(UIPreferences.getParameterNames().contains(param.getName())) {
                if (finder.checkJwtPattern(param.getValue())) {
                    parameter = param;
                    break;
                }
            }
        }

        // Initialize UI components
        initComponents();

        // Parse the JOSE value to an JSONObject
        JSONObject[] joseJSONComponents = joseDecoder.getJsonComponents(parameter.getValue());


        // If the keys "alg" and "typ" exist, get their value and update informational fields
        if(joseJSONComponents[0].has("alg")) algorithm = joseJSONComponents[0].getString("alg");
        if(joseJSONComponents[0].has("typ")) type = joseJSONComponents[0].getString("typ");
        typeValue.setText(type);
        algorithmValue.setText(algorithm);

        loggerInstance.log(getClass(), "JOSE Parameter Name: " + parameter.getName(), Logger.DEBUG);
        loggerInstance.log(getClass(), "JOSE Parameter Value (JSON Parsed) " + joseJSONComponents[0].toString() + " . " + joseJSONComponents[1].toString() + " . " + joseJSONComponents[2].toString(), Logger.DEBUG);

        // Build available attacks list
        for(IAttack attack : this.registeredAttacks) {
            // If attack is suitable for given JOSE type, add it to attackListModel
            if(attack.isSuitable(type, algorithm)) {
                attackListModel.addElement(attack.getName());
            }

            /* BEGIN TMP! */
            loggerInstance.log(attack.getClass(), "Preparing attack...", Logger.DEBUG);
            try {
                attack.prepareAttack(callbacks, requestResponse, requestInfo, parameter);
            } catch (AttackPreparationFailedException e) {
                e.printStackTrace();
            }

            loggerInstance.log(attack.getClass(), "Performing attack...", Logger.DEBUG);
            try {
                attack.performAttack();
            } catch (AttackNotPreparedException e) {
                e.printStackTrace();
            }

            for(IHttpRequestResponse foo : attack.getResult()) {
                byte[] response = foo.getResponse();
                loggerInstance.log(attack.getClass(),  helpers.bytesToString(response), Logger.DEBUG);
            }
            /* END TMP */
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        typeLabel = new javax.swing.JLabel();
        attackListLabel = new javax.swing.JLabel();
        attackList = new javax.swing.JComboBox<>();
        attackButton = new javax.swing.JButton();
        algorithmLabel = new javax.swing.JLabel();
        typeValue = new javax.swing.JLabel();
        algorithmValue = new javax.swing.JLabel();

        typeLabel.setFont(new java.awt.Font("Lucida Grande", 1, 13)); // NOI18N
        typeLabel.setText("Type:");

        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("JOSEPH"); // NOI18N
        attackListLabel.setText(bundle.getString("ATTACKLISTLABEL")); // NOI18N

        attackList.setModel(attackListModel);

        attackButton.setText(bundle.getString("LOADBUTTON")); // NOI18N
        attackButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                attackButtonActionPerformed(evt);
            }
        });

        algorithmLabel.setFont(new java.awt.Font("Lucida Grande", 1, 13)); // NOI18N
        algorithmLabel.setText("Algorithm:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(typeLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(typeValue, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(algorithmLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(algorithmValue))
                    .addComponent(attackListLabel)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(attackList, javax.swing.GroupLayout.PREFERRED_SIZE, 351, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(attackButton)))
                .addContainerGap(261, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(typeLabel)
                    .addComponent(algorithmLabel)
                    .addComponent(typeValue)
                    .addComponent(algorithmValue))
                .addGap(18, 18, 18)
                .addComponent(attackListLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(attackList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(attackButton))
                .addContainerGap(206, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void attackButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_attackButtonActionPerformed
        loggerInstance.log(getClass(), "Load button clicked", Logger.DEBUG);
    }//GEN-LAST:event_attackButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel algorithmLabel;
    private javax.swing.JLabel algorithmValue;
    private javax.swing.JButton attackButton;
    private javax.swing.JComboBox<String> attackList;
    private javax.swing.JLabel attackListLabel;
    private javax.swing.JLabel typeLabel;
    private javax.swing.JLabel typeValue;
    // End of variables declaration//GEN-END:variables
}
