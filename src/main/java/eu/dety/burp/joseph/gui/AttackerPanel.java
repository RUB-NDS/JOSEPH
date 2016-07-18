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

import eu.dety.burp.joseph.attacks.*;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Finder;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import java.util.*;
import org.json.JSONObject;


/**
 * Attacker panel showing a single message and related attacks
 * @author Dennis Detering
 * @version 1.0
 */
public class AttackerPanel extends JPanel {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    private HashMap<String, IAttackInfo> registeredAttacks = new HashMap<>();
    private DefaultComboBoxModel<String> attackListModel = new DefaultComboBoxModel<>();
    private IHttpRequestResponse requestResponse;
    private IRequestInfo requestInfo;
    private IParameter parameter = null;
    private String type = "?";
    private String algorithm = "?";
    private IAttackInfo selectedAttack = null;

    /**
     * Register Attacks
     * <p>
     * Method called on construction to register all available attacks.
     * Extend this method to add your custom attack.
     */
    private void registerAttacks() {
        SignatureExclusionInfo signatureExclusionInfo = new SignatureExclusionInfo();
        registeredAttacks.put(signatureExclusionInfo.getName(), signatureExclusionInfo);
        loggerInstance.log(getClass(), "Attack registered: Signature Exclusion", Logger.LogLevel.INFO);

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo();
        registeredAttacks.put(keyConfusionInfo.getName(), keyConfusionInfo);
        loggerInstance.log(getClass(), "Attack registered: Key Confusion", Logger.LogLevel.INFO);
    }

    /**
     * AttackerPanel constructor
     * <p>
     * Register available attacks, extract "alg" and "typ" header fields and
     * generate attackListModel based on type and suitableness of the attack.
     *
     * @param callbacks {@link IBurpExtenderCallbacks} extender callbacks
     * @param message {@link IHttpRequestResponse} requestResponse message
     */
    public AttackerPanel(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message) {
        Decoder joseDecoder = new Decoder();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);

        // Register all available attacks
        registerAttacks();

        // Find the JOSE parameter
        for (IParameter param : requestInfo.getParameters()) {
            if(PreferencesPanel.getParameterNames().contains(param.getName())) {
                if (Finder.checkJwtPattern(param.getValue())) {
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

        loggerInstance.log(getClass(), "JOSE Parameter Name: " + parameter.getName(), Logger.LogLevel.DEBUG);
        loggerInstance.log(getClass(), "JOSE Parameter Value (JSON Parsed) " + joseJSONComponents[0].toString() + " . "
                + joseJSONComponents[1].toString() + " . " + joseJSONComponents[2].toString(), Logger.LogLevel.DEBUG);

        // Build available attacks list
        for(Map.Entry<String, IAttackInfo> attack : this.registeredAttacks.entrySet()) {
            // If attack is suitable for given JOSE type, add it to attackListModel
            if (attack.getValue().isSuitable(type, algorithm)) {
                attackListModel.addElement(attack.getKey());
            }
        }
    }

    /**
     * Clean up attack specific UI changes
     */
    private void clearAttackSelection() {
        attackInfoName.setText("");
        attackInfoName.setEnabled(false);

        attackInfoDescription.setText("");
        attackInfoDescription.setEnabled(false);

        extraPanel.removeAll();
        extraPanel.setEnabled(false);

        attackButton.setEnabled(false);
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
        loadButton = new javax.swing.JButton();
        algorithmLabel = new javax.swing.JLabel();
        typeValue = new javax.swing.JLabel();
        algorithmValue = new javax.swing.JLabel();
        attackInfoName = new javax.swing.JLabel();
        attackInfoDescription = new javax.swing.JLabel();
        extraPanel = new javax.swing.JPanel();
        attackButton = new javax.swing.JButton();

        typeLabel.setFont(new java.awt.Font("Lucida Grande", 1, 13)); // NOI18N
        typeLabel.setText("Type:");

        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("JOSEPH"); // NOI18N
        attackListLabel.setText(bundle.getString("ATTACKLISTLABEL")); // NOI18N

        attackList.setModel(attackListModel);
        attackList.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                attackListItemStateChanged(evt);
            }
        });

        loadButton.setText(bundle.getString("LOADBUTTON")); // NOI18N
        loadButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadButtonActionPerformed(evt);
            }
        });

        algorithmLabel.setFont(new java.awt.Font("Lucida Grande", 1, 13)); // NOI18N
        algorithmLabel.setText("Algorithm:");

        attackInfoName.setFont(new java.awt.Font("Lucida Grande", 1, 13)); // NOI18N
        attackInfoName.setEnabled(false);

        attackInfoDescription.setEnabled(false);

        extraPanel.setEnabled(false);
        extraPanel.setLayout(new java.awt.GridBagLayout());

        attackButton.setText(bundle.getString("ATTACKBUTTON")); // NOI18N
        attackButton.setEnabled(false);
        attackButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                attackButtonActionPerformed(evt);
            }
        });

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
                        .addComponent(loadButton))
                    .addComponent(attackInfoName)
                    .addComponent(attackInfoDescription)
                    .addComponent(extraPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(attackButton))
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
                    .addComponent(loadButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(attackInfoName)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(attackInfoDescription)
                .addGap(18, 18, 18)
                .addComponent(extraPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(attackButton)
                .addContainerGap(120, Short.MAX_VALUE))
        );

        attackInfoName.getAccessibleContext().setAccessibleName("attackInfoName");
    }// </editor-fold>//GEN-END:initComponents

    private void loadButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadButtonActionPerformed
        loggerInstance.log(getClass(), "Load button clicked, chosen attack: " + attackListModel.getSelectedItem(), Logger.LogLevel.DEBUG);

        // Get selected Attack
        selectedAttack = registeredAttacks.get(attackListModel.getSelectedItem());

        // Set attack information
        loggerInstance.log(selectedAttack.getClass(), "Loading attack information and additional UI components...", Logger.LogLevel.DEBUG);
        attackInfoName.setText(selectedAttack.getName());
        attackInfoName.setEnabled(true);

        attackInfoDescription.setText(selectedAttack.getDescription());
        attackInfoDescription.setEnabled(true);

        // Check if attack has extra UI components and update UI
        boolean hasExtraUI = selectedAttack.getExtraUI(extraPanel);

        if(hasExtraUI) {
            extraPanel.setEnabled(true);
            extraPanel.revalidate();
            extraPanel.repaint();
        }

        // Enable attack button
        attackButton.setEnabled(true);

    }//GEN-LAST:event_loadButtonActionPerformed

    private void attackButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_attackButtonActionPerformed
        loggerInstance.log(getClass(), "Attack button clicked, prepare attack and FIRE!", Logger.LogLevel.DEBUG);

        try {
            // Prepare the selected attack
            loggerInstance.log(selectedAttack.getClass(), "Preparing attack...", Logger.LogLevel.DEBUG);
            IAttack attack = selectedAttack.prepareAttack(callbacks, requestResponse, requestInfo, parameter);

            // Perform the selected attack
            loggerInstance.log(selectedAttack.getClass(), "Performing attack...", Logger.LogLevel.DEBUG);
            attack.performAttack();
        } catch (AttackPreparationFailedException e) {
            // Show error popup with exception message
            JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), bundle.getString("ATTACK_PREPARATION_FAILED"), JOptionPane.ERROR_MESSAGE);
            loggerInstance.log(selectedAttack.getClass(), e.getMessage(), Logger.LogLevel.ERROR);
        }

    }//GEN-LAST:event_attackButtonActionPerformed

    private void attackListItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_attackListItemStateChanged
        clearAttackSelection();
    }//GEN-LAST:event_attackListItemStateChanged

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel algorithmLabel;
    private javax.swing.JLabel algorithmValue;
    private javax.swing.JButton attackButton;
    private javax.swing.JLabel attackInfoDescription;
    private javax.swing.JLabel attackInfoName;
    private javax.swing.JComboBox<String> attackList;
    private javax.swing.JLabel attackListLabel;
    private javax.swing.JPanel extraPanel;
    private javax.swing.JButton loadButton;
    private javax.swing.JLabel typeLabel;
    private javax.swing.JLabel typeValue;
    // End of variables declaration//GEN-END:variables
}
