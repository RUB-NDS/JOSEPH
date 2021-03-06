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
package eu.dety.burp.joseph.gui;

import burp.IBurpExtenderCallbacks;
import eu.dety.burp.joseph.attacks.AttackLoader;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.attacks.IAttackInfo;
import eu.dety.burp.joseph.utilities.*;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

public class ManualPanel extends javax.swing.JPanel {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    private HashMap<String, IAttackInfo> registeredAttacks = new HashMap<>();
    private DefaultComboBoxModel<String> attackListModel = new DefaultComboBoxModel<>();
    private IAttackInfo selectedAttack = null;

    private HashMap<String, ? extends Enum> payloads;
    private JComboBox<String> payloadSelection = new JComboBox<>();
    private DefaultComboBoxModel<String> payloadSelectionListModel = new DefaultComboBoxModel<>();

    private JoseParameter joseValue = null;

    ManualPanel(IBurpExtenderCallbacks callbacks) {
        // Register all available attacks
        registeredAttacks = AttackLoader.getRegisteredAttackInstances(callbacks);

        initComponents();

        jScrollPane2.setVisible(false);
        outputValue.setVisible(false);
        attackList.setVisible(false);
        loadAttackButton.setVisible(false);
        updateButton.setVisible(false);
    }

    /**
     * Update the attack list
     */
    public void updateAttackList() {
        attackListModel.removeAllElements();

        String algorithm = null;

        // If the keys "alg" and "typ" exist, get their value and update
        // informational fields
        JSONObject headerJson = Decoder.getJsonComponents(this.joseValue.getJoseValue())[0];
        if (headerJson.has("alg"))
            algorithm = headerJson.getString("alg");

        // Build available attacks list
        for (Map.Entry<String, IAttackInfo> attack : this.registeredAttacks.entrySet()) {
            // If attack is suitable for given JOSE type, add it to
            // attackListModel
            if (attack.getValue().isSuitable(this.joseValue.getJoseType(), algorithm)) {
                attackListModel.addElement(attack.getKey());
            }
        }
    }

    /**
     * Clean up attack specific UI changes
     */
    private void clearAttackSelection() {
        extraPanel.removeAll();
        extraPanel.revalidate();
        extraPanel.repaint();
        extraPanel.setEnabled(false);

        payloadSelectionListModel.removeAllElements();

        jScrollPane2.setVisible(false);
        outputValue.setVisible(false);
        outputValue.setText("");
        updateButton.setVisible(false);
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The content of this
     * method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed"
    // desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        inputLabel = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        inputValue = new javax.swing.JTextArea();
        loadJoseButton = new javax.swing.JButton();
        attackList = new javax.swing.JComboBox<>();
        loadAttackButton = new javax.swing.JButton();
        extraPanel = new javax.swing.JPanel();
        updateButton = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        outputValue = new javax.swing.JTextArea();

        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("JOSEPH"); // NOI18N
        inputLabel.setText(bundle.getString("JOSE_INPUT_LABEL")); // NOI18N

        inputValue.setColumns(20);
        inputValue.setRows(5);
        jScrollPane1.setViewportView(inputValue);

        loadJoseButton.setText(bundle.getString("LOADBUTTON")); // NOI18N
        loadJoseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadJoseButtonActionPerformed(evt);
            }
        });

        attackList.setModel(attackListModel);
        attackList.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                attackListItemStateChanged(evt);
            }
        });

        loadAttackButton.setText(bundle.getString("LOADBUTTON")); // NOI18N
        loadAttackButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadAttackButtonActionPerformed(evt);
            }
        });

        extraPanel.setEnabled(false);
        extraPanel.setLayout(new java.awt.GridBagLayout());

        updateButton.setText(bundle.getString("UPDATEBUTTON")); // NOI18N
        updateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                updateButtonActionPerformed(evt);
            }
        });

        outputValue.setEditable(false);
        outputValue.setColumns(20);
        outputValue.setRows(5);
        jScrollPane2.setViewportView(outputValue);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(
                                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 790, Short.MAX_VALUE)
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addGroup(
                                                                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                                        .addComponent(extraPanel, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                        .addComponent(inputLabel)
                                                                        .addComponent(loadJoseButton)
                                                                        .addGroup(
                                                                                layout.createSequentialGroup()
                                                                                        .addComponent(attackList, javax.swing.GroupLayout.PREFERRED_SIZE, 351,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                        .addComponent(loadAttackButton)).addComponent(updateButton))
                                                        .addGap(0, 0, Short.MAX_VALUE)).addComponent(jScrollPane2)).addContainerGap()));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(inputLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
                                javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(loadJoseButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(
                                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(attackList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE).addComponent(loadAttackButton))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(extraPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
                                javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(updateButton)
                        .addGap(18, 18, 18)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
                                javax.swing.GroupLayout.PREFERRED_SIZE).addContainerGap(96, Short.MAX_VALUE)));
    }// </editor-fold>//GEN-END:initComponents

    private void attackListItemStateChanged(java.awt.event.ItemEvent evt) {// GEN-FIRST:event_attackListItemStateChanged
        clearAttackSelection();
    }// GEN-LAST:event_attackListItemStateChanged

    private void loadAttackButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_loadAttackButtonActionPerformed
        loggerInstance.log(getClass(), "Load button clicked, chosen attack: " + attackListModel.getSelectedItem(), Logger.LogLevel.DEBUG);

        clearAttackSelection();

        // Get selected Attack
        selectedAttack = registeredAttacks.get(attackListModel.getSelectedItem());

        // Set attack information
        loggerInstance.log(selectedAttack.getClass(), "Loading attack information and additional UI components...", Logger.LogLevel.DEBUG);

        // Check if attack has extra UI components and update UI
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        selectedAttack.getExtraUI(extraPanel, constraints);

        payloads = selectedAttack.getPayloadList();

        payloadSelection.setPreferredSize(new Dimension(350, 25));

        for (Map.Entry<String, ? extends Enum> payload : payloads.entrySet()) {
            payloadSelectionListModel.addElement(payload.getKey());
        }

        payloadSelection.setModel(payloadSelectionListModel);

        constraints.gridy++;
        extraPanel.add(new JLabel(bundle.getString("CHOOSE_PAYLOAD")), constraints);

        constraints.gridy++;
        extraPanel.add(payloadSelection, constraints);

        extraPanel.setEnabled(true);
        extraPanel.revalidate();
        extraPanel.repaint();

        // Enable attack button
        updateButton.setVisible(true);

    }// GEN-LAST:event_loadAttackButtonActionPerformed

    private void loadJoseButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_loadJoseButtonActionPerformed
        loggerInstance.log(getClass(), "Load JOSE button clicked!", Logger.LogLevel.DEBUG);

        String inputValueText = inputValue.getText();

        if (!inputValueText.isEmpty()) {
            try {
                joseValue = new JoseParameter(Finder.getJoseValue(inputValueText));
            } catch (InvalidJoseValueException e) {
                JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), bundle.getString("INVALID_JOSE_VALUE").toUpperCase(), JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(selectedAttack.getClass(), "ERROR: " + e.getMessage(), Logger.LogLevel.ERROR);
                return;
            }

            updateAttackList();

            attackList.setVisible(true);
            loadAttackButton.setVisible(true);
        }
    }// GEN-LAST:event_loadJoseButtonActionPerformed

    private void updateButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_updateButtonActionPerformed
        loggerInstance.log(getClass(), "Update button clicked, modify request!", Logger.LogLevel.DEBUG);

        if (joseValue.getJoseType().equals(JoseParameter.JoseType.JWS)) {
            String[] components = joseValue.getComponents();

            String header = Decoder.getDecoded(components[0]);
            String payload = Decoder.getDecoded(components[1]);
            String signature = components[2];

            try {
                loggerInstance.log(selectedAttack.getClass(), "Selected payload: " + payloadSelectionListModel.getSelectedItem(), Logger.LogLevel.DEBUG);
                HashMap<String, String> updatedValues = selectedAttack.updateValuesByPayload(payloads.get(payloadSelectionListModel.getSelectedItem()), header,
                        payload, signature);

                loggerInstance.log(selectedAttack.getClass(), "Values: " + updatedValues.get("header") + "; " + updatedValues.get("payload") + "; "
                        + updatedValues.get("signature"), Logger.LogLevel.DEBUG);

                String output = Decoder.concatComponents(new String[] { Decoder.base64UrlEncode(updatedValues.get("header").getBytes()),
                        Decoder.base64UrlEncode(updatedValues.get("payload").getBytes()), updatedValues.get("signature") });

                outputValue.setText(output);
                jScrollPane2.setVisible(true);
                outputValue.setVisible(true);

                revalidate();
                repaint();

            } catch (AttackPreparationFailedException e) {
                // Show error popup with exception message
                JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), bundle.getString("ATTACK_PREPARATION_FAILED"), JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(selectedAttack.getClass(), e.getMessage(), Logger.LogLevel.ERROR);
            }
        } else {
            JOptionPane.showMessageDialog(new JFrame(), bundle.getString("NOT_YET_SUPPORTED_MSG"), bundle.getString("NOT_YET_SUPPORTED"),
                    JOptionPane.ERROR_MESSAGE);
            loggerInstance.log(selectedAttack.getClass(), bundle.getString("NOT_YET_SUPPORTED_MSG"), Logger.LogLevel.ERROR);
        }

    }// GEN-LAST:event_updateButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox<String> attackList;
    private javax.swing.JPanel extraPanel;
    private javax.swing.JLabel inputLabel;
    private javax.swing.JTextArea inputValue;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JButton loadAttackButton;
    private javax.swing.JButton loadJoseButton;
    private javax.swing.JTextArea outputValue;
    private javax.swing.JButton updateButton;
    // End of variables declaration//GEN-END:variables
}
