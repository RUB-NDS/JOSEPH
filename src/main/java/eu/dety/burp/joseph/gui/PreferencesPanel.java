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

import eu.dety.burp.joseph.utilities.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Preference tab to customize some behaviour
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class PreferencesPanel extends javax.swing.JPanel {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final String configFilePath = System.getProperty("user.home") + "/.joseph/config.json";

    // Configuration options
    private static int logLevel = 1;
    private static boolean highlighting = true;
    private static final List<String> defaultParameterNames = Arrays.asList("access_token", "id_token", "token", "Authorization", "payload");

    private static DefaultListModel<String> parameterNamesListModel = new DefaultListModel<>();

    public PreferencesPanel() {
        initComponents();

        // Set ListModel for parameterNamesList
        parameterNamesList.setModel(parameterNamesListModel);
        // Add default parameter
        for (String param : defaultParameterNames) {
            parameterNamesListModel.addElement(param);
        }

        // Load or create config file
        try {
            File configFile = new File(configFilePath);

            // Check if directory exists, if not create it
            if (!configFile.getParentFile().exists()) {
                loggerInstance.log(getClass(), "Config file directory not found! Creating it...", Logger.LogLevel.DEBUG);
                configFile.getParentFile().mkdir();
            }

            // Check if config file exists, if not create it
            if (!configFile.exists()) {
                loggerInstance.log(getClass(), "Config file not found! Creating it...", Logger.LogLevel.DEBUG);
                configFile.createNewFile();
                saveConfig();

                // Update UI elements
                logLevelCombo.setSelectedIndex(getLogLevel());
                highlightCheckbox.setSelected(getHighlighting());
                parameterNamesListModel.clear();
                for (String param : defaultParameterNames) {
                    parameterNamesListModel.addElement(param);
                }

            } else {
                loggerInstance.log(getClass(), "Loading config file.", Logger.LogLevel.DEBUG);
                loadConfig();
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, e.toString(), "Error loading config file", JOptionPane.ERROR_MESSAGE);
            loggerInstance.log(getClass(), e.toString(), Logger.LogLevel.ERROR);
        }
    }

    /**
     * Get the log level 0 = ERROR, 1 = INFO, 2 = DEBUG
     *
     * @return The Log level.
     */
    public static int getLogLevel() {
        return logLevel;
    }

    /**
     * Set the logging level 0 = ERROR, 1 = INFO, 2 = DEBUG
     */
    private void setLogLevel(int logLvl) {
        logLevel = logLvl;
    }

    /**
     * Get the highlighting option value
     *
     * @return The highlighting option value.
     */
    public static boolean getHighlighting() {
        return highlighting;
    }

    /**
     * Set the highlighting option
     */
    private void setHighlighting(boolean highlight) {
        highlighting = highlight;
    }

    /**
     * Get the parameter names
     *
     * @return The parameter names string list.
     */
    public static List<Object> getParameterNames() {
        return Arrays.asList(parameterNamesListModel.toArray());
    }

    /**
     * Save all configurations to the system.
     */
    @SuppressWarnings("unchecked")
    private void saveConfig() {
        File configFile = new File(configFilePath);

        if (!configFile.exists()) {
            loggerInstance.log(getClass(), "Config file does not exist!", Logger.LogLevel.ERROR);
            return;
        }

        if (!configFile.isDirectory() && configFile.canWrite()) {

            JSONObject configObj = new JSONObject();
            configObj.put("logLevel", getLogLevel());
            configObj.put("highlighting", getHighlighting());
            configObj.put("parameterNames", getParameterNames());

            try {
                FileWriter configFileWriter = new FileWriter(configFile);

                try {
                    configFileWriter.write(configObj.toJSONString());
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(this, "The config file can not be written!\n\nError:\n" + e.toString(), "Error writing config file",
                            JOptionPane.ERROR_MESSAGE);
                    loggerInstance.log(getClass(), "Config file can not be written!\n" + e.toString(), Logger.LogLevel.ERROR);
                }

                configFileWriter.flush();
                configFileWriter.close();
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "The config file can not be written!\n\nError:\n" + e.toString(), "Error writing config file",
                        JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "Config file can not be written!\n" + e.toString(), Logger.LogLevel.ERROR);
            } catch (Exception e) {
                loggerInstance.log(getClass(), e.toString(), Logger.LogLevel.ERROR);
            }

        } else {
            JOptionPane.showMessageDialog(this, "The config file is not writable: " + configFilePath, "Error writing config file", JOptionPane.ERROR_MESSAGE);
            loggerInstance.log(getClass(), "Config file is not writable: " + configFilePath, Logger.LogLevel.ERROR);
        }
    }

    /**
     * Load the configuration file and apply values to the UI.
     */
    @SuppressWarnings("unchecked")
    private void loadConfig() {
        File configFile = new File(configFilePath);

        if (!configFile.exists()) {
            loggerInstance.log(getClass(), "Config file does not exist!", Logger.LogLevel.ERROR);
            return;
        }

        if (!configFile.isDirectory() && configFile.canRead()) {

            JSONParser jsonParser = new JSONParser();

            try {
                FileReader configFileReader = new FileReader(configFile);
                JSONObject configObj = (JSONObject) jsonParser.parse(configFileReader);

                setLogLevel(((Long) configObj.get("logLevel")).intValue());
                logLevelCombo.setSelectedIndex(getLogLevel());

                setHighlighting(((boolean) configObj.get("highlighting")));
                highlightCheckbox.setSelected(getHighlighting());

                parameterNamesListModel.clear();
                for (String param : (List<String>) configObj.get("parameterNames")) {
                    parameterNamesListModel.addElement(param);
                }

            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "The config file can not be read!\n\nError:\n" + e.toString(), "Error reading config file",
                        JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "Config file can not be read!\n" + e.toString(), Logger.LogLevel.ERROR);
            } catch (ParseException e) {
                JOptionPane.showMessageDialog(this, "The config file can not be parsed!\n\nError:\n" + e.toString(), "Error parsing config file",
                        JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "Config file can not be parsed!\n" + e.toString(), Logger.LogLevel.ERROR);
            } catch (NullPointerException e) {
                JOptionPane.showMessageDialog(this, "The config file needs to contain all option values!\n\nError:\n" + e.toString(),
                        "Error parsing config file", JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "The config file needs to contain any option values!\n" + e.toString(), Logger.LogLevel.ERROR);
            } catch (Exception e) {
                loggerInstance.log(getClass(), e.toString(), Logger.LogLevel.ERROR);
            }

        } else {
            JOptionPane.showMessageDialog(this, "The config file is not readable or a directory: " + configFilePath, "Config file not readable",
                    JOptionPane.ERROR_MESSAGE);
            loggerInstance.log(getClass(), "The config file is not readable or a directory: " + configFilePath, Logger.LogLevel.ERROR);
        }
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The content of this
     * method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed"
    // desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        loggingHeadlineLabel = new javax.swing.JLabel();
        jSeparator1 = new javax.swing.JSeparator();
        logLevelCombo = new javax.swing.JComboBox<>();
        logLevelLabel = new javax.swing.JLabel();
        highlightCheckbox = new javax.swing.JCheckBox();
        jSeparator2 = new javax.swing.JSeparator();
        parameterNamesHelp = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        parameterNamesList = new javax.swing.JList<>();
        parameterNamesTextField = new javax.swing.JTextField();
        parameterNamesAddButton = new javax.swing.JButton();
        parameterNamesRemoveButton = new javax.swing.JButton();
        saveConfigButton = new javax.swing.JButton();

        setFont(new java.awt.Font("Lucida Grande", 0, 12)); // NOI18N

        loggingHeadlineLabel.setFont(new java.awt.Font("Lucida Grande", Font.BOLD, 13)); // NOI18N
        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("JOSEPH"); // NOI18N
        loggingHeadlineLabel.setText(bundle.getString("LOGGING_HEADLINE")); // NOI18N
        loggingHeadlineLabel.setName("loggingHeadlineLabel"); // NOI18N

        logLevelCombo.setFont(new java.awt.Font("Lucida Grande", 0, 12)); // NOI18N
        logLevelCombo.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "ERROR", "INFO", "DEBUG" }));
        logLevelCombo.setName("logLevelCombo"); // NOI18N
        logLevelCombo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logLevelComboActionPerformed(evt);
            }
        });

        logLevelLabel.setFont(new java.awt.Font("Lucida Grande", 0, 12)); // NOI18N
        logLevelLabel.setText(bundle.getString("LOGLEVEL")); // NOI18N
        logLevelLabel.setName("logLevelLabel"); // NOI18N

        highlightCheckbox.setFont(new java.awt.Font("Lucida Grande", Font.BOLD, 13)); // NOI18N
        highlightCheckbox.setText(bundle.getString("HIGHLIGHTING")); // NOI18N
        highlightCheckbox.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        highlightCheckbox.setName("highlightCheckbox"); // NOI18N
        highlightCheckbox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                highlightCheckboxActionPerformed(evt);
            }
        });

        parameterNamesHelp.setFont(new java.awt.Font("Lucida Grande", 0, 12)); // NOI18N
        parameterNamesHelp.setText(bundle.getString("PARAMETER_NAMES_LABEL")); // NOI18N
        parameterNamesHelp.setName("parameterNamesHelp"); // NOI18N

        parameterNamesList.setModel(parameterNamesListModel);
        parameterNamesList.setName("parameterNamesList"); // NOI18N
        jScrollPane1.setViewportView(parameterNamesList);

        parameterNamesTextField.setName("parameterNamesTextField"); // NOI18N
        parameterNamesTextField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                parameterNamesTextFieldKeyPressed(evt);
            }
        });

        parameterNamesAddButton.setText(bundle.getString("ADD")); // NOI18N
        parameterNamesAddButton.setName("parameterNamesAddButton"); // NOI18N
        parameterNamesAddButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                parameterNamesAddButtonActionPerformed(evt);
            }
        });

        parameterNamesRemoveButton.setText(bundle.getString("REMOVE")); // NOI18N
        parameterNamesRemoveButton.setName("parameterNamesRemoveButton"); // NOI18N
        parameterNamesRemoveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                parameterNamesRemoveButtonActionPerformed(evt);
            }
        });

        saveConfigButton.setText(bundle.getString("SAVE_CONFIGURATION")); // NOI18N
        saveConfigButton.setName("saveConfigButton"); // NOI18N
        saveConfigButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveConfigButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(layout
                .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jSeparator1)
                .addComponent(jSeparator2)
                .addGroup(
                        layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(
                                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                .addGroup(
                                                        layout.createSequentialGroup()
                                                                .addGroup(
                                                                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                                                .addGroup(
                                                                                        layout.createSequentialGroup()
                                                                                                .addComponent(logLevelLabel)
                                                                                                .addPreferredGap(
                                                                                                        javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                                .addComponent(logLevelCombo,
                                                                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                        javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                .addComponent(parameterNamesHelp)
                                                                                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 350,
                                                                                        Short.MAX_VALUE).addComponent(parameterNamesTextField))
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                .addGroup(
                                                                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                                                .addComponent(parameterNamesRemoveButton, javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                        javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                                                .addComponent(parameterNamesAddButton, javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                        javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                                                .addComponent(saveConfigButton).addComponent(highlightCheckbox).addComponent(loggingHeadlineLabel))
                                .addContainerGap(221, Short.MAX_VALUE)));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(
                        layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(loggingHeadlineLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(
                                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                .addComponent(logLevelLabel)
                                                .addComponent(logLevelCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addComponent(highlightCheckbox)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(parameterNamesHelp)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(
                                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGroup(
                                                        layout.createSequentialGroup().addComponent(parameterNamesAddButton)
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                .addComponent(parameterNamesRemoveButton)))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(parameterNamesTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
                                        javax.swing.GroupLayout.PREFERRED_SIZE).addGap(18, 18, 18).addComponent(saveConfigButton)
                                .addContainerGap(135, Short.MAX_VALUE)));
    }// </editor-fold>//GEN-END:initComponents

    private void saveConfigButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_saveConfigButtonActionPerformed
        saveConfig();
    }// GEN-LAST:event_saveConfigButtonActionPerformed

    private void parameterNamesAddButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_parameterNamesAddButtonActionPerformed
        String newParameter = parameterNamesTextField.getText();

        if (!newParameter.equals("")) {
            parameterNamesListModel.addElement(newParameter);
            parameterNamesTextField.setText("");
        }
    }// GEN-LAST:event_parameterNamesAddButtonActionPerformed

    private void parameterNamesRemoveButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_parameterNamesRemoveButtonActionPerformed
        for (int paramIndex : parameterNamesList.getSelectedIndices()) {
            parameterNamesListModel.removeElementAt(paramIndex);
        }
    }// GEN-LAST:event_parameterNamesRemoveButtonActionPerformed

    private void parameterNamesTextFieldKeyPressed(java.awt.event.KeyEvent evt) {// GEN-FIRST:event_parameterNamesTextFieldKeyPressed
        if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
            String newParameter = parameterNamesTextField.getText();

            if (!newParameter.equals("")) {
                parameterNamesListModel.addElement(newParameter);
                parameterNamesTextField.setText("");
            }
        }
    }// GEN-LAST:event_parameterNamesTextFieldKeyPressed

    private void logLevelComboActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_logLevelComboActionPerformed
        int logLevel = logLevelCombo.getSelectedIndex();
        setLogLevel(logLevel);
    }// GEN-LAST:event_logLevelComboActionPerformed

    private void highlightCheckboxActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_highlightCheckboxActionPerformed
        boolean highlighting = highlightCheckbox.isSelected();
        setHighlighting(highlighting);
    }// GEN-LAST:event_highlightCheckboxActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox highlightCheckbox;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JComboBox<String> logLevelCombo;
    private javax.swing.JLabel logLevelLabel;
    private javax.swing.JLabel loggingHeadlineLabel;
    private javax.swing.JButton parameterNamesAddButton;
    private javax.swing.JLabel parameterNamesHelp;
    private javax.swing.JList<String> parameterNamesList;
    private javax.swing.JButton parameterNamesRemoveButton;
    private javax.swing.JTextField parameterNamesTextField;
    private javax.swing.JButton saveConfigButton;
    // End of variables declaration//GEN-END:variables
}
