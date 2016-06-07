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
/*
 * Created by JFormDesigner on Sun May 29 18:55:01 CEST 2016
 */

package eu.dety.burp.joseph.gui;

import java.awt.*;
import java.awt.event.*;
import eu.dety.burp.joseph.utilities.Logger;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import javax.swing.*;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * Preference tab to customize some behaviour
 * @author Dennis Detering
 * @version 1.0
 */
public class UIPreferences extends JPanel {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final String configFilePath = System.getProperty("user.home") + "/.joseph/config.json";

    // Configuration options
    private static int logLevel = 2;
    private static boolean highlighting = true;
    private static final List<String> defaultParameterNames = Arrays.asList("access_token", "token");

    private static DefaultListModel<String> parameterNamesListModel = new DefaultListModel<>();

    @SuppressWarnings("unchecked")
    UIPreferences() {
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
                loggerInstance.log(getClass(), "Config file directory not found! Creating it...", Logger.DEBUG);
                configFile.getParentFile().mkdir();
            }

            // Check if config file exists, if not create it
            if (!configFile.exists()) {
                loggerInstance.log(getClass(), "Config file not found! Creating it...", Logger.DEBUG);
                configFile.createNewFile();
                saveConfig();
            } else {
                loggerInstance.log(getClass(), "Loading config file.", Logger.DEBUG);
                loadConfig();
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, e.toString(), "Error loading config file", JOptionPane.ERROR_MESSAGE);
            loggerInstance.log(getClass(), e.toString(), Logger.ERROR);
        }
    }

    /**
     * Get the log level
     * 0 = ERROR, 1 = INFO, 2 = DEBUG
     * @return The Log level.
     */
    public static int getLogLevel(){
        return logLevel;
    }

    /**
     * Set the logging level
     * 0 = ERROR, 1 = INFO, 2 = DEBUG
     */
    private void setLogLevel(int logLvl){
        logLevel = logLvl;
    }

    /**
     * Get the highlighting option value
     * @return The highlighting option value.
     */
    public static boolean getHighlighting(){
        return highlighting;
    }

    /**
     * Set the highlighting option
     */
    private void setHighlighting(boolean highlight){
        highlighting = highlight;
    }

    /**
     * Get the parameter names
     * @return The parameter names string list.
     */
    public static List<Object> getParameterNames(){
        return Arrays.asList(parameterNamesListModel.toArray());
    }

    /**
     * Save all configurations to the system.
     */
    @SuppressWarnings("unchecked")
    private void saveConfig() {
        File configFile = new File(configFilePath);

        if (!configFile.exists()) {
            loggerInstance.log(getClass(), "Config file does not exist!", Logger.ERROR);
            return;
        }

        if (!configFile.isDirectory() && configFile.canWrite()){

            JSONObject configObj = new JSONObject();
            configObj.put("logLevel", getLogLevel());
            configObj.put("highlighting", getHighlighting());
            configObj.put("parameterNames", getParameterNames());

            try {
                FileWriter configFileWriter = new FileWriter(configFile);

                try {
                    configFileWriter.write(configObj.toJSONString());
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(this, "The config file can not be written!\n\nError:\n" + e.toString(), "Error writing config file", JOptionPane.ERROR_MESSAGE);
                    loggerInstance.log(getClass(), "Config file can not be written!\n" + e.toString(), Logger.ERROR);
                }

                configFileWriter.flush();
                configFileWriter.close();
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "The config file can not be written!\n\nError:\n" + e.toString(), "Error writing config file", JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "Config file can not be written!\n" + e.toString(), Logger.ERROR);
            } catch (Exception e) {
                loggerInstance.log(getClass(), e.toString(), Logger.ERROR);
            }

        } else {
            JOptionPane.showMessageDialog(this, "The config file is not writable: " + configFilePath, "Error writing config file", JOptionPane.ERROR_MESSAGE);
            loggerInstance.log(getClass(), "Config file is not writable: " + configFilePath, Logger.ERROR);
        }
    }

    /**
     * Load the configuration file and apply values to the UI.
     */
    @SuppressWarnings("unchecked")
    private void loadConfig() {
        File configFile = new File(configFilePath);

        if (!configFile.exists()) {
            loggerInstance.log(getClass(), "Config file does not exist!", Logger.ERROR);
            return;
        }

        if (!configFile.isDirectory() && configFile.canRead()) {

            JSONParser jsonParser = new JSONParser();

            // TODO: Check if exists before calling get() to prevent NullPointerException
            try {
                FileReader configFileReader = new FileReader(configFile);
                JSONObject configObj = (JSONObject)jsonParser.parse(configFileReader);

                setLogLevel(((Long)configObj.get("logLevel")).intValue());
                logLevelCombo.setSelectedIndex(getLogLevel());

                setHighlighting(((boolean)configObj.get("highlighting")));
                highlightCheckbox.setSelected(getHighlighting());

                parameterNamesListModel.clear();
                for (String param : (List<String>)configObj.get("parameterNames")) {
                    parameterNamesListModel.addElement(param);
                }

            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "The config file can not be read!\n\nError:\n" + e.toString(), "Error reading config file", JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "Config file can not be read!\n" + e.toString(), Logger.ERROR);
            } catch (ParseException e) {
                JOptionPane.showMessageDialog(this, "The config file can not be parsed!\n\nError:\n" + e.toString(), "Error parsing config file", JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "Config file can not be parsed!\n" + e.toString(), Logger.ERROR);
            } catch (NullPointerException e) {
                JOptionPane.showMessageDialog(this, "The config file needs to contain any option values!\n\nError:\n" + e.toString(), "Error parsing config file", JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "The config file needs to contain any option values!\n" + e.toString(), Logger.ERROR);
            } catch (Exception e) {
                loggerInstance.log(getClass(), e.toString(), Logger.ERROR);
            }

        } else {
            JOptionPane.showMessageDialog(this, "The config file is not readable or a directory: " + configFilePath, "Config file not readable", JOptionPane.ERROR_MESSAGE);
            loggerInstance.log(getClass(), "The config file is not readable or a directory: " + configFilePath, Logger.ERROR);
        }
    }

    private void logLevelComboActionPerformed(ActionEvent evt) {
        int logLevel = logLevelCombo.getSelectedIndex();
        setLogLevel(logLevel);
    }

    private void highlightCheckboxActionPerformed(ActionEvent evt) {
        boolean highlighting= highlightCheckbox.isSelected();
        setHighlighting(highlighting);
    }

    private void parameterNamesAddButtonActionPerformed(ActionEvent evt) {
        String newParameter = parameterNamesTextField.getText();

        if (!newParameter.equals("")) {
            parameterNamesListModel.addElement(newParameter);
            parameterNamesTextField.setText("");
        }
    }

    private void parameterNamesRemoveButtonActionPerformed(ActionEvent evt) {
        for(int paramIndex : parameterNamesList.getSelectedIndices()) {
            parameterNamesListModel.removeElementAt(paramIndex);
        }
    }

    private void parameterNamesTextFieldKeyPressed(KeyEvent evt) {
        if(evt.getKeyCode() == KeyEvent.VK_ENTER) {
            String newParameter = parameterNamesTextField.getText();

            if (!newParameter.equals("")) {
                parameterNamesListModel.addElement(newParameter);
                parameterNamesTextField.setText("");
            }
        }
    }

    private void saveConfigButtonActionPerformed(ActionEvent e) {
        saveConfig();
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        // Generated using JFormDesigner Evaluation license - Dennis Detering
        ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");
        loggingHeadlineLabel = new JLabel();
        logLevelCombo = new JComboBox<>();
        loggingSeparator = new JSeparator();
        logLevelLabel = new JLabel();
        highlightingSeparator = new JSeparator();
        highlightCheckbox = new JCheckBox();
        scrollPane1 = new JScrollPane();
        parameterNamesList = new JList();
        parameterNamesTextField = new JTextField();
        parameterNamesAddButton = new JButton();
        parameterNamesRemoveButton = new JButton();
        label1 = new JLabel();
        saveConfigButton = new JButton();

        //======== this ========
        setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);

        // JFormDesigner evaluation mark
        setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.TitledBorder(new javax.swing.border.EmptyBorder(0, 0, 0, 0),
                "JFormDesigner Evaluation", javax.swing.border.TitledBorder.CENTER,
                javax.swing.border.TitledBorder.BOTTOM, new java.awt.Font("Dialog", java.awt.Font.BOLD, 12),
                java.awt.Color.red), getBorder())); addPropertyChangeListener(new java.beans.PropertyChangeListener(){public void propertyChange(java.beans.PropertyChangeEvent e){if("border".equals(e.getPropertyName()))throw new RuntimeException();}});


        //---- loggingHeadlineLabel ----
        loggingHeadlineLabel.setText(bundle.getString("LOGGING_HEADLINE"));

        //---- logLevelCombo ----
        logLevelCombo.setModel(new DefaultComboBoxModel<>(new String[] {
            "ERROR",
            "INFO",
            "DEBUG"
        }));
        logLevelCombo.setSelectedIndex(2);
        logLevelCombo.setFont(new Font("Lucida Grande", Font.PLAIN, 12));
        logLevelCombo.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logLevelComboActionPerformed(e);
            }
        });

        //---- logLevelLabel ----
        logLevelLabel.setText(bundle.getString("LOGLEVEL"));
        logLevelLabel.setFont(new Font("Lucida Grande", Font.PLAIN, 12));

        //---- highlightCheckbox ----
        highlightCheckbox.setText(bundle.getString("HIGHLIGHTING"));
        highlightCheckbox.setSelected(true);
        highlightCheckbox.setHorizontalTextPosition(SwingConstants.LEFT);
        highlightCheckbox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightCheckboxActionPerformed(e);
            }
        });

        //======== scrollPane1 ========
        {
            scrollPane1.setViewportView(parameterNamesList);
        }

        //---- parameterNamesTextField ----
        parameterNamesTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                parameterNamesTextFieldKeyPressed(e);
            }
        });

        //---- parameterNamesAddButton ----
        parameterNamesAddButton.setText(bundle.getString("ADD"));
        parameterNamesAddButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                parameterNamesAddButtonActionPerformed(e);
            }
        });

        //---- parameterNamesRemoveButton ----
        parameterNamesRemoveButton.setText(bundle.getString("REMOVE"));
        parameterNamesRemoveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                parameterNamesRemoveButtonActionPerformed(e);
            }
        });

        //---- label1 ----
        label1.setText(bundle.getString("PARAMETER_NAMES_LABEL"));
        label1.setFont(new Font("Lucida Grande", Font.PLAIN, 12));

        //---- saveConfigButton ----
        saveConfigButton.setText(bundle.getString("SAVE_CONFIGURATION"));
        saveConfigButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveConfigButtonActionPerformed(e);
            }
        });

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addComponent(loggingSeparator)
                .addComponent(loggingHeadlineLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(highlightingSeparator)
                .addComponent(highlightCheckbox, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup()
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(logLevelLabel, GroupLayout.PREFERRED_SIZE, 72, GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(logLevelCombo, GroupLayout.PREFERRED_SIZE, 86, GroupLayout.PREFERRED_SIZE)
                            .addGap(0, 0, Short.MAX_VALUE))
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup()
                                .addComponent(saveConfigButton)
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(scrollPane1, GroupLayout.PREFERRED_SIZE, 256, GroupLayout.PREFERRED_SIZE)
                                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                        .addComponent(parameterNamesRemoveButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(parameterNamesAddButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                                .addComponent(label1, GroupLayout.PREFERRED_SIZE, 447, GroupLayout.PREFERRED_SIZE)
                                .addComponent(parameterNamesTextField, GroupLayout.PREFERRED_SIZE, 256, GroupLayout.PREFERRED_SIZE))
                            .addContainerGap(17, Short.MAX_VALUE))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(loggingHeadlineLabel)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(loggingSeparator, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(layout.createParallelGroup()
                        .addComponent(logLevelCombo, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(logLevelLabel, GroupLayout.PREFERRED_SIZE, 26, GroupLayout.PREFERRED_SIZE))
                    .addGap(18, 18, 18)
                    .addComponent(highlightCheckbox)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(highlightingSeparator, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(label1)
                    .addGap(5, 5, 5)
                    .addGroup(layout.createParallelGroup()
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(parameterNamesAddButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(parameterNamesRemoveButton))
                        .addComponent(scrollPane1, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(parameterNamesTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, 24, Short.MAX_VALUE)
                    .addComponent(saveConfigButton)
                    .addContainerGap())
        );
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    // Generated using JFormDesigner Evaluation license - Dennis Detering
    private JLabel loggingHeadlineLabel;
    private JComboBox<String> logLevelCombo;
    private JSeparator loggingSeparator;
    private JLabel logLevelLabel;
    private JSeparator highlightingSeparator;
    private JCheckBox highlightCheckbox;
    private JScrollPane scrollPane1;
    private JList parameterNamesList;
    private JTextField parameterNamesTextField;
    private JButton parameterNamesAddButton;
    private JButton parameterNamesRemoveButton;
    private JLabel label1;
    private JButton saveConfigButton;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}
