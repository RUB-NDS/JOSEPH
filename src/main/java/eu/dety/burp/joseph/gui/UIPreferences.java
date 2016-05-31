/*
 * Created by JFormDesigner on Sun May 29 18:55:01 CEST 2016
 */

package eu.dety.burp.joseph.gui;

import java.awt.*;
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
    private static List<String> parameterNames = Arrays.asList("access_token", "token");

    UIPreferences() {
        initComponents();

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
     * Get the parameter names
     * @return The parameter names string array.
     */
    public static List<String> getParameterNames(){
        return parameterNames;
    }

    /**
     * Set the parameter names
     */
    private void setParameterNames(List<String> paramNames){
        parameterNames = paramNames;
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
            configObj.put("logLevel", logLevel);
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

            try {
                FileReader configFileReader = new FileReader(configFile);
                JSONObject configObj = (JSONObject)jsonParser.parse(configFileReader);

                setLogLevel(((Long)configObj.get("logLevel")).intValue());
                logLevelCombo.setSelectedIndex(getLogLevel());

                setParameterNames(((List<String>)configObj.get("parameterNames")));

            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "The config file can not be read!\n\nError:\n" + e.toString(), "Error reading config file", JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "Config file can not be read!\n" + e.toString(), Logger.ERROR);
            } catch (ParseException e) {
                JOptionPane.showMessageDialog(this, "The config file can not be parsed!\n\nError:\n" + e.toString(), "Error parsing config file", JOptionPane.ERROR_MESSAGE);
                loggerInstance.log(getClass(), "Config file can not be parsed!\n" + e.toString(), Logger.ERROR);
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

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        // Generated using JFormDesigner Evaluation license - Dennis Detering
        ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");
        loggingHeadlineLabel = new JLabel();
        logLevelCombo = new JComboBox<>();
        loggingSeparator = new JSeparator();
        logLevelLabel = new JLabel();

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
        logLevelCombo.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logLevelComboActionPerformed(e);
            }
        });

        //---- logLevelLabel ----
        logLevelLabel.setText(bundle.getString("LOGLEVEL"));

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(logLevelLabel, GroupLayout.PREFERRED_SIZE, 72, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(logLevelCombo, GroupLayout.PREFERRED_SIZE, 86, GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(236, Short.MAX_VALUE))
                .addComponent(loggingSeparator, GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
                .addComponent(loggingHeadlineLabel, GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(loggingHeadlineLabel)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(loggingSeparator, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(layout.createParallelGroup()
                        .addComponent(logLevelLabel, GroupLayout.PREFERRED_SIZE, 26, GroupLayout.PREFERRED_SIZE)
                        .addComponent(logLevelCombo, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addContainerGap(234, Short.MAX_VALUE))
        );
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    // Generated using JFormDesigner Evaluation license - Dennis Detering
    private JLabel loggingHeadlineLabel;
    private JComboBox<String> logLevelCombo;
    private JSeparator loggingSeparator;
    private JLabel logLevelLabel;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}
