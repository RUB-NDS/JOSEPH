/*
 * Created by JFormDesigner on Sun May 29 18:55:01 CEST 2016
 */

package eu.dety.burp.joseph.gui;

import java.awt.*;
import eu.dety.burp.joseph.utilities.Logger;

import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.GroupLayout;

/**
 * @author Dennis Detering
 */
public class UIPreferences extends JPanel {
    private static Logger loggerInstance = Logger.getInstance();
    private static int logLevel = 2;

    public UIPreferences() {
        initComponents();
        // logLevelCombo.setSelectedIndex(logLevel);
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
    public void setLogLevel(int logLvl){
        logLevel = logLvl;
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
