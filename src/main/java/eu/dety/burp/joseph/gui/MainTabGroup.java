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

import burp.*;
import eu.dety.burp.joseph.scanner.Marker;
import eu.dety.burp.joseph.utilities.Finder;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;

/**
 * The main window, the parent window for all tabs.
 * @author Dennis Detering
 * @version 1.0
 */
public class MainTabGroup extends JTabbedPane implements ITab, IContextMenuFactory {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");
    private final IBurpExtenderCallbacks callbacks;
    private int globalTabCounter = 0;

    // Sub tabs within JOSEPH MainTabGroup
    private ManualPanel manualPanel;
    private DecoderPanel decoderPanel;
    private HelpPanel helpPanel;
    private PreferencesPanel preferencesPanel;
    private JTabbedPane attackerTabGroup = new JTabbedPane();

    /**
     * Construct the main UI.
     * <p>
     * Calls {@link #initComponents()} to initialize UI components
     * @param callbacks {@link burp.IBurpExtenderCallbacks}.
     */
    public MainTabGroup(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        initComponents();
    }

    /**
     * Get the UI component
     * @return Get the UI component that should be registered at the Burp GUI.
     */
    @Override
    public Component getUiComponent() {
        return this;
    }

    /**
     * Get tab caption
     * @return Get the title for the tab.
     */
    @Override
    public String getTabCaption() {
        return "JOSEPH";
    }

    /**
     * Create context menu
     * <p>
     * Create context menu for marked messages to create new {@link AttackerPanel} for this message
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        IHttpRequestResponse[] messages = iContextMenuInvocation.getSelectedMessages();
        if (messages != null && messages.length == 1) {

            final IHttpRequestResponse message = messages[0];

            java.util.List<JMenuItem> list = new ArrayList<>();
            JMenuItem menuItem = new JMenuItem(bundle.getString("SEND2JOSEPH"));
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent evt) {
                    try {
                        loggerInstance.log(MainTabGroup.class, "Send to JOSEPH context menu item clicked", Logger.LogLevel.DEBUG);

                        // Create new attacker panel for this message
                        AttackerPanel attackerPanel = new AttackerPanel(callbacks, message);

                        int newTabCounter = getNewGlobalTabCounter();
                        final String captionTitleValue = Integer.toString(newTabCounter);
                        attackerTabGroup.addTab(captionTitleValue, attackerPanel);
                        attackerTabGroup.setSelectedIndex(attackerTabGroup.indexOfTab(captionTitleValue));

                        // Tab caption
                        JPanel tabCaptionPanel = new JPanel(new GridBagLayout());
                        tabCaptionPanel.setOpaque(false);
                        JLabel captionTitle = new JLabel(captionTitleValue);
                        captionTitle.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 3));

                        // Define close button
                        final JButton closeButton = new JButton("x");
                        closeButton.setToolTipText("Click to close tab.");
                        closeButton.setOpaque(false);
                        closeButton.setContentAreaFilled(false);
                        closeButton.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
                        closeButton.setPreferredSize(new Dimension(18, 18));
                        closeButton.setMargin(new Insets(0, 0, 0, 0));
                        closeButton.setForeground(Color.gray);

                        // Close button mouse listener performing the tab removal on mouse click and defining hover effects
                        closeButton.addMouseListener(new MouseListener() {

                            @Override
                            public void mouseClicked(MouseEvent e) {
                                int index = attackerTabGroup.indexOfTab(captionTitleValue);

                                if (index >= 0) {
                                    attackerTabGroup.removeTabAt(index);
                                }
                            }

                            @Override
                            public void mousePressed(MouseEvent e) {
                            }

                            @Override
                            public void mouseReleased(MouseEvent e) {
                            }

                            @Override
                            public void mouseEntered(MouseEvent e) {
                                closeButton.setForeground(Color.black);
                            }

                            @Override
                            public void mouseExited(MouseEvent e) {
                                closeButton.setForeground(Color.gray);
                            }
                        });

                        GridBagConstraints gridBagConstraints = new GridBagConstraints();
                        gridBagConstraints.gridx = 0;
                        gridBagConstraints.gridy = 0;
                        gridBagConstraints.weightx = 1;
                        tabCaptionPanel.add(captionTitle, gridBagConstraints);

                        gridBagConstraints.gridx++;
                        gridBagConstraints.weightx = 0;
                        tabCaptionPanel.add(closeButton, gridBagConstraints);

                        attackerTabGroup.setTabComponentAt(attackerTabGroup.indexOfTab(captionTitleValue), tabCaptionPanel);

                    } catch (Exception e) {
                        loggerInstance.log(MainTabGroup.class, e.getMessage(), Logger.LogLevel.ERROR);
                    }
                }
            });
            list.add(menuItem);

            // Check if message has been marked by JOSEPH extension (or if tool is repeater)
            if (!Objects.equals(message.getHighlight(), Marker.getHighlightColor()) && iContextMenuInvocation.getToolFlag() != IBurpExtenderCallbacks.TOOL_REPEATER) {
                menuItem.setEnabled(false);
            }

            // Additionally check whether JWS or JWE patterns exists
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(message);
            if (Finder.checkHeaderAndParameterForJwsPattern(requestInfo) == null && Finder.checkHeaderAndParameterForJwePattern(requestInfo) == null) {
                menuItem.setEnabled(false);
            }

            return list;
        }

        return null;
    }

    /**
     * Getter for the decoder panel
     * @return {@link DecoderPanel} object.
     */
    public DecoderPanel getDecoderPanel() {
        return decoderPanel;
    }

    /**
     * Getter for the help panel
     * @return {@link HelpPanel} object.
     */
    public HelpPanel getHelpPanel() {
        return helpPanel;
    }

    /**
     * Getter for the preferences panel
     * @return {@link PreferencesPanel} object.
     */
    public PreferencesPanel getPreferencesPanel() {
        return preferencesPanel;
    }

    /**
     * Get the current tab index
     * @return the tab index.
     */
    public int getGlobalTabCounter() {
        return globalTabCounter;
    }

    /**
     * Increase the tab index and get new value
     * @return the increased tab index.
     */
    public int getNewGlobalTabCounter() {
        globalTabCounter++;
        return globalTabCounter;
    }

    /**
     * Initialize all necessary components
     */
    private void initComponents() {
        // Create panel instances
        manualPanel = new ManualPanel(callbacks);
        decoderPanel = new DecoderPanel(callbacks);
        preferencesPanel = new PreferencesPanel();
        helpPanel = new HelpPanel();

        // Add panel instances as tabs
        this.addTab(bundle.getString("ATTACKER"), attackerTabGroup);
        this.addTab(bundle.getString("MANUAL"), manualPanel);
        this.addTab(bundle.getString("DECODER"), decoderPanel);
        this.addTab(bundle.getString("PREFERENCES"), preferencesPanel);
        this.addTab(bundle.getString("HELP"), helpPanel);

        attackerTabGroup.addTab(bundle.getString("INFO"), new AttackerInfoPanel());


        // Use Burp UI settings and add as extension tab
        callbacks.customizeUiComponent(this);
        callbacks.addSuiteTab(this);
    }
}
