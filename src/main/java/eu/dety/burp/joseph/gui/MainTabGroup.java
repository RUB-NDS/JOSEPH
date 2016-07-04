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
import eu.dety.burp.joseph.scanner.Marker;
import eu.dety.burp.joseph.utilities.Logger;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;
import javax.swing.*;

/**
 * The main window, the parent window for all tabs.
 * @author Dennis Detering
 * @version 1.0
 */
public class MainTabGroup extends JTabbedPane implements ITab, IContextMenuFactory {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");
    private final IBurpExtenderCallbacks callbacks;
    private int tabIndex = 0;

    // Sub tabs within JOSEPH MainTabGroup
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

            // Check if message has been marked by JOSEPH extension
            if(!Objects.equals(message.getHighlight(), Marker.getHighlightColor())) {
                return null;
            }

            java.util.List<JMenuItem> list = new ArrayList<>();
            JMenuItem menuItem = new JMenuItem(bundle.getString("SEND2JOSEPH"));
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent evt) {
                    try {
                        loggerInstance.log(MainTabGroup.class, "Send to JOSEPH context menu item clicked", Logger.DEBUG);

                        // Create new attacker panel for this message
                        AttackerPanel attackerPanel = new AttackerPanel(callbacks, message);

                        int newTabIndex = getNewTabIndex();
                        attackerTabGroup.addTab(Integer.toString(newTabIndex), attackerPanel);
                        attackerTabGroup.setSelectedIndex(newTabIndex - 1);

                        // TODO: Highlight MainTabGroup (like on "send to repeater")

                    } catch (Exception e) {
                        loggerInstance.log(MainTabGroup.class, e.getMessage(), Logger.ERROR);
                    }
                }
            });
            list.add(menuItem);
            return list;
        }

        return null;
    }

    /**
     * Getter for the help pabel
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
    public int getTabIndex(){
        return tabIndex;
    }

    /**
     * Increase the tab index and get new value
     * @return the increased tab index.
     */
    public int getNewTabIndex(){
        tabIndex++;
        return tabIndex;
    }

    /**
     * Initialize all necessary components
     */
    private void initComponents(){
        // Create panel instances
        helpPanel = new HelpPanel();
        preferencesPanel = new PreferencesPanel();

        // Add panel instances as tabs
        this.addTab(bundle.getString("ATTACKER"), attackerTabGroup);
        this.addTab(bundle.getString("PREFERENCES"), preferencesPanel);
        this.addTab(bundle.getString("HELP"), helpPanel);

        // Use Burp UI settings and add as extension tab
        callbacks.customizeUiComponent(this);
        callbacks.addSuiteTab(this);
    }
}
