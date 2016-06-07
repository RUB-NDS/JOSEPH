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

import burp.IBurpExtenderCallbacks;
import javax.swing.JTabbedPane;
import java.util.ResourceBundle;

/**
 * The main window, the parent window for all tabs.
 * @author Dennis Detering
 * @version 1.0
 */
public class UIMain extends JTabbedPane {
    private final IBurpExtenderCallbacks callbacks;
    private final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");


    // Sub tabs within JOSEPH main tab
    private UIHelp helpTab;
    private UIPreferences preferencesTab;

    /**
     * Construct the main UI.
     * Calls {@link #initComponents()} to initialize ...
     * @param callbacks {@link burp.IBurpExtenderCallbacks}.
     */
    public UIMain(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        initComponents();
    }

    /**
     * Getter for the help sub tab
     * @return {@link UIHelp} object.
     */
    public UIHelp getHelpTab() {
        return helpTab;
    }

    /**
     * Getter for the preferences sub tab
     * @return {@link UIPreferences} object.
     */
    public UIPreferences getPreferencesTab() {
        return preferencesTab;
    }

    /**
     * Initialize all necessary components
     */
    private void initComponents(){
        // Help sub tab
        helpTab = new UIHelp();
        preferencesTab = new UIPreferences();

        this.addTab(bundle.getString("PREFERENCES"), preferencesTab);
        this.addTab(bundle.getString("HELP"), helpTab);

        // Customize UI components
        callbacks.customizeUiComponent(this);
    }
}
