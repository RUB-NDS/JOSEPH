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

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;

/**
 * An additional tab in Burp
 * @author Dennis Detering
 * @version 1.0
 */
public class UITab implements ITab, IContextMenuFactory {
    
    private UIMain mainTab;
    private final IBurpExtenderCallbacks callbacks;
    private static final Logger loggerInstance = Logger.getInstance();
    private static ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    /**
     * Create a new tab.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     */
    public UITab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.mainTab = new UIMain(callbacks);
        callbacks.customizeUiComponent(mainTab);
        callbacks.addSuiteTab(this);
    }
    
    /**
     * 
     * @return Get the UI component that should be registered at the Burp GUI.
     */
    @Override
    public Component getUiComponent() {
        return mainTab;
    }


    /**
     *
     * @return Get the main tab.
     */
    public UIMain getUiMain(){
        return mainTab;
    }

    /**
     *
     * @return Get the headline for the tab.
     */
    @Override
    public String getTabCaption() {
        return "JOSEPH";
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        IHttpRequestResponse[] messages = iContextMenuInvocation.getSelectedMessages();
        if (messages != null && messages.length == 1) {

            final IHttpRequestResponse message = messages[0];

            // Check if message has been marked by our extension
            if(!Objects.equals(message.getHighlight(), Marker.getHighlightColor())) {
                return null;
            }

            List<JMenuItem> list = new ArrayList<>();
            JMenuItem menuItem = new JMenuItem(bundle.getString("SEND2JOSEPH"));
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent evt) {
                    try {
                        loggerInstance.log(UITab.class, "Send to JOSEPH context menu item clicked", Logger.LogLevel.DEBUG);

                        UIAttacker attacker = mainTab.getAttackerTab();
                        UIAttackerTab attackerTab = new UIAttackerTab(callbacks, message);

                        int newTabIndex = attacker.getNewTabIndex();
                        attacker.addTab(Integer.toString(newTabIndex), attackerTab);
                        attacker.setSelectedIndex(newTabIndex - 1);

                        // TODO: Highlight

                    } catch (Exception e) {
                        loggerInstance.log(UITab.class, e.getMessage(), Logger.LogLevel.ERROR);
                    }
                }
            });
            list.add(menuItem);
            return list;
        }

        return null;
    }
}
