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
import burp.ITab;
import java.awt.Component;

/**
 * An additional tab in Burp
 * @author Dennis Detering
 * @version 1.0
 */
public class UITab implements ITab {
    
    private UIMain mainTab;
    private final IBurpExtenderCallbacks callbacks;

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
}
