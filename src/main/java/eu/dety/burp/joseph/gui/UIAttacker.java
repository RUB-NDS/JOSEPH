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

import eu.dety.burp.joseph.utilities.Logger;

import java.util.ResourceBundle;
import javax.swing.*;

/**
 * The attacker tab holding message specific attack tabs.
 * @author Dennis Detering
 * @version 1.0
 */
public class UIAttacker extends JTabbedPane {
    // private static final Logger loggerInstance = Logger.getInstance();
    // private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");
    // private UIAttackerTab attackerTab;
    private static int tabIndex = 0;

    /**
     * Construct the attacker UI.
     */
    public UIAttacker() {}


    /**
     * Get new tabIndex and increase the value
     */
    public int getTabIndex(){
        return tabIndex;
    }

    /**
     * Get new tabIndex and increase the value
     */
    public int getNewTabIndex(){
        tabIndex++;

        return tabIndex;
    }

}
