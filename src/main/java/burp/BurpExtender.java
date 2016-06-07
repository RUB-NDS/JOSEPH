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
package burp;

import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.ResourceBundle;

import eu.dety.burp.joseph.gui.UITab;
import eu.dety.burp.joseph.scanner.Marker;
import eu.dety.burp.joseph.utilities.Logger;

/**
 * The Burp Extender to register the JOSEPH extension
 * @author Dennis Detering
 * @version 1.0
 */

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String EXTENSION_NAME = "JOSEPH";

    private IBurpExtenderCallbacks callbacks;

    private static PrintWriter stdout;
    private static PrintWriter stderr;

    ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    /**
     * Set the extension name and print loading information to standard output.
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Keep a reference to callbacks object
        this.callbacks = callbacks;

        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME);

        // Obtain streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        Logger loggerInstance = Logger.getInstance();

        // Get current time
        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String time = dateFormat.format(calObj.getTime());
        stdout.println("+---------------------------------------------------------+");
        stdout.println("|                         JOSEPH                          |");
        stdout.println("|                     Version 1.0.0                       |");
        stdout.println("|                   Started @ "+time+"                    |");
        stdout.println("+---------------------------------------------------------+");

        // Register JOSEPH tab
        final UITab josephMainTab = new UITab(callbacks);
        loggerInstance.log(getClass(), bundle.getString("REGISTERED_MAINTAB"), Logger.INFO);

        // Register HTTP listener
        final Marker marker = new Marker(callbacks);
        callbacks.registerHttpListener(marker);
        loggerInstance.log(getClass(), bundle.getString("REGISTERED_HTTPLISTENER"), Logger.INFO);
    }

    /**
     * Print a notification on the standard output when extension is unloaded.
     */
    @Override
    public void extensionUnloaded() {
        stdout.println(bundle.getString("EXTENSION_UNLOADED"));
    }
    
    /**
     * Get a {@link java.io.PrintWriter} to the standard output of Burp.
     * @return The standard output
     */
    public static PrintWriter getStdOut(){
        return stdout;
    }
    
    /**
     * Get a {@link java.io.PrintWriter} to the standard error output of Burp.
     * @return The standard error output
     */    
    public static PrintWriter getStdErr(){
        return stderr;
    }
}