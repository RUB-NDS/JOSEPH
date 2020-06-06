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
package burp;

import eu.dety.burp.joseph.editor.JweEditor;
import eu.dety.burp.joseph.editor.JwsEditor;
import eu.dety.burp.joseph.gui.MainTabGroup;
import eu.dety.burp.joseph.scanner.Marker;
import eu.dety.burp.joseph.utilities.Logger;

import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.ResourceBundle;

/**
 * The Burp Extender to register the JOSEPH extension
 *
 * @author Dennis Detering
 * @version 1.0
 */

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String EXTENSION_NAME = "JOSEPH";

    private static PrintWriter stdout;
    private static PrintWriter stderr;

    private ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    /**
     * Set the extension name and print loading information to standard output.
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
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
        stdout.println("|                     Version 1.0.3                       |");
        stdout.println("|                   Started @ " + time + "                    |");
        stdout.println("+---------------------------------------------------------+");

        // Register JOSEPH tab
        final MainTabGroup josephMainTab = new MainTabGroup(callbacks);
        loggerInstance.log(getClass(), bundle.getString("REGISTERED_MAINTAB"), Logger.LogLevel.INFO);

        // Register Context Menu
        callbacks.registerContextMenuFactory(josephMainTab);
        loggerInstance.log(getClass(), bundle.getString("REGISTERED_CONTEXTMENU"), Logger.LogLevel.INFO);

        // Register HTTP listener
        final Marker marker = new Marker(callbacks);
        callbacks.registerHttpListener(marker);
        loggerInstance.log(getClass(), bundle.getString("REGISTERED_HTTPLISTENER"), Logger.LogLevel.INFO);

        // Register JWS Editor
        final JwsEditor jwsEditor = new JwsEditor(callbacks);
        callbacks.registerMessageEditorTabFactory(jwsEditor);
        loggerInstance.log(getClass(), bundle.getString("REGISTERED_JWSEDITOR"), Logger.LogLevel.INFO);

        // Register JWE Editor
        final JweEditor jweEditor = new JweEditor(callbacks);
        callbacks.registerMessageEditorTabFactory(jweEditor);
        loggerInstance.log(getClass(), bundle.getString("REGISTERED_JWEEDITOR"), Logger.LogLevel.INFO);

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
     *
     * @return The standard output
     */
    public static PrintWriter getStdOut() {
        return stdout;
    }

    /**
     * Get a {@link java.io.PrintWriter} to the standard error output of Burp.
     *
     * @return The standard error output
     */
    public static PrintWriter getStdErr() {
        return stderr;
    }
}
