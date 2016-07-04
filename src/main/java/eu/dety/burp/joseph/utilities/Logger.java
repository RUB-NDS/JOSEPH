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
package eu.dety.burp.joseph.utilities;

import burp.BurpExtender;

import eu.dety.burp.joseph.gui.PreferencesPanel;

import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Objects;

/**
 * Internal logger for the extension
 * @author Dennis Detering
 * @version 1.0
 */
public class Logger {

    private static PrintWriter stdout = null;
    private static PrintWriter stderr = null;

    public static final int ERROR = 0;
    public static final int INFO = 1;
    public static final int DEBUG = 2;

    private Logger(){
        stdout = BurpExtender.getStdOut();
        stderr = BurpExtender.getStdErr();
    }

    /**
     * Singleton pattern to ensure a single instance
     */
    private static class SingletonHolder {
        private static final Logger INSTANCE = new Logger();
    }

    /**
     * Get the Instance of the Logger.
     * @return Logger instance.
     */
    public static Logger getInstance() {
        return SingletonHolder.INSTANCE;
    }

    /**
     * Log a specific message on a logging level.
     * @param callingClass The calling class.
     * @param message The message to log.
     * @param logType The logging type.
     */
    public void log(Class callingClass, String message, int logType){
        // Get current time
        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String time = dateFormat.format(calObj.getTime());

        // Choose correct output stream
        PrintWriter outputStream;
        outputStream = (Objects.equals(logType, ERROR)) ? stderr : stdout;

        // Check if message should be logged based on current log level preference
        if (logType <= PreferencesPanel.getLogLevel()) {
            String logTypeName = "UNKNOWN";
            // TODO: Easier way to get constant name (by value)?
            switch(logType) {
                case ERROR:
                    logTypeName = "ERROR";
                    break;
                case INFO:
                    logTypeName = "INFO";
                    break;
                case DEBUG:
                    logTypeName = "DEBUG";
                    break;
            }

            // Print log message
            String logOutput = String.format("[%s] %s - [%s]: %s ", logTypeName, time, callingClass.getSimpleName(), message);
            outputStream.println(logOutput);
        }
    }
}
