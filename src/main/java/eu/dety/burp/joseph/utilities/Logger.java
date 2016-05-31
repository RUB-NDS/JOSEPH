package eu.dety.burp.joseph.utilities;

import burp.BurpExtender;
import eu.dety.burp.joseph.gui.UIPreferences;

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
        if (logType <= UIPreferences.getLogLevel()) {
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
