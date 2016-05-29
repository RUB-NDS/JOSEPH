package eu.dety.burp.joseph.utilities;

import burp.BurpExtender;

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

    public static final String ERROR = "ERROR";
    public static final String INFO = "INFO";
    public static final String DEBUG = "DEBUG";

    private Logger(){
        stdout = BurpExtender.getStdOut();
        stderr = BurpExtender.getStdErr();
    }

    // Singleton pattern to ensure a single instance
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
    public void log(Class callingClass, String message, String logType){
        // Get current time
        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String time = dateFormat.format(calObj.getTime());

        // Choose correct output stream
        PrintWriter outputStream;
        outputStream = (Objects.equals(logType, ERROR)) ? stderr : stdout;

        // Print log message
        String logOutput = String.format("[%s] %s - [%s]: %s ", logType, time, callingClass.getName(), message);
        outputStream.println(logOutput);
    }
}
