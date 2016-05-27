package burp;

import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import eu.dety.burp.joseph.gui.UITab;

/**
 * The Burp Extender to register the JOSEPH Extension
 * @author Dennis Detering
 * @version 1.0
 */

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
	public static final String EXTENSION_NAME = "JOSEPH";

    private IBurpExtenderCallbacks callbacks;

    private static PrintWriter stdout;
    private static PrintWriter stderr;

    /**
     * Set the extension name and print loading information to standard output.
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME);

        // Obtain streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String time = dateFormat.format(calObj.getTime());
        stdout.println("+---------------------------------------------------------+");
        stdout.println("|                         JOSEPH                          |");
        stdout.println("|                     Version 1.0.0                       |");
        stdout.println("|                   Started @ "+time+"                    |");
        stdout.println("+---------------------------------------------------------+");
        
        // Register new JOSEPH Tab
        UITab josephMainTab = new UITab(callbacks);
        
    }

    /**
     * Print a notification on the standard output when extension is unloaded.
     */
    @Override
    public void extensionUnloaded() {
        stdout.println("Extension JOSEPH is now unloaded.");
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