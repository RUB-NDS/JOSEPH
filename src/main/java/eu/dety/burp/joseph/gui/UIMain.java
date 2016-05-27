package eu.dety.burp.joseph.gui;

import burp.IBurpExtenderCallbacks;
import javax.swing.JTabbedPane;

/**
 * The main window, the parent window for all tabs.
 * @author Dennis Detering
 * @version 1.0
 */
public class UIMain extends JTabbedPane {
    private IBurpExtenderCallbacks callbacks;

    // Sub tabs within JOSEPH main tab
    private UIHelp help;

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
     * @return Get the help tab.
     */
    public UIHelp getHelp() {
        return help;
    }

    /**
     * Initialize all necessary components
     */
    private void initComponents(){
        // Help sub tab
        help = new UIHelp();

        this.addTab("Help", help);

        // Customize UI components
        callbacks.customizeUiComponent(this);
    }
}
