package eu.dety.burp.joseph.gui;

import burp.IBurpExtenderCallbacks;
import javax.swing.JTabbedPane;
import java.util.ResourceBundle;

/**
 * The main window, the parent window for all tabs.
 * @author Dennis Detering
 * @version 1.0
 */
public class UIMain extends JTabbedPane {
    private final IBurpExtenderCallbacks callbacks;
    private final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");


    // Sub tabs within JOSEPH main tab
    private UIHelp helpTab;
    private UIPreferences preferencesTab;

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
     * @return {@link UIHelp} object.
     */
    public UIHelp getHelpTab() {
        return helpTab;
    }

    /**
     * Getter for the preferences sub tab
     * @return {@link UIPreferences} object.
     */
    public UIPreferences getPreferencesTab() {
        return preferencesTab;
    }

    /**
     * Initialize all necessary components
     */
    private void initComponents(){
        // Help sub tab
        helpTab = new UIHelp();
        preferencesTab = new UIPreferences();

        this.addTab(bundle.getString("PREFERENCES"), preferencesTab);
        this.addTab(bundle.getString("HELP"), helpTab);

        // Customize UI components
        callbacks.customizeUiComponent(this);
    }
}
