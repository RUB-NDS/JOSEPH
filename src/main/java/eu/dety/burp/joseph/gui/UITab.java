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
