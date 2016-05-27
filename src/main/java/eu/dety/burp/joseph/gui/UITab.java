package eu.dety.burp.joseph.gui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import java.awt.Component;

/**
 * An additional tab in Burp Suite
 * @author Dennis Detering
 * @version 1.0
 */
public class UITab implements ITab {
    
    private UIMain main;
    private final IBurpExtenderCallbacks callbacks;

    /**
     * Create a new Tab.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     */
    public UITab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.main = new UIMain(callbacks);
        callbacks.customizeUiComponent(main);
        callbacks.addSuiteTab(this);
    }
    
    /**
     * 
     * @return Get the UI component that should be registered at the Burp Suite GUI. 
     */
    @Override
    public Component getUiComponent() {
        return main;
    }
    
    /**
     * 
     * @return Get the UI component that should be registered at the Burp Suite GUI.
     */
    public UIMain getUiMain(){
        return main;
    }
    
    /**
     * 
     * @return Get the Headline for the Tab. 
     */
    @Override
    public String getTabCaption() {
        return "JOSEPH";
    }
}
