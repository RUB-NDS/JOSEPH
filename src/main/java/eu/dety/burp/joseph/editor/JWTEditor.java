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
package eu.dety.burp.joseph.editor;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import burp.ITextEditor;

import eu.dety.burp.joseph.gui.UIPreferences;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Logger;
import eu.dety.burp.joseph.utilities.Finder;

import javax.swing.JTabbedPane;
import java.awt.Component;

/**
 * JSON Web Token (JWT) Editor.
 * Display decoded JWT syntax highlighted.
 * @author Dennis Detering
 * @version 1.0
 */
public class JWTEditor implements IMessageEditorTabFactory {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final Finder finder = new Finder();
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private String joseParameterName = null;

    /**
     * Create new Source Viewer instance.
     * @param callbacks {@link IBurpExtenderCallbacks}.
     */
    public JWTEditor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * Create a new Instance of Burps own Request/Response Viewer (IMessageEditorTab).
     * @param controller {@link burp.IMessageEditorController}
     * @param editable True if message is editable, false otherwise.
     * @return {@link burp.IMessageEditorTab}
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new UIJWTEditorTab(controller, editable);
    }

    class UIJWTEditorTab implements IMessageEditorTab {
        private JTabbedPane UIJWTEditorTabPanel;
        private boolean editable;
        private byte[] currentMessage;
        private Decoder joseDecoder;

        private ITextEditor sourceViewerRaw;
        private ITextEditor sourceViewerHeader;
        private ITextEditor sourceViewerPayload;
        private ITextEditor sourceViewerSignature;

        UIJWTEditorTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;
            this.UIJWTEditorTabPanel = new JTabbedPane();
            this.joseDecoder = new Decoder(callbacks);


            // Create an instance of Burp's text editor to display raw data
            sourceViewerRaw = callbacks.createTextEditor();
            sourceViewerRaw.setEditable(editable);

            // Add text editor tab for each JOSE part
            sourceViewerHeader = callbacks.createTextEditor();
            sourceViewerPayload = callbacks.createTextEditor();
            sourceViewerSignature = callbacks.createTextEditor();

            UIJWTEditorTabPanel.addTab("Header", sourceViewerHeader.getComponent());
            UIJWTEditorTabPanel.addTab("Payload", sourceViewerPayload.getComponent());
            UIJWTEditorTabPanel.addTab("Base64(Signature)", sourceViewerSignature.getComponent());
            UIJWTEditorTabPanel.addTab("Raw", sourceViewerRaw.getComponent());
        }

        @Override
        public String getTabCaption() {
            return "JWT";
        }

        @Override
        public Component getUiComponent() {
            return UIJWTEditorTabPanel;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // Enable this tab for requests containing a JOSE parameter
            if(isRequest) {
                for(Object param: UIPreferences.getParameterNames().toArray()) {
                    if(helpers.getRequestParameter(content, param.toString()) != null && finder.checkJWTPattern(helpers.getRequestParameter(content, param.toString()).getValue())) {
                        joseParameterName = helpers.getRequestParameter(content, param.toString()).getName();
                        loggerInstance.log(getClass(), "JWT value found, enable JWTEditor.", Logger.DEBUG);
                        return true;
                    }
                }
            }
            return false;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                // Clear display
                sourceViewerRaw.setText(null);
                sourceViewerRaw.setEditable(false);
            } else {
                // Retrieve JOSE parameter
                IParameter parameter = helpers.getRequestParameter(content, joseParameterName);

                sourceViewerRaw.setText(parameter.getValue().getBytes());
                sourceViewerRaw.setEditable(editable);

                String[] joseParts = joseDecoder.getComponents(parameter.getValue());

                sourceViewerHeader.setEditable(editable);
                sourceViewerPayload.setEditable(editable);
                sourceViewerSignature.setEditable(editable);

                sourceViewerHeader.setText(joseDecoder.getDecoded(joseParts[0]).getBytes());
                sourceViewerPayload.setText(joseDecoder.getDecoded(joseParts[1]).getBytes());
                sourceViewerSignature.setText(helpers.stringToBytes(joseParts[2]));
            }

            // Remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            // Determine whether the user modified the raw data
            if (sourceViewerRaw.isTextModified()) {
                byte[] text = sourceViewerRaw.getText();

                // Update the request with the new parameter value
                return helpers.updateParameter(currentMessage, helpers.buildParameter(joseParameterName, text.toString(), IParameter.PARAM_URL));
            } else if (sourceViewerHeader.isTextModified() || sourceViewerPayload.isTextModified() || sourceViewerSignature.isTextModified()) {
                String[] components = {
                    joseDecoder.getEncoded(sourceViewerHeader.getText()),
                    joseDecoder.getEncoded(sourceViewerPayload.getText()),
                    helpers.bytesToString(sourceViewerSignature.getText()),
                };

                // Update the request with the new parameter value
                return helpers.updateParameter(currentMessage, helpers.buildParameter(joseParameterName, joseDecoder.concatComponents(components), IParameter.PARAM_URL));
            } else {
                return currentMessage;
            }
        }

        @Override
        public boolean isModified() {
            return (sourceViewerRaw.isTextModified() || sourceViewerHeader.isTextModified() || sourceViewerPayload.isTextModified() || sourceViewerSignature.isTextModified());
        }

        @Override
        public byte[] getSelectedData() {
            return sourceViewerRaw.getSelectedText();
        }
    }
}

