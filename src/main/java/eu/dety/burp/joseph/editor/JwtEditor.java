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

import burp.*;

import eu.dety.burp.joseph.gui.EditorAttackerPanel;
import eu.dety.burp.joseph.gui.PreferencesPanel;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Logger;
import eu.dety.burp.joseph.utilities.Finder;

import javax.swing.JTabbedPane;
import java.awt.Component;
import java.util.Arrays;
import java.util.List;

/**
 * JSON Web Token (JWT) Editor.
 * <p>
 * Display decoded JWT components.
 * @author Dennis Detering
 * @version 1.0
 */
public class JwtEditor implements IMessageEditorTabFactory {
    private static final Logger loggerInstance = Logger.getInstance();
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private String joseHeader = null;
    private String joseHeaderValue = null;
    private String joseParameterName = null;


    /**
     * Create JwtEditor instance.
     * @param callbacks {@link IBurpExtenderCallbacks}.
     */
    public JwtEditor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * Create a new instance of Burps own request/response viewer (IMessageEditorTab).
     * @param controller {@link burp.IMessageEditorController}
     * @param editable True if message is editable, false otherwise.
     * @return {@link JwtEditor.JwtEditorTab} instance implementing {@link burp.IMessageEditorTab}
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new JwtEditorTab(controller, editable);
    }

    public class JwtEditorTab implements IMessageEditorTab {
        private JTabbedPane JwtEditorTabPanel;
        private boolean editable;
        private byte[] currentMessage;
        private boolean isModified = false;

        private ITextEditor sourceViewerHeader;
        private ITextEditor sourceViewerPayload;
        private ITextEditor sourceViewerSignature;
        private EditorAttackerPanel editorAttackerPanel;

        JwtEditorTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;
            this.JwtEditorTabPanel = new JTabbedPane();

            // Add text editor tab for each JOSE part
            sourceViewerHeader = callbacks.createTextEditor();
            sourceViewerPayload = callbacks.createTextEditor();
            sourceViewerSignature = callbacks.createTextEditor();

            JwtEditorTabPanel.addTab("Header", sourceViewerHeader.getComponent());
            JwtEditorTabPanel.addTab("Payload", sourceViewerPayload.getComponent());
            JwtEditorTabPanel.addTab("Base64(Signature)", sourceViewerSignature.getComponent());

            editorAttackerPanel = new EditorAttackerPanel(callbacks, this);
            if(editable) {
                JwtEditorTabPanel.addTab("Attacker", editorAttackerPanel);
            }
        }

        @Override
        public String getTabCaption() {
            return "JWT";
        }

        @Override
        public Component getUiComponent() {
            return JwtEditorTabPanel;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // Enable this tab for requests containing a JOSE parameter
            if(isRequest) {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);

                // Search for JOSE header
                for (String header : requestInfo.getHeaders()) {
                    if (header.toUpperCase().startsWith("AUTHORIZATION: BEARER") && Finder.checkJwtPattern(header)) {
                        joseHeader = header;
                        joseHeaderValue = Finder.getJwtValue(joseHeader);

                        loggerInstance.log(getClass(), "Authorization HTTP Header with JOSE value found, enable JwtEditor.", Logger.LogLevel.DEBUG);
                        return true;
                    }
                }

                // Search for JOSE parameter
                for(Object param: PreferencesPanel.getParameterNames().toArray()) {
                    if(helpers.getRequestParameter(content, param.toString()) != null && Finder.checkJwtPattern(helpers.getRequestParameter(content, param.toString()).getValue())) {
                        joseParameterName = helpers.getRequestParameter(content, param.toString()).getName();

                        loggerInstance.log(getClass(), "JWT value found, enable JwtEditor.", Logger.LogLevel.DEBUG);
                        return true;
                    }
                }
            }
            return false;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                // Clear displayed content
            }
            // Set JOSE header values
            else if (joseHeader != null) {
                sourceViewerHeader.setText(null);
                sourceViewerHeader.setEditable(false);

                sourceViewerPayload.setText(null);
                sourceViewerPayload.setEditable(false);

                sourceViewerSignature.setText(null);
                sourceViewerSignature.setEditable(false);

                editorAttackerPanel.setEnabled(false);
            }
            // Set JOSE parameter values
            else if (joseParameterName != null) {

                // Retrieve JOSE parameter
                IParameter parameter = helpers.getRequestParameter(content, joseParameterName);

                String[] joseParts = Decoder.getComponents(parameter.getValue(), 3);

                sourceViewerHeader.setEditable(editable);
                sourceViewerPayload.setEditable(editable);
                sourceViewerSignature.setEditable(editable);

                String header = Decoder.getDecoded(joseParts[0]);
                String payload = Decoder.getDecoded(joseParts[1]);
                String signature = joseParts[2];

                sourceViewerHeader.setText(helpers.stringToBytes(header));
                sourceViewerPayload.setText(helpers.stringToBytes(payload));
                sourceViewerSignature.setText(helpers.stringToBytes(signature));

                editorAttackerPanel.updateAttackList();
            }

            // Remember the displayed content
            currentMessage = content;
        }

        // TODO: Beautify!
        // TODO: Outsource Header mofification function
        @Override
        public byte[] getMessage() {
            if (sourceViewerHeader.isTextModified() || sourceViewerPayload.isTextModified() || sourceViewerSignature.isTextModified()) {
                String[] components = {
                        Decoder.getEncoded(sourceViewerHeader.getText()),
                        Decoder.getEncoded(sourceViewerPayload.getText()),
                        helpers.bytesToString(sourceViewerSignature.getText())
                };

                // Update the request with the new parameter value
                if (joseHeader != null && joseHeaderValue != null) {
                    IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);
                    List<String> headers = requestInfo.getHeaders();

                    int index = 0;
                    for (String header: headers) {
                        if (header.equals(joseHeader)) {
                            headers.set(index, header.replace(joseHeaderValue, Decoder.concatComponents(components)));
                        }
                        index++;
                    }

                    return helpers.buildHttpMessage(headers, Arrays.copyOfRange(currentMessage,requestInfo.getBodyOffset(), currentMessage.length));
                }
                // Update the request with the new parameter value
                else if (joseParameterName != null) {
                    return helpers.updateParameter(currentMessage, helpers.buildParameter(joseParameterName, Decoder.concatComponents(components), IParameter.PARAM_URL));
                }
                // Some issue occurred, should not happen
                else {
                    return currentMessage;
                }

            } else {
                return currentMessage;
            }

        }

        @Override
        public boolean isModified() {
            boolean isModified = (sourceViewerHeader.isTextModified() || sourceViewerPayload.isTextModified() || sourceViewerSignature.isTextModified() || this.isModified);
            this.isModified = false;
            return isModified;
        }

        @Override
        public byte[] getSelectedData() {
            return null;
        }

        /**
         * Update all related source viewer editors
         * @param header The header JSON string
         * @param payload The payload JSON string
         * @param signature The signature base64 string
         */
        public void updateSourceViewer(String header, String payload, String signature) {
            sourceViewerHeader.setText(helpers.stringToBytes(header));
            sourceViewerPayload.setText(helpers.stringToBytes(payload));
            sourceViewerSignature.setText(helpers.stringToBytes(signature));
            this.isModified = true;
        }

        /**
         * Get the header value from sourceViewerHeader editor as string
         * @return Header JSON string
         */
        public String getHeader() {
            return helpers.bytesToString(sourceViewerHeader.getText());
        }

        /**
         * Get the payload value from sourceViewerPayload editor as string
         * @return Payload JSON string
         */
        public String getPayload() {
            return helpers.bytesToString(sourceViewerPayload.getText());
        }
    }
}

