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
 * Display decoded JWT syntax highlighted.
 * @author Dennis Detering
 * @version 1.0
 */
public class JwtEditor implements IMessageEditorTabFactory {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final Decoder joseDecoder = new Decoder();
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

    private class JwtEditorTab implements IMessageEditorTab {
        private JTabbedPane JwtEditorTabPanel;
        private boolean editable;
        private byte[] currentMessage;

        private ITextEditor sourceViewerRaw;
        private ITextEditor sourceViewerHeader;
        private ITextEditor sourceViewerPayload;
        private ITextEditor sourceViewerSignature;

        JwtEditorTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;
            this.JwtEditorTabPanel = new JTabbedPane();

            // Create an instance of Burp's text editor to display raw data
            sourceViewerRaw = callbacks.createTextEditor();
            sourceViewerRaw.setEditable(editable);

            // Add text editor tab for each JOSE part
            sourceViewerHeader = callbacks.createTextEditor();
            sourceViewerPayload = callbacks.createTextEditor();
            sourceViewerSignature = callbacks.createTextEditor();

            JwtEditorTabPanel.addTab("Header", sourceViewerHeader.getComponent());
            JwtEditorTabPanel.addTab("Payload", sourceViewerPayload.getComponent());
            JwtEditorTabPanel.addTab("Base64(Signature)", sourceViewerSignature.getComponent());
            JwtEditorTabPanel.addTab("Raw", sourceViewerRaw.getComponent());
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
                sourceViewerRaw.setText(null);
                sourceViewerRaw.setEditable(false);
            }
            // Set JOSE header values
            else if (joseHeader != null) {
                sourceViewerRaw.setText(joseHeaderValue.getBytes());
                sourceViewerRaw.setEditable(editable);

                String[] joseParts = joseDecoder.getComponents(joseHeaderValue, 3);

                sourceViewerHeader.setEditable(editable);
                sourceViewerPayload.setEditable(editable);
                sourceViewerSignature.setEditable(editable);

                sourceViewerHeader.setText(joseDecoder.getDecoded(joseParts[0]).getBytes());
                sourceViewerPayload.setText(joseDecoder.getDecoded(joseParts[1]).getBytes());
                sourceViewerSignature.setText(helpers.stringToBytes(joseParts[2]));
            }
            // Set JOSE parameter values
            else if (joseParameterName != null) {
                // Retrieve JOSE parameter
                IParameter parameter = helpers.getRequestParameter(content, joseParameterName);

                sourceViewerRaw.setText(parameter.getValue().getBytes());
                sourceViewerRaw.setEditable(editable);

                String[] joseParts = joseDecoder.getComponents(parameter.getValue(), 3);

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

        // TODO: Beautify!
        // TODO: Outsource Header mofification function
        @Override
        public byte[] getMessage() {
            // Determine whether the user modified the raw data
            if (sourceViewerRaw.isTextModified()) {
                byte[] text = sourceViewerRaw.getText();

                if (joseHeader != null && joseHeaderValue != null) {
                    IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);
                    List<String> headers = requestInfo.getHeaders();

                    int index = 0;
                    for (String header : headers) {
                        if (header.equals(joseHeader)) {
                            headers.set(index, header.replace(joseHeaderValue, helpers.bytesToString(text)));
                        }
                        index++;
                    }

                    return helpers.buildHttpMessage(headers, Arrays.copyOfRange(currentMessage, requestInfo.getBodyOffset(), currentMessage.length));
                } else {
                    // Update the request with the new parameter value
                    return helpers.updateParameter(currentMessage, helpers.buildParameter(joseParameterName, helpers.bytesToString(text), IParameter.PARAM_URL));
                }

            } else if (sourceViewerHeader.isTextModified() || sourceViewerPayload.isTextModified() || sourceViewerSignature.isTextModified()) {
                String[] components = {
                    joseDecoder.getEncoded(sourceViewerHeader.getText()),
                    joseDecoder.getEncoded(sourceViewerPayload.getText()),
                    helpers.bytesToString(sourceViewerSignature.getText()),
                };

                // Update the request with the new parameter value
                if (joseHeader != null && joseHeaderValue != null) {
                    IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);
                    List<String> headers = requestInfo.getHeaders();

                    int index = 0;
                    for (String header: headers) {
                        if (header.equals(joseHeader)) {
                            headers.set(index, header.replace(joseHeaderValue, joseDecoder.concatComponents(components)));
                        }
                        index++;
                    }

                    return helpers.buildHttpMessage(headers, Arrays.copyOfRange(currentMessage,requestInfo.getBodyOffset(), currentMessage.length));
                }
                // Update the request with the new parameter value
                else if (joseParameterName != null) {
                    return helpers.updateParameter(currentMessage, helpers.buildParameter(joseParameterName, joseDecoder.concatComponents(components), IParameter.PARAM_URL));
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
            return (sourceViewerRaw.isTextModified() || sourceViewerHeader.isTextModified() || sourceViewerPayload.isTextModified() || sourceViewerSignature.isTextModified());
        }

        @Override
        public byte[] getSelectedData() {
            return sourceViewerRaw.getSelectedText();
        }
    }
}

