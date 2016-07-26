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

import eu.dety.burp.joseph.gui.EditorAttackerPanel;
import eu.dety.burp.joseph.gui.PreferencesPanel;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Logger;
import eu.dety.burp.joseph.utilities.Finder;

import javax.swing.JTabbedPane;
import java.awt.Component;

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
                sourceViewerHeader.setText(null);
                sourceViewerHeader.setEditable(false);

                sourceViewerPayload.setText(null);
                sourceViewerPayload.setEditable(false);

                sourceViewerSignature.setText(null);
                sourceViewerSignature.setEditable(false);

                editorAttackerPanel.setEnabled(false);
            } else if (joseParameterName != null) {
                // Retrieve JOSE parameter
                IParameter parameter = helpers.getRequestParameter(content, joseParameterName);

                String[] joseParts = joseDecoder.getComponents(parameter.getValue(), 3);

                sourceViewerHeader.setEditable(editable);
                sourceViewerPayload.setEditable(editable);
                sourceViewerSignature.setEditable(editable);

                String header = joseDecoder.getDecoded(joseParts[0]);
                String payload = joseDecoder.getDecoded(joseParts[1]);
                String signature = joseParts[2];

                sourceViewerHeader.setText(header.getBytes());
                sourceViewerPayload.setText(payload.getBytes());
                sourceViewerSignature.setText(helpers.stringToBytes(signature));

                editorAttackerPanel.updateAttackList();
            }

            // Remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            String[] components = {
                joseDecoder.getEncoded(sourceViewerHeader.getText()),
                joseDecoder.getEncoded(sourceViewerPayload.getText()),
                helpers.bytesToString(sourceViewerSignature.getText())
            };

            // Update the request with the new parameter value
            return helpers.updateParameter(currentMessage, helpers.buildParameter(joseParameterName, joseDecoder.concatComponents(components), IParameter.PARAM_URL));
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
         * @param signature The signature JSON string
         */
        public void updateSourceViewer(String header, String payload, String signature) {
            sourceViewerHeader.setText(header.getBytes());
            sourceViewerPayload.setText(payload.getBytes());
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

