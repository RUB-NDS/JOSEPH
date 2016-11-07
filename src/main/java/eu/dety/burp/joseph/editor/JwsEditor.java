/**
 * JOSEPH - JavaScript Object Signing and Encryption Pentesting Helper
 * Copyright (C) 2016 Dennis Detering
 * <p>
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * <p>
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package eu.dety.burp.joseph.editor;

import burp.*;
import eu.dety.burp.joseph.gui.EditorAttackerPanel;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Finder;
import eu.dety.burp.joseph.utilities.JoseParameter;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import java.awt.*;

/**
 * JSON Web Signature (JWS) Editor.
 * <p>
 * Display decoded JWS components.
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class JwsEditor implements IMessageEditorTabFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    /**
     * Create JwsEditor instance.
     * 
     * @param callbacks
     *            {@link IBurpExtenderCallbacks}.
     */
    public JwsEditor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * Create a new instance of Burps own request/response viewer (IMessageEditorTab).
     * 
     * @param controller
     *            {@link burp.IMessageEditorController}
     * @param editable
     *            True if message is editable, false otherwise.
     * @return {@link JwsEditorTab} instance implementing {@link burp.IMessageEditorTab}
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new JwsEditorTab(controller, editable);
    }

    public class JwsEditorTab implements IMessageEditorTab {
        private JTabbedPane JwsEditorTabPanel;
        private boolean editable;
        private byte[] currentMessage;
        private boolean isModified = false;
        private JoseParameter joseParameter = null;

        private ITextEditor sourceViewerHeader;
        private ITextEditor sourceViewerPayload;
        private ITextEditor sourceViewerSignature;
        private EditorAttackerPanel editorAttackerPanel;

        JwsEditorTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;
            this.JwsEditorTabPanel = new JTabbedPane();

            // Add text editor tab for each JOSE part
            sourceViewerHeader = callbacks.createTextEditor();
            sourceViewerPayload = callbacks.createTextEditor();
            sourceViewerSignature = callbacks.createTextEditor();

            JwsEditorTabPanel.addTab("Header", sourceViewerHeader.getComponent());
            JwsEditorTabPanel.addTab("Payload", sourceViewerPayload.getComponent());
            JwsEditorTabPanel.addTab("Base64(Signature)", sourceViewerSignature.getComponent());

            editorAttackerPanel = new EditorAttackerPanel(callbacks, this);
            if (editable) {
                JwsEditorTabPanel.addTab("Attacker", editorAttackerPanel);
            }
        }

        @Override
        public String getTabCaption() {
            return "JWS";
        }

        @Override
        public Component getUiComponent() {
            return JwsEditorTabPanel;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // Enable this tab for requests containing a JOSE parameter
            if (isRequest) {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);

                JoseParameter joseParameterCheck = Finder.checkHeaderAndParameterForJwsPattern(requestInfo);
                if (joseParameterCheck != null) {
                    joseParameter = joseParameterCheck;
                    return true;
                }

            }
            return false;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null || joseParameter == null) {

                // Clear displayed content
                sourceViewerHeader.setText(null);
                sourceViewerHeader.setEditable(false);

                sourceViewerPayload.setText(null);
                sourceViewerPayload.setEditable(false);

                sourceViewerSignature.setText(null);
                sourceViewerSignature.setEditable(false);

            } else {
                String[] joseParts = Decoder.getComponents(joseParameter.getJoseValue(), 3);

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

        @Override
        public byte[] getMessage() {
            if (this.isModified()) {
                String[] components = { Decoder.getEncoded(sourceViewerHeader.getText()), Decoder.getEncoded(sourceViewerPayload.getText()),
                        helpers.bytesToString(sourceViewerSignature.getText()) };

                return JoseParameter.updateRequest(currentMessage, joseParameter, helpers, Decoder.concatComponents(components));
            }
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            boolean isModifiedResult = (sourceViewerHeader.isTextModified() || sourceViewerPayload.isTextModified() || sourceViewerSignature.isTextModified() || this.isModified);
            this.isModified = false;
            return isModifiedResult;
        }

        @Override
        public byte[] getSelectedData() {
            return null;
        }

        /**
         * Update all related source viewer editors
         * 
         * @param header
         *            The header JSON string
         * @param payload
         *            The payload JSON string
         * @param signature
         *            The signature base64 string
         */
        public void updateSourceViewer(String header, String payload, String signature) {
            sourceViewerHeader.setText(helpers.stringToBytes(header));
            sourceViewerPayload.setText(helpers.stringToBytes(payload));
            sourceViewerSignature.setText(helpers.stringToBytes(signature));
            this.isModified = true;
        }

        /**
         * Get the header value from sourceViewerHeader editor as string
         * 
         * @return Header JSON string
         */
        public String getHeader() {
            return helpers.bytesToString(sourceViewerHeader.getText());
        }

        /**
         * Get the payload value from sourceViewerPayload editor as string
         * 
         * @return Payload JSON string
         */
        public String getPayload() {
            return helpers.bytesToString(sourceViewerPayload.getText());
        }

        /**
         * Get the signature value from sourceViewerSignature editor as string
         * 
         * @return Signature base64url string
         */
        public String getSignature() {
            return helpers.bytesToString(sourceViewerSignature.getText());
        }
    }
}
