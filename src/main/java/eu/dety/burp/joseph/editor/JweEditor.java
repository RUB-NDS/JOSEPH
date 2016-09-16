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
import eu.dety.burp.joseph.utilities.Finder;
import eu.dety.burp.joseph.utilities.JoseParameter;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import java.awt.*;
import java.util.*;

/**
 * JSON Web Token (JWE) Editor.
 * <p>
 * Display decoded JWE components.
 * @author Dennis Detering
 * @version 1.0
 */
public class JweEditor implements IMessageEditorTabFactory {
    private static final Logger loggerInstance = Logger.getInstance();
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    /**
     * Create JweEditor instance.
     * @param callbacks {@link IBurpExtenderCallbacks}.
     */
    public JweEditor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * Create a new instance of Burps own request/response viewer (IMessageEditorTab).
     * @param controller {@link IMessageEditorController}
     * @param editable True if message is editable, false otherwise.
     * @return {@link JweEditorTab} instance implementing {@link IMessageEditorTab}
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new JweEditorTab(controller, editable);
    }

    public class JweEditorTab implements IMessageEditorTab {
        private JTabbedPane JweEditorTabPanel;
        private boolean editable;
        private byte[] currentMessage;
        private boolean isModified = false;
        private JoseParameter joseParameter = null;

        private ITextEditor sourceViewerHeader;
        private ITextEditor sourceViewerCek;
        private ITextEditor sourceViewerIv;
        private ITextEditor sourceViewerCiphertext;
        private ITextEditor sourceViewerTag;

        JweEditorTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;
            this.JweEditorTabPanel = new JTabbedPane();

            // Add text editor tab for each JOSE part
            sourceViewerHeader = callbacks.createTextEditor();
            sourceViewerCek = callbacks.createTextEditor();
            sourceViewerIv = callbacks.createTextEditor();
            sourceViewerCiphertext = callbacks.createTextEditor();
            sourceViewerTag = callbacks.createTextEditor();

            JweEditorTabPanel.addTab("Header", sourceViewerHeader.getComponent());
            JweEditorTabPanel.addTab("CEK (base64)", sourceViewerCek.getComponent());
            JweEditorTabPanel.addTab("IV (base64)", sourceViewerIv.getComponent());
            JweEditorTabPanel.addTab("Ciphertext (base64)", sourceViewerCiphertext.getComponent());
            JweEditorTabPanel.addTab("AuthTag (base64)", sourceViewerTag.getComponent());

        }

        @Override
        public String getTabCaption() {
            return "JWE";
        }

        @Override
        public Component getUiComponent() {
            return JweEditorTabPanel;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // Enable this tab for requests containing a JOSE parameter
            if(isRequest) {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);

                JoseParameter joseParameterCheck = Finder.checkHeaderAndParameterForJwePattern(requestInfo);
                if(joseParameterCheck != null) {
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

                sourceViewerCek.setText(null);
                sourceViewerCek.setEditable(false);

                sourceViewerIv.setText(null);
                sourceViewerIv.setEditable(false);

                sourceViewerCiphertext.setText(null);
                sourceViewerCiphertext.setEditable(false);

                sourceViewerTag.setText(null);
                sourceViewerTag.setEditable(false);

            } else {
                String[] joseParts = Decoder.getComponents(joseParameter.getJoseValue(), 5);

                sourceViewerHeader.setEditable(editable);
                sourceViewerCek.setEditable(editable);
                sourceViewerIv.setEditable(editable);
                sourceViewerCiphertext.setEditable(editable);
                sourceViewerTag.setEditable(editable);

                String header = Decoder.getDecoded(joseParts[0]);
                String cek = joseParts[1];
                String iv = joseParts[2];
                String ciphertext = joseParts[3];
                String tag = joseParts[4];

                sourceViewerHeader.setText(helpers.stringToBytes(header));
                sourceViewerCek.setText(helpers.stringToBytes(cek));
                sourceViewerIv.setText(helpers.stringToBytes(iv));
                sourceViewerCiphertext.setText(helpers.stringToBytes(ciphertext));
                sourceViewerTag.setText(helpers.stringToBytes(tag));
            }

            // Remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            if (this.isModified()) {
                String[] components = {
                        Decoder.getEncoded(sourceViewerHeader.getText()),
                        helpers.bytesToString(sourceViewerCek.getText()),
                        helpers.bytesToString(sourceViewerIv.getText()),
                        helpers.bytesToString(sourceViewerCiphertext.getText()),
                        helpers.bytesToString(sourceViewerTag.getText())
                };

                switch(joseParameter.getOriginType()) {
                    // Update the request with the new header value
                    case HEADER:
                        IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);
                        java.util.List<String> headers = requestInfo.getHeaders();

                        for (int i = 0; i < headers.size(); i++) {
                            if (headers.get(i).startsWith(joseParameter.getName())) {
                                headers.set(i, headers.get(i).replace(joseParameter.getJoseValue(), Decoder.concatComponents(components)));
                            }
                        }

                        return helpers.buildHttpMessage(headers, Arrays.copyOfRange(currentMessage,requestInfo.getBodyOffset(), currentMessage.length));

                    // Update the request with the new parameter value
                    case PARAMETER:
                        return helpers.updateParameter(currentMessage, helpers.buildParameter(joseParameter.getName(), Decoder.concatComponents(components), joseParameter.getParameterType()));
                }

            }
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            boolean isModified = (sourceViewerHeader.isTextModified() || sourceViewerCek.isTextModified() || sourceViewerIv.isTextModified()  || sourceViewerCiphertext.isTextModified() || sourceViewerTag.isTextModified() || this.isModified);
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
         * @param cek The CEK base64string
         * @param iv The IV base64string
         * @param ciphertext The ciphertext base64string
         * @param tag The AuthTag base64string
         */
        public void updateSourceViewer(String header, String cek, String iv, String ciphertext, String tag) {
            sourceViewerHeader.setText(helpers.stringToBytes(header));
            sourceViewerCek.setText(helpers.stringToBytes(cek));
            sourceViewerIv.setText(helpers.stringToBytes(iv));
            sourceViewerCiphertext.setText(helpers.stringToBytes(ciphertext));
            sourceViewerTag.setText(helpers.stringToBytes(tag));
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
         * Get the CEK value from sourceViewerCek editor as string
         * @return CEK JSON string
         */
        public String getCek() {
            return helpers.bytesToString(sourceViewerCek.getText());
        }

        /**
         * Get the IV value from sourceViewerIv editor as string
         * @return IV JSON string
         */
        public String getIv() {
            return helpers.bytesToString(sourceViewerIv.getText());
        }

        /**
         * Get the ciphertext value from sourceViewerCiphertext editor as string
         * @return Ciphertext JSON string
         */
        public String getCiphertext() {
            return helpers.bytesToString(sourceViewerCiphertext.getText());
        }

        /**
         * Get the authentication tag value from sourceViewerTag editor as string
         * @return AuthTag JSON string
         */
        public String getTag() {
            return helpers.bytesToString(sourceViewerTag.getText());
        }
    }
}

