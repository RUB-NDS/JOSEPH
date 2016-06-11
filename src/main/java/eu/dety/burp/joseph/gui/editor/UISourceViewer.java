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
package eu.dety.burp.joseph.gui.editor;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

/**
 * Source Viewer.
 * Display syntax highlighted source code.
 * @author Dennis Detering
 * @version 1.0
 */
public class UISourceViewer extends JPanel {
    private String sourceCode = "[EMPTY]";
    private String codeStyle = SyntaxConstants.SYNTAX_STYLE_JSON;
    private boolean editable = false;
    private RSyntaxTextArea textArea;

    /**
     * Create new Source Viewer instance.
     */
    public UISourceViewer(){
        super(new BorderLayout());
        initComponent();
    }

    /**
     * Create new Source Viewer instance.
     * @param sourceCode The Code that should be highlighted.
     * @param codeStyle The syntax highlighting language.
     */
    public UISourceViewer(String sourceCode, String codeStyle) {
        super(new BorderLayout());
        setViewerContent(sourceCode, codeStyle);
        initComponent();
    }

    /**
     * Initialize UI components
     */
    private void initComponent(){
        textArea = new RSyntaxTextArea(20, 60);
        RTextScrollPane scrollPane = new RTextScrollPane(textArea);
        this.add(scrollPane);
    }

    /**
     * Set editable flag
     */
    public void setEditable(boolean editable){
        this.editable = editable;
    }

    /**
     * Set the source code and highlighting.
     * @param sourceCode The Code that should be highlighted.
     * @param codeStyle The syntax highlighting language.
     */
    public void setViewerContent(String sourceCode, String codeStyle){
        this.sourceCode = sourceCode;
        this.codeStyle = codeStyle;
        textArea.setSyntaxEditingStyle(this.codeStyle);
        textArea.setCodeFoldingEnabled(true);
        textArea.setEditable(this.editable);
        textArea.setText(this.sourceCode);
        this.updateUI();
    }

}
