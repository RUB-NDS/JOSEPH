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
package eu.dety.burp.joseph;

import burp.*;

import java.awt.*;
import java.io.File;
import java.io.OutputStream;
import java.net.URL;
import java.util.*;

/**
 * Simple class implementing {@link IBurpExtenderCallbacks}
 * to mock Burp's behavior for extender callbacks
 * to be able to write according unit tests.
 */
public class BurpExtenderCallbacksMock implements IBurpExtenderCallbacks {

    @Override
    public void setExtensionName(String s) {

    }

    @Override
    public IExtensionHelpers getHelpers() {
        return null;
    }

    @Override
    public OutputStream getStdout() {
        return null;
    }

    @Override
    public OutputStream getStderr() {
        return null;
    }

    @Override
    public void registerExtensionStateListener(IExtensionStateListener iExtensionStateListener) {

    }

    @Override
    public void registerHttpListener(IHttpListener iHttpListener) {

    }

    @Override
    public void registerProxyListener(IProxyListener iProxyListener) {

    }

    @Override
    public void registerScannerListener(IScannerListener iScannerListener) {

    }

    @Override
    public void registerScopeChangeListener(IScopeChangeListener iScopeChangeListener) {

    }

    @Override
    public void registerContextMenuFactory(IContextMenuFactory iContextMenuFactory) {

    }

    @Override
    public void registerMessageEditorTabFactory(IMessageEditorTabFactory iMessageEditorTabFactory) {

    }

    @Override
    public void registerScannerInsertionPointProvider(IScannerInsertionPointProvider iScannerInsertionPointProvider) {

    }

    @Override
    public void registerScannerCheck(IScannerCheck iScannerCheck) {

    }

    @Override
    public void registerIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory iIntruderPayloadGeneratorFactory) {

    }

    @Override
    public void registerIntruderPayloadProcessor(IIntruderPayloadProcessor iIntruderPayloadProcessor) {

    }

    @Override
    public void registerSessionHandlingAction(ISessionHandlingAction iSessionHandlingAction) {

    }

    @Override
    public void unloadExtension() {

    }

    @Override
    public void addSuiteTab(ITab iTab) {

    }

    @Override
    public void removeSuiteTab(ITab iTab) {

    }

    @Override
    public void customizeUiComponent(Component component) {

    }

    @Override
    public IMessageEditor createMessageEditor(IMessageEditorController iMessageEditorController, boolean b) {
        return null;
    }

    @Override
    public String[] getCommandLineArguments() {
        return new String[0];
    }

    @Override
    public void saveExtensionSetting(String s, String s1) {

    }

    @Override
    public String loadExtensionSetting(String s) {
        return null;
    }

    @Override
    public ITextEditor createTextEditor() {
        return null;
    }

    @Override
    public void sendToRepeater(String s, int i, boolean b, byte[] bytes, String s1) {

    }

    @Override
    public void sendToIntruder(String s, int i, boolean b, byte[] bytes) {

    }

    @Override
    public void sendToIntruder(String s, int i, boolean b, byte[] bytes, java.util.List<int[]> list) {

    }

    @Override
    public void sendToSpider(URL url) {

    }

    @Override
    public IScanQueueItem doActiveScan(String s, int i, boolean b, byte[] bytes) {
        return null;
    }

    @Override
    public IScanQueueItem doActiveScan(String s, int i, boolean b, byte[] bytes, java.util.List<int[]> list) {
        return null;
    }

    @Override
    public void doPassiveScan(String s, int i, boolean b, byte[] bytes, byte[] bytes1) {

    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService iHttpService, byte[] bytes) {
        return null;
    }

    @Override
    public byte[] makeHttpRequest(String s, int i, boolean b, byte[] bytes) {
        return new byte[0];
    }

    @Override
    public boolean isInScope(URL url) {
        return false;
    }

    @Override
    public void includeInScope(URL url) {

    }

    @Override
    public void excludeFromScope(URL url) {

    }

    @Override
    public void issueAlert(String s) {

    }

    @Override
    public IHttpRequestResponse[] getProxyHistory() {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IHttpRequestResponse[] getSiteMap(String s) {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IScanIssue[] getScanIssues(String s) {
        return new IScanIssue[0];
    }

    @Override
    public void generateScanReport(String s, IScanIssue[] iScanIssues, File file) {

    }

    @Override
    public java.util.List<ICookie> getCookieJarContents() {
        return null;
    }

    @Override
    public void updateCookieJar(ICookie iCookie) {

    }

    @Override
    public void addToSiteMap(IHttpRequestResponse iHttpRequestResponse) {

    }

    @Override
    public void restoreState(File file) {

    }

    @Override
    public void saveState(File file) {

    }

    @Override
    public Map<String, String> saveConfig() {
        return null;
    }

    @Override
    public void loadConfig(Map<String, String> map) {

    }

    @Override
    public void setProxyInterceptionEnabled(boolean b) {

    }

    @Override
    public String[] getBurpVersion() {
        return new String[0];
    }

    @Override
    public void exitSuite(boolean b) {

    }

    @Override
    public ITempFile saveToTempFile(byte[] bytes) {
        return null;
    }

    @Override
    public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse iHttpRequestResponse) {
        return null;
    }

    @Override
    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse iHttpRequestResponse, java.util.List<int[]> list, java.util.List<int[]> list1) {
        return null;
    }

    @Override
    public String getToolName(int i) {
        return null;
    }

    @Override
    public void addScanIssue(IScanIssue iScanIssue) {

    }

    @Override
    public String[][] getParameters(byte[] bytes) {
        return new String[0][];
    }

    @Override
    public String[] getHeaders(byte[] bytes) {
        return new String[0];
    }

    @Override
    public void registerMenuItem(String s, IMenuItemHandler iMenuItemHandler) {

    }
}
