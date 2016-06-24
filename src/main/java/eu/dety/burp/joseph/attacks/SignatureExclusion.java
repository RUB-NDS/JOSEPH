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


import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

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
public class SignatureExclusion implements IAttack {
    // Unique identifier for the attack class
    private static final String id = "signature_exclusion";
    // Full name of the attack
    private static final String name = "Signature Exclusion";
    // List of types this attack is suitable for
    // Available: jwt, jws, jwe
    private static final List<String> suitableTypes = Arrays.asList("jwt", "jws");
    // Amount of requests needed
    private static final int amountRequests = 4;

    @Override
    public void prepareAttack(IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) {

    }

    @Override
    public void performAttack() {

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
