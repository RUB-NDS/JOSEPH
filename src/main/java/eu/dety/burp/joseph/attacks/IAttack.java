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

import eu.dety.burp.joseph.exceptions.AttackNotPreparedException;
import eu.dety.burp.joseph.exceptions.AttackPreparationFailedException;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

import java.util.List;

/**
 * Interface defining necessary methods for attack classes
 * @author Dennis Detering
 * @version 1.0
 */
public interface IAttack {
    /**
     * Prepare the attack by loading all necessary parameter
     * @param requestResponse {@link IHttpRequestResponse} requestResponse message
     * @param requestInfo {@link IRequestInfo} analyzed request
     * @param parameter {@link IParameter} JOSE parameter
     * @return true if attack preparation was successful
     */
    void prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) throws AttackPreparationFailedException;

    /**
     * Perform the attack
     */
    void performAttack() throws AttackNotPreparedException;

    /**
     * Return the result as list of IHttpRequestResponse objects
     * @return list of IHttpRequestResponse objects
     */
    List<IHttpRequestResponse> getResult();

    /**
     * Get unique attack ID
     * @return Unique identifier string
     */
    String getId();

    /**
     * Get attack name
     * @return Attack name string
     */
    String getName();

    /**
     * Get list of suitable JOSE types
     * @return List of suitable JOSE types
     */
    List<String> getSuitableTypes();

    /**
     * Get the amount of requests performed
     * @return Amount of requests needed
     */
    int getAmountRequests();

    /**
     * Check whether attack is suitable based on algorithm and type values
     * @param type JOSE header type value string
     * @param algorithm JOSE header algorithm value string
     * @return true if attack is suitable
     */
    boolean isSuitable(String type, String algorithm);
}
