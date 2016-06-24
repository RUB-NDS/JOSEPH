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

import java.util.List;

/**
 * Interface defining necessary methods for attack classes
 * @author Dennis Detering
 * @version 1.0
 */
public interface IAttack {
    /**
     * Prepare the attack with loading all necessary parameter
     * @param requestResponse {@link IHttpRequestResponse} requestResponse message
     * @param requestInfo {@link IRequestInfo} analyzed request
     * @param parameter {@link IParameter} JOSE parameter
     */
    void prepareAttack(IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter);

    /**
     * Perform the attack
     */
    void performAttack();

    /**
     * Get unique attack ID
     * @return Unique identifier
     */
    String getId();

    /**
     * Get attack name
     * @return Attack name
     */
    String getName();

    /**
     * Get list of suitable JOSE types
     * @return List of suitable JOSE types
     */
    List<String> getSuitableTypes();

    /**
     * Get the amount of requests performed (guess)
     * @return Amount of requests needed
     */
    int getAmountRequests();

    /**
     * Check whether attack is suitable based on algorithm and type
     * @return boolean if attack is suitable
     */
    boolean isSuitable(String type, String algorithm);
}
