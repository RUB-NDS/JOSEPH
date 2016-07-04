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


/**
 * AttackPreparationFailedException
 * <p>
 * Throw new exception if the preparation of an {@link eu.dety.burp.joseph.attacks.IAttackInfo} fails.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class AttackPreparationFailedException extends Exception {
    public AttackPreparationFailedException () {

    }

    public AttackPreparationFailedException (String message) {
        super (message);
    }

    public AttackPreparationFailedException (Throwable cause) {
        super (cause);
    }

    public AttackPreparationFailedException (String message, Throwable cause) {
        super (message, cause);
    }
}