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
package eu.dety.burp.joseph.exceptions;

/**
 * AttackNotPreparedException
 *
 * Throw new exception if {@link eu.dety.burp.joseph.attacks.IAttack#performAttack()} is
 * called before being successfully prepared.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class AttackNotPreparedException extends Exception {
    public AttackNotPreparedException () {

    }

    public AttackNotPreparedException (String message) {
        super (message);
    }

    public AttackNotPreparedException (Throwable cause) {
        super (cause);
    }

    public AttackNotPreparedException (String message, Throwable cause) {
        super (message, cause);
    }
}