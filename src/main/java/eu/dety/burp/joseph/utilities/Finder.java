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
package eu.dety.burp.joseph.utilities;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Help functions to find JWT and JWE patterns.
 * @author Dennis Detering
 * @version 1.0
 */
public class Finder {

    /**
     * Check whether given JWT candidate matches regex pattern
     * @param candidate String containing the JWT candidate value.
     * @return boolean whether regex pattern matched or not.
     */
    public static boolean checkJwtPattern(String candidate) {
        Pattern jwtPattern = Pattern.compile("(ey[a-zA-Z0-9\\-_]+\\.ey[a-zA-Z0-9\\-_]+\\.([a-zA-Z0-9\\-_]+)?)", Pattern.CASE_INSENSITIVE);
        Matcher jwtMatcher = jwtPattern.matcher(candidate);

        return jwtMatcher.matches();
    }

    /**
     * Check whether given JWE candidate matches regex pattern
     * @param candidate String containing the JWE candidate value.
     * @return boolean whether regex pattern matched or not.
     */
    public static boolean checkJwePattern(String candidate) {
        Pattern jwePattern = Pattern.compile("(ey[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+)", Pattern.CASE_INSENSITIVE);
        Matcher jweMatcher = jwePattern.matcher(candidate);

        return jweMatcher.matches();
    }
}
