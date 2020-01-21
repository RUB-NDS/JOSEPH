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
package eu.dety.burp.joseph.attacks;

import burp.IBurpExtenderCallbacks;
import eu.dety.burp.joseph.attacks.bleichenbacher_pkcs1.BleichenbacherPkcs1Info;
import eu.dety.burp.joseph.attacks.invalid_curve.InvalidCurveInfo;
import eu.dety.burp.joseph.attacks.key_confusion.KeyConfusionInfo;
import eu.dety.burp.joseph.attacks.signature_exclusion.SignatureExclusionInfo;
import eu.dety.burp.joseph.utilities.Logger;

import java.util.HashMap;

/**
 * Attack Loader
 * <p>
 * Class to manage all available attacks at one place.
 */
public class AttackLoader {
    private static final Logger loggerInstance = Logger.getInstance();

    /**
     * Get new list of new instances of all registered attacks
     *
     * @param callbacks
     *            {@link IBurpExtenderCallbacks} instance
     * @return HashMap with the name of the attack as string and a new instance of the attack's info class
     */
    public static HashMap<String, IAttackInfo> getRegisteredAttackInstances(IBurpExtenderCallbacks callbacks) {
        HashMap<String, IAttackInfo> registeredAttackInstances = new HashMap<>();

        /* Signature Exclusion Attack */
        SignatureExclusionInfo signatureExclusionInfo = new SignatureExclusionInfo(callbacks);
        registeredAttackInstances.put(signatureExclusionInfo.getName(), signatureExclusionInfo);
        loggerInstance.log(AttackLoader.class, "Attack registered: Signature Exclusion", Logger.LogLevel.INFO);

        /* Key Confusion Attack (aka. Algorithm Substitution) */
        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);
        registeredAttackInstances.put(keyConfusionInfo.getName(), keyConfusionInfo);
        loggerInstance.log(AttackLoader.class, "Attack registered: Key Confusion", Logger.LogLevel.INFO);

        /* Bleichenbacher Attack on RSA PKCS#1 v1.5 */
        BleichenbacherPkcs1Info bleichenbacherPkcs1Info = new BleichenbacherPkcs1Info(callbacks);
        registeredAttackInstances.put(bleichenbacherPkcs1Info.getName(), bleichenbacherPkcs1Info);
        loggerInstance.log(AttackLoader.class, "Attack registered: Bleichenbacher PKCS#1 v1.5", Logger.LogLevel.INFO);

        /* Invalid Curve Attack on Elliptic Curves */
        InvalidCurveInfo invalidCurveInfo = new InvalidCurveInfo(callbacks);
        registeredAttackInstances.put(invalidCurveInfo.getName(), invalidCurveInfo);
        loggerInstance.log(AttackLoader.class, "Attack registered: Invalid Curve", Logger.LogLevel.INFO);

        /* Attack Template Attack */
        // AttackTemplateInfo attackTemplateInfo = new AttackTemplateInfo(callbacks);
        // registeredAttackInstances.put(attackTemplateInfo.getName(), attackTemplateInfo);
        // loggerInstance.log(AttackLoader.class, "Attack registered: Attack Template", Logger.LogLevel.INFO);

        return registeredAttackInstances;
    }

}
