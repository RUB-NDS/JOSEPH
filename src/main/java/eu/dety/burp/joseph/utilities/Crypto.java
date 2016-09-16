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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.util.Arrays;

public class Crypto {

    public static byte[] decryptAES(String header, byte[] key, byte[] iv, byte[] cipherBytes, byte[] authTag) throws DecryptionFailedException {
        byte[] decryptedContent;

        String encAlg = Decoder.getValueByBase64String(header, "enc").toUpperCase();

        int keyLen;
        String cipherInstance;

        switch(encAlg) {
            case "A128CBC-HS256":
                keyLen = 16;
                cipherInstance = "AES/CBC/PKCS5Padding";
                break;
            case "A192CBC-HS384":
                keyLen = 24;
                cipherInstance = "AES/CBC/PKCS5Padding";
                break;
            case "A256CBC-HS512":
                keyLen = 32;
                cipherInstance = "AES/CBC/PKCS5Padding";
                break;
            case "A128GCM":
                keyLen = 16;
                cipherInstance = "AES/GCM/NoPadding";
                break;
            case "A192GCM":
                keyLen = 24;
                cipherInstance = "AES/GCM/NoPadding";
                break;
            case "A256GCM":
                keyLen = 32;
                cipherInstance = "AES/GCM/NoPadding";
                break;
            default:
                throw new DecryptionFailedException("Could not determine encryption algorithm or it is not supported");
        }

        byte[] keyBytes = Arrays.copyOfRange(key, key.length - keyLen, key.length);

        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher;

        try {
            // Change isRestricted value of JceSecurity to allow AES key length > 128
            Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            field.setAccessible(true);
            field.set(null, java.lang.Boolean.FALSE);

            cipher = Cipher.getInstance(cipherInstance, new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));

            if (encAlg.contains("GCM")) {
                cipher.updateAAD(header.getBytes());

                // Concatenate ciphertext and authentication tag byte arrays
                byte[] concat = new byte[cipherBytes.length + authTag.length];
                System.arraycopy(cipherBytes, 0, concat, 0, cipherBytes.length);
                System.arraycopy(authTag, 0, concat, cipherBytes.length, authTag.length);

                decryptedContent = cipher.doFinal(concat);
            } else {
                decryptedContent = cipher.doFinal(cipherBytes);
            }

        } catch (Exception e) {
            throw new DecryptionFailedException(e.getMessage());
        }

        return decryptedContent;

    }
}
