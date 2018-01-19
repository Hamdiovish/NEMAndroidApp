package org.nem.nac;

import org.junit.Assert;
import org.junit.Test;
import org.nem.core.utils.HexEncoder;
import org.nem.nac.crypto.KeyProvider;
import org.nem.nac.models.BinaryData;
import org.nem.nac.models.EncryptedNacPrivateKey;
import org.nem.nac.models.NacPrivateKey;

public final class HBouncyCastleTest {

    public BinaryData mockBinaryData(String in) {
        byte[] bytes = HexEncoder.getBytes(in);
        return new BinaryData(bytes);
    }

    @Test
    public void testHEncryptDecryptFromDevIsCorrect()
            throws Exception {
        final NacPrivateKey originalKey =
                new NacPrivateKey("32856003a578948c24bd989cab6d2d5af594dcf266f8e373a7d6c12d87df1f4d");
        final EncryptedNacPrivateKey encrypted1 = new EncryptedNacPrivateKey("ee6045ca86511ec91af5a43a0cf8758463d7da4f38358a6c7d42bb313065c615891f216dca35b92868b6d26971e1a501069ad935dd962ad439284df5de4cde34");
        final BinaryData salt1 = mockBinaryData("d0479393b7adebbaf7dcbbd78aa693f277f8c9751f09723ba950e334db4b33ce");
        final String pass1 = "123465";

        final BinaryData eKeyDec1 = KeyProvider.deriveKey(pass1, salt1);
        final NacPrivateKey decryptedKey1 = encrypted1.decryptKey(eKeyDec1);
        Assert.assertArrayEquals("Decrypted key Dev-version is different!", originalKey.getRaw(), decryptedKey1.getRaw());
        System.out.println("Encrypted1: " + encrypted1.toString());
        System.out.println("Decrypted key from Dev-version OK");
    }

}
