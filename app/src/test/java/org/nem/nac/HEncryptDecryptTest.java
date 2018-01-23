package org.nem.nac;

import org.junit.Assert;
import org.junit.Test;
import org.nem.core.utils.HexEncoder;
import org.nem.nac.crypto.KeyProvider;
import org.nem.nac.models.BinaryData;
import org.nem.nac.models.EncryptedNacPrivateKey;
import org.nem.nac.models.NacPrivateKey;
import org.nem.nac.models.NacPublicKey;

public final class HEncryptDecryptTest {

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

    @Test
    public void testHEncryptDecryptFromPubIsCorrect()
            throws Exception {
        final NacPrivateKey originalKey =
                new NacPrivateKey("1db578e27316bb6cf00183f061f9a1e137c4b99feee22be7be7d173ff3d971ba");
        final EncryptedNacPrivateKey encrypted1 = new EncryptedNacPrivateKey("9bdb7db8e2a97abc46d46f40c5a34d0011363aa4fe9e123e1fb89091dbd0c23054914424ebe79c9836a2a66bd29d097f11d32e9cfbedf7303a02b9ea893108cb");
        final BinaryData salt1 = mockBinaryData("bee31024ca3dfcef8da9bbbb79c07d62ca4678aa593468aeaffb9887b9bd0a99");
        final String pass1 = "123465";

        final BinaryData eKeyDec1 = KeyProvider.deriveKey(pass1, salt1);
        final NacPrivateKey decryptedKey1 = encrypted1.decryptKey(eKeyDec1);
        Assert.assertArrayEquals("Decrypted key from Pub-version is different!", originalKey.getRaw(), decryptedKey1.getRaw());
        System.out.println("Encrypted1: " + encrypted1.toString());
        System.out.println("Decrypted key from Pub-version 1 OK");
    }

    @Test
    public void testHAddressesIsCorrect()
            throws Exception {

        final String expectedAddress = "NBFNBPTWROWBBFUGSI7XCKR33HAD74RONKDPQRD3";
        final String expectedAddressDashed = "NBFNBP-TWROWB-BFUGSI-7XCKR3-3HAD74-RONKDP-QRD3";
        final String expectedPubKey = "57c6fccacea03e05c11b50d755e60a07c6ec1eee204fc7834e790178068baa26";
        final NacPrivateKey originalKey =
                new NacPrivateKey("1db578e27316bb6cf00183f061f9a1e137c4b99feee22be7be7d173ff3d971ba");
        final EncryptedNacPrivateKey encrypted1 = new EncryptedNacPrivateKey("9bdb7db8e2a97abc46d46f40c5a34d0011363aa4fe9e123e1fb89091dbd0c23054914424ebe79c9836a2a66bd29d097f11d32e9cfbedf7303a02b9ea893108cb");
        final BinaryData salt1 = mockBinaryData("bee31024ca3dfcef8da9bbbb79c07d62ca4678aa593468aeaffb9887b9bd0a99");
        final String pass1 = "123465";

        final BinaryData eKeyDec1 = KeyProvider.deriveKey(pass1, salt1);
        final NacPrivateKey decryptedKey1 = encrypted1.decryptKey(eKeyDec1);
        Assert.assertArrayEquals("Decrypted key from Pub-version is different!", originalKey.getRaw(), decryptedKey1.getRaw());
        System.out.println("Encrypted1: " + encrypted1.toString());
        System.out.println("Decrypted key from Pub-version 1 OK");

        final NacPublicKey publicKey = NacPublicKey.fromPrivateKey(decryptedKey1);
        Assert.assertEquals("Public Keys are different!", publicKey.toPublicKey().toString(), expectedPubKey);
        System.out.println("Public Keys match: " + publicKey.toPublicKey().toString());
        Assert.assertEquals("Addresses are different!", publicKey.toAddress().toString(), expectedAddress);
        System.out.println("Address: " + publicKey.toAddress().toString(false));
        Assert.assertEquals("Addresses Dashed are different!", publicKey.toAddress().toString(true), expectedAddressDashed);
        System.out.println("Address Dashed: " + publicKey.toAddress().toString(true));
    }


}
