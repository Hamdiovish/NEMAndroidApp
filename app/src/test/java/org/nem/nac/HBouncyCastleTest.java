package org.nem.nac;

import junit.framework.Assert;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.Security;

public final class HBouncyCastleTest {

    private static SHA3Digest digest = new SHA3Digest(256);
    String expected151 = "3a784687a2b2ff9a2c72e22b001d33d9f2e2155a7858ff663b0990d35f14745d";
    String expected159 = "7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789";

    //final SHA3.DigestSHA3 sha3 = new SHA3.Digest256();
    @Test
    public void testSHA3_151() {
        String data = "demo";
        byte[] m = data.getBytes();
        digest.update(m, 0, m.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        Assert.assertEquals(Hex.toHexString(hash), expected151);
    }

    @Test
    public void testSHA3_159() {
        String data = "demo";
        byte[] m = data.getBytes();
        digest.update(m, 0, m.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        Assert.assertEquals(Hex.toHexString(hash), expected159);
    }

    @Test
    public void testSHA3_fix() {
        String data = "demo";
        byte[] hash = hash("KECCAK-256", data.getBytes());
        Assert.assertEquals(Hex.toHexString(hash), expected151);
    }

    private static byte[] hash(final String algorithm, final byte[] inputs) {
        MessageDigest digest = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm, "BC");
            byte[] hashedString = messageDigest.digest(inputs);
            return hashedString;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


}

