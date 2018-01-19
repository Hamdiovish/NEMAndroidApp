package org.nem.nac.models.api;

import org.nem.nac.models.NacPrivateKey;

import java.math.BigInteger;

/**
 * Created by Kwlee on 12/29/17.
 */

public class RequestAnnounceHarvestApiDto {

    public String value;

    public RequestAnnounceHarvestApiDto() {
    }

    public RequestAnnounceHarvestApiDto(NacPrivateKey pkey) {
        value = pkey.toHexStr();
//        value= bytesToDec(pkey.getRaw());
    }

    private String bytesToDec(byte[] bytes){
        BigInteger bi = new BigInteger(bytes);

        // Format to decimal
        String s = bi.toString();
        return s;
    }
}
