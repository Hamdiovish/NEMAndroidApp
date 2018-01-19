package org.nem.nac.tasks;

import android.support.annotation.NonNull;
import android.util.Log;

import com.annimon.stream.Optional;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import org.nem.core.crypto.DsaSigner;
import org.nem.core.crypto.KeyPair;
import org.nem.core.crypto.ed25519.Ed25519DsaSigner;
import org.nem.core.utils.HexEncoder;
import org.nem.nac.R;
import org.nem.nac.application.NacApplication;
import org.nem.nac.common.exceptions.NacException;
import org.nem.nac.common.exceptions.NoNetworkException;
import org.nem.nac.common.utils.AssertUtils;
import org.nem.nac.common.utils.ErrorUtils;
import org.nem.nac.common.utils.IOUtils;
import org.nem.nac.common.utils.LogUtils;
import org.nem.nac.crypto.NacCryptoException;
import org.nem.nac.http.NisApi;
import org.nem.nac.http.ServerErrorException;
import org.nem.nac.http.ServerResponse;
import org.nem.nac.log.LogTags;
import org.nem.nac.models.AnnounceResult;
import org.nem.nac.models.BinaryData;
import org.nem.nac.models.EncryptedNacPrivateKey;
import org.nem.nac.models.NacPrivateKey;
import org.nem.nac.models.SignedBinaryData;
import org.nem.nac.models.api.ApiResultCode;
import org.nem.nac.models.api.HarvestingInfoArrayApiDto;
import org.nem.nac.models.api.RequestAnnounceApiDto;
import org.nem.nac.models.api.RequestAnnounceHarvestApiDto;
import org.nem.nac.models.api.transactions.AnnounceRequestResultApiDto;
import org.nem.nac.models.primitives.AddressValue;
import org.nem.nac.models.transactions.drafts.AbstractTransactionDraft;
import org.nem.nac.providers.EKeyProvider;
import org.nem.nac.ui.activities.NacBaseActivity;
import org.nem.nac.ui.utils.Toaster;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicReference;

import timber.log.Timber;

/**
 * Created by Kwlee on 12/28/17.
 */

public final class SetHarvestLockTask extends BaseAsyncTask<SetHarvestLockTask, Void, Void, AnnounceResult> {

    private AddressValue _address;
    private boolean _lock;


    private final AtomicReference<byte[]> _serializedTransaction = new AtomicReference<>();
    private final AtomicReference<AbstractTransactionDraft> _transaction  = new AtomicReference<>();

    @NonNull
    private final EncryptedNacPrivateKey _tranSigner;

    public SetHarvestLockTask(final NacBaseActivity activity, final AddressValue address, final boolean lock, @NonNull EncryptedNacPrivateKey tranSigner) {
        super(activity, R.string.progress_dialog_message_waiting_for_server);
        AssertUtils.notNull(address);

        _address = address;
        _lock=lock;
        _tranSigner = tranSigner;
    }

    @Override
    protected AnnounceResult doInBackground(final Void... params) {
        Optional<BinaryData> eKey = EKeyProvider.instance().getKey();
        if (!eKey.isPresent()) {
            Timber.e("No key present");
            return null;
        }

        if (!populateServer()) {
            Toaster.instance().show(R.string.errormessage_no_server);
            return null;
        }

        /////// private key //////
        final NacPrivateKey privateKey;
        try {
            privateKey = _tranSigner.decryptKey(eKey.get());
        } catch (NacCryptoException e) {
            Toaster.instance().show(R.string.errormessage_account_error, Toaster.Length.LONG);
            Timber.e("Decryption failed!");
            return null;
        }

        final RequestAnnounceHarvestApiDto announceDto = new RequestAnnounceHarvestApiDto(privateKey);
        final NisApi api = new NisApi();
        try {
            final ServerResponse<AnnounceRequestResultApiDto> response =
                    api.setHarvestLock(server, announceDto, _lock);
            final AnnounceRequestResultApiDto announceResult = response.model;
            final String message;
            if (announceResult.code.getCode() != ApiResultCode.UNKNOWN) {
                message = NacApplication.getResString(announceResult.code.getMessageRes());
            }
            else {
                message = announceResult.message;
            }
            Timber.d("Tran announced with message: %s", message);
            return new AnnounceResult(announceResult.isSuccessful(), message, null);
        } catch (ServerErrorException e) {
            String error = e.getReadableError(NacApplication.getResString(R.string.errormessage_error_occured));
            Timber.w("Server returned an error: %s", error);
            Toaster.instance().show(R.string.errormessage_server_error_occured);
        } catch (NoNetworkException e) {
            Timber.w("No network");
            return null;
        } catch (IOException e) {
            Timber.e(e, "Http request failed");
            Toaster.instance().show(R.string.errormessage_http_request_failed);
        }
        return null;
    }

    private String getPostData(NacPrivateKey privateKey){
        String pkeyDec= bytesToDec(privateKey.getRaw());
        JsonObject json = new JsonObject();
//        json.addProperty("value", pkeyDec);
        json.addProperty("value", privateKey.toHexStr());
        String jsonstr=new Gson().toJson(json);
        System.out.println(String.format("142- pkey: %s==%s==%s==", privateKey.toHexStr(),
                pkeyDec, jsonstr ));
        return  jsonstr;
    }

    private String bytesToDec(byte[] bytes){
        BigInteger bi = new BigInteger(bytes);

        // Format to decimal
        String s = bi.toString();
        return s;
    }

}
