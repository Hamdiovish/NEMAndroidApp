package org.nem.nac.application;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;

import org.nem.nac.ui.activities.LoginActivity;

import static android.app.Activity.RESULT_CANCELED;
import static org.nem.nac.ui.activities.LoginActivity.EXTRA_BOOL_EXIT_ATTEMPT;

/**
 * Created by Kwlee on 10/15/17.
 */

public class Share {
    public static void feedBackCancel(Activity This){
        if (Share.quitUriAppCall) {
            Intent data = new Intent();
            data.putExtra("streetkey", "streetname");
            This.setResult(RESULT_CANCELED, data);
            This.finish();
        }
    }

    public static Uri uriData=null;
    public static boolean quitUriAppCall=false;
}
