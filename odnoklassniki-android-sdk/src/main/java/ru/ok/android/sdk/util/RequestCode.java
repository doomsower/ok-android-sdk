package ru.ok.android.sdk.util;

import java.util.HashMap;
import java.util.Map;

import ru.ok.android.sdk.Odnoklassniki;
import ru.ok.android.sdk.OkListener;

public enum RequestCode {

    /**
     * Application authorization
     *
     * @see ru.ok.android.sdk.Odnoklassniki#requestAuthorization(String, OkAuthType, String...)
     * @see Odnoklassniki#checkValidTokens()
     */
    LOGIN,

    /**
     * Posting a feed
     *
     * @see ru.ok.android.sdk.Odnoklassniki#performPosting(String, boolean, HashMap, OkListener) `
     */
    MEDIATOPIC_POST,

    /**
     * Inviting friend to a game
     *
     * @see ru.ok.android.sdk.Odnoklassniki#performAppInvite(OkListener, HashMap)
     */
    INVITE,

    /**
     * Suggesting friend to a game
     *
     * @see ru.ok.android.sdk.Odnoklassniki#performAppSuggest(OkListener, HashMap)
     */
    SUGGEST,

    /**
     * REST API call
     *
     * @see ru.ok.android.sdk.Odnoklassniki#request(String, Map, String, OkListener)
     */
    REST,
    //
    ;

}
