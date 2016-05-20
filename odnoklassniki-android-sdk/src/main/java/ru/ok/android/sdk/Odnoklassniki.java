package ru.ok.android.sdk;

import java.io.IOException;
import java.util.Collection;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.json.JSONException;
import org.json.JSONObject;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.webkit.CookieManager;
import android.webkit.CookieSyncManager;
import ru.ok.android.sdk.util.OkAuthType;
import ru.ok.android.sdk.util.OkEncryptUtil;
import ru.ok.android.sdk.util.OkNetUtil;
import ru.ok.android.sdk.util.OkScope;
import ru.ok.android.sdk.util.OkThreadUtil;
import ru.ok.android.sdk.util.RequestCode;

public class Odnoklassniki {
    private volatile static Odnoklassniki instance;

    private final EnumMap<RequestCode, ConcurrentLinkedQueue<DeferredResponse>> deferredResponses;
    private final EnumMap<RequestCode, OkListener> listenersByRequest = new EnumMap<>(RequestCode.class);

    private Context context;

    // Application info
    protected final String appId;
    protected final String appKey;

    // Current tokens
    protected String accessToken;
    protected String sessionSecretKey;

    // Stuff
    protected final HttpClient httpClient;

    /**
     * @deprecated use {@link #createInstance(android.content.Context, String, String)} instead.
     */
    @Deprecated
    public static Odnoklassniki createInstance(final Context context, final String appId, final String appSecret, final String appKey) {
        return createInstance(context, appId, appKey);
    }

    /**
     * This method is required to be called before {@link Odnoklassniki#getInstance()}<br>
     * Note that instance is only created once. Multiple calls to this method wont' create multiple instances of the object
     */
    public static Odnoklassniki createInstance(final Context context, final String appId, final String appKey) {
        if ((appId == null) || (appKey == null)) {
            throw new IllegalArgumentException(context.getString(R.string.no_application_data));
        }
        if (instance == null) {
            synchronized (Odnoklassniki.class) {
                if (instance == null) {
                    instance = new Odnoklassniki(context.getApplicationContext(), appId, appKey);
                }
            }
        }
        return instance;
    }

    /**
     * Get previously created instance.<br>
     * You must always call {@link Odnoklassniki#createInstance(Context, String, String)} before calling this method, or {@link IllegalStateException} will be thrown
     */
    public static Odnoklassniki getInstance(Context context) {
        return getInstance();
    }

    public static Odnoklassniki getInstance() {
        if (instance == null) {
            throw new IllegalStateException("No instance available. Odnoklassniki.createInstance() needs to be called before Odnoklassniki.getInstance()");
        }
        return instance;
    }

    public static boolean hasInstance() {
        return (instance != null);
    }

    private Odnoklassniki(final Context context, final String appId, final String appKey) {
        deferredResponses = new EnumMap<>(RequestCode.class);
        for (RequestCode code : RequestCode.values()) {
            deferredResponses.put(code, new ConcurrentLinkedQueue<DeferredResponse>());
        }

        this.context = context;

        // APP INFO
        this.appId = appId;
        this.appKey = appKey;

        // HTTPCLIENT
        final HttpParams params = new BasicHttpParams();
        final SchemeRegistry registry = new SchemeRegistry();
        registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
        final ClientConnectionManager cm = new ThreadSafeClientConnManager(params, registry);
        httpClient = new DefaultHttpClient(cm, params);

        // RESTORE
        accessToken = TokenStore.getStoredAccessToken(context);
        sessionSecretKey = TokenStore.getStoredSessionSecretKey(context);
    }

    /**
     * Starts user authorization
     *
     * @param redirectUri the URI to which the access_token will be redirected
     * @param authType    selected auth type
     * @param scopes      {@link OkScope} - application request permissions as per {@link OkScope}.
     * @see OkAuthType
     */
    public final void requestAuthorization(@Nullable String redirectUri,
                                           OkAuthType authType, final String... scopes) {
        final Intent intent = new Intent(context, OkAuthActivity.class);
        intent.putExtra(Shared.PARAM_CLIENT_ID, appId);
        intent.putExtra(Shared.PARAM_APP_KEY, appKey);
        intent.putExtra(Shared.PARAM_REDIRECT_URI, redirectUri);
        intent.putExtra(Shared.PARAM_AUTH_TYPE, authType);
        intent.putExtra(Shared.PARAM_SCOPES, scopes);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }

    void onTokenResponseReceived(final Bundle result) {
        if (result == null) {
            notifyFailed(RequestCode.LOGIN, null);
        } else {
            final String accessToken = result.getString(Shared.PARAM_ACCESS_TOKEN);
            if (accessToken == null) {
                String error = result.getString(Shared.PARAM_ERROR);
                notifyFailed(RequestCode.LOGIN, error);
            } else {
                final String sessionSecretKey = result.getString(Shared.PARAM_SESSION_SECRET_KEY);
                final String refreshToken = result.getString(Shared.PARAM_REFRESH_TOKEN);
                long expiresIn = result.getLong(Shared.PARAM_EXPIRES_IN);
                this.accessToken = accessToken;
                this.sessionSecretKey = sessionSecretKey != null ? sessionSecretKey : refreshToken;
                JSONObject json = new JSONObject();
                try {
                    json.put(Shared.PARAM_ACCESS_TOKEN, this.accessToken);
                    json.put(Shared.PARAM_SESSION_SECRET_KEY, this.sessionSecretKey);
                    if (expiresIn > 0) {
                        json.put(Shared.PARAM_EXPIRES_IN, expiresIn);
                    }
                } catch (JSONException ignore) {
                }
                notifySuccess(RequestCode.LOGIN, json);
            }
        }
    }

    protected final void notifyFailed(RequestCode code, final String error) {
        OkListener listener = listenersByRequest.get(code);
        if (listener != null) {
            notifyClientFailed(listener, error);
        } else {
            deferredResponses.get(code).offer(new DeferredResponse(error));
        }
    }

    protected final void notifyClientFailed(final OkListener listener, final String error) {
        if (listener != null) {
            OkThreadUtil.executeOnMain(new Runnable() {
                public void run() {
                    listener.onError(error);
                }
            });
        }
    }

    protected final void notifySuccess(RequestCode code, final JSONObject json) {
        OkListener listener = listenersByRequest.get(code);
        if (listener != null) {
            notifyClientSuccess(listener, json);
        } else {
            deferredResponses.get(code).offer(new DeferredResponse(json));
        }
    }

    protected final void notifyClientSuccess(final OkListener listener, final JSONObject json) {
        if (listener != null) {
            OkThreadUtil.executeOnMain(new Runnable() {
                public void run() {
                    listener.onSuccess(json);
                }
            });
        }
    }

    public void clearDefferedData() {
        deferredResponses.clear();
    }

        /* **** API REQUESTS *** */

    /**
     * Call an API method and get the result as a String.
     * <p/>
     * <b>Note that those calls MUST be performed in a non-UI thread.</b>
     *
     * @param apiMethod  - odnoklassniki api method.
     * @param httpMethod - only "get" and "post" are supported.
     * @return query result
     * @throws IOException in case of a problem or the connection was aborted.
     * @see #request(String, Map, EnumSet)
     */
    @Deprecated
    public final String request(final String apiMethod, final String httpMethod) throws IOException {
        return request(apiMethod, null, httpMethod);
    }

    /**
     * Call an API method and get the result as a String.
     * <p/>
     * <b>Note that those calls MUST be performed in a non-UI thread.</b>
     *
     * @param apiMethod  - odnoklassniki api method.
     * @param params     - map of key-value params
     * @param httpMethod - only "get" and "post" are supported.
     * @return query result
     * @throws IOException
     * @see #request(String, Map, EnumSet)
     */
    @Deprecated
    public final String request(final String apiMethod, final Map<String, String> params, final String httpMethod)
            throws IOException {
        if (TextUtils.isEmpty(apiMethod)) {
            throw new IllegalArgumentException(context.getString(R.string.api_method_cant_be_empty));
        }
        Map<String, String> requestParams = new TreeMap<>();
        if ((params != null) && !params.isEmpty()) {
            requestParams.putAll(params);
        }
        requestParams.put(Shared.PARAM_APP_KEY, appKey);
        requestParams.put(Shared.PARAM_METHOD, apiMethod);
        signParameters(requestParams);
        requestParams.put(Shared.PARAM_ACCESS_TOKEN, accessToken);
        final String requestUrl = Shared.API_URL;
        String response;
        if ("post".equalsIgnoreCase(httpMethod)) {
            response = OkNetUtil.performPostRequest(httpClient, requestUrl, requestParams);
        } else {
            response = OkNetUtil.performGetRequest(httpClient, requestUrl, requestParams);
        }
        return response;
    }

    /**
     * Performs a REST API request and gets result as a string<br/>
     * <br/>
     * Note that a method is synchronous so should not be called from UI thread<br/>
     *
     * @param method REST method
     * @param params request params
     * @param mode   request mode
     * @return query result
     * @throws IOException
     * @see OkRequestMode#DEFAULT OkRequestMode.DEFAULT default request mode
     */
    public final String request(String method,
                                @Nullable Map<String, String> params,
                                @Nullable EnumSet<OkRequestMode> mode)
            throws IOException {

        if (TextUtils.isEmpty(method)) {
            throw new IllegalArgumentException(context.getString(R.string.api_method_cant_be_empty));
        }
        if (mode == null) {
            mode = OkRequestMode.DEFAULT;
        }
        Map<String, String> requestParams = new TreeMap<>();
        if ((params != null) && !params.isEmpty()) {
            requestParams.putAll(params);
        }
        requestParams.put(Shared.PARAM_APP_KEY, appKey);
        requestParams.put(Shared.PARAM_METHOD, method);
        if (mode.contains(OkRequestMode.SIGNED)) {
            signParameters(requestParams);
            requestParams.put(Shared.PARAM_ACCESS_TOKEN, accessToken);
        }
        final String requestUrl = Shared.API_URL;
        String response;
        if (mode.contains(OkRequestMode.POST)) {
            response = OkNetUtil.performPostRequest(httpClient, requestUrl, requestParams);
        } else {
            response = OkNetUtil.performGetRequest(httpClient, requestUrl, requestParams);
        }
        return response;
    }

    /**
     * Call an API method and get the result as a String.
     * <p/>
     * Note, that those calls <b>MUST be performed in a non-UI thread</b>.<br/>
     * Note, that if an api method does not return JSONObject but might return array or just a value,
     * this method should not be used. Thus it is preferable to use #request(String, Map, EnumSet) instead
     *
     * @param apiMethod  - odnoklassniki api method.
     * @param params     - map of key-value paramsRequestCode.REST,
     * @param httpMethod - only "get" and "post" are supported.
     * @param listener   - listener which will be called after method call
     * @throws IOException
     * @see #request(String, Map, EnumSet)
     */
    public final void request(final String apiMethod, final Map<String, String> params,
                              final String httpMethod, OkListener listener) throws IOException {
        setOkListener(RequestCode.REST, listener);
        String response = request(apiMethod, params, httpMethod);
        try {
            JSONObject json = new JSONObject(response);
            if (json.has(Shared.PARAM_ERROR_MSG)) {
                notifyFailed(RequestCode.REST, json.getString(Shared.PARAM_ERROR_MSG));
            } else {
                notifySuccess(RequestCode.REST, json);
            }
        } catch (JSONException e) {
            notifyFailed(RequestCode.REST, response);
        }
    }

    /**
     * Convenience method to send invitation to the application to friends.
     * <p/>
     * <b>Important: User must confirm the list of recipients. It must be obvious for user, that his action will result sending the pack of invitations to other users. Violating this rule will cause the application to be blocked by administration. In
     * case of any questions or doubts please contact API support team.</b>
     * <p/>
     * <b>Note: Use method friends.getByDevices to get user's friends having devices you are interested in.</b>
     *
     * @param friendUids     - list of recipient friend ids (required).
     * @param invitationText - invitation text (can be null).
     * @param deviceGroups   - list of device groups on which the invitation will be shown. Check {@link ru.ok.android.sdk.util.OkDevice} enum for the list of supported device groups (cannot be null).
     * @return
     * @throws IOException
     */
    public final String inviteFriends(final Collection<String> friendUids, final String invitationText, final String... deviceGroups)
            throws IOException {
        if ((friendUids == null) || friendUids.isEmpty()) {
            throw new IllegalArgumentException(context.getString(R.string.friend_uids_cant_be_empty));
        }
        final String friendsParamValue = TextUtils.join(",", friendUids);
        final Map<String, String> params = new HashMap<>();
        params.put("uids", friendsParamValue);
        if (!TextUtils.isEmpty(invitationText)) {
            params.put("text", invitationText);
        }
        if ((deviceGroups != null) && (deviceGroups.length > 0)) {
            final String deviceParamValue = TextUtils.join(",", deviceGroups);
            params.put("devices", deviceParamValue);
        }
        return request("friends.appInvite", params, "get");
    }

    /**
     * Check if access token is available (can be used to check if previously used access token and refresh token was successfully loaded from the storage).
     * Also check is it valid with method call
     */
    public final void checkValidTokens(final OkListener listener) {
        setOkListener(RequestCode.LOGIN, listener);
        checkValidTokens();
    }

    public final void checkValidTokens() {
        if (accessToken == null || sessionSecretKey == null) {
            notifyFailed(RequestCode.LOGIN, context.getString(R.string.no_valid_token));
            return;
        }

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String response = request("users.getLoggedInUser", "get");

                    if (response != null && response.length() > 2 && TextUtils.isDigitsOnly(response.substring(1, response.length() - 1))) {
                        JSONObject json = new JSONObject();
                        try {
                            json.put(Shared.PARAM_ACCESS_TOKEN, accessToken);
                            json.put(Shared.PARAM_SESSION_SECRET_KEY, sessionSecretKey);
                        } catch (JSONException ignore) {
                        }
                        notifySuccess(RequestCode.LOGIN, json);
                    } else {
                        try {
                            JSONObject json = new JSONObject(response);
                            if (json.has(Shared.PARAM_ERROR_MSG)) {
                                notifyFailed(RequestCode.LOGIN, json.getString(Shared.PARAM_ERROR_MSG));
                                return;
                            }
                        } catch (JSONException ignore) {
                        }
                        notifyFailed(RequestCode.LOGIN, response);
                    }
                } catch (IOException e) {
                    notifyFailed(RequestCode.LOGIN, e.getMessage());
                }
            }
        }).start();
    }

    /**
     * Call an API posting widget
     *
     * @param attachment      - json with publishing attachment
     * @param userTextEnabled - ability to enable user comment
     * @param args            widget arguments as specified in documentation
     * @param postingListener - listener which will be called after method call
     */
    public void performPosting(String attachment, boolean userTextEnabled,
                               @Nullable HashMap<String, String> args,
                               OkListener postingListener) {
        setOkListener(RequestCode.MEDIATOPIC_POST, postingListener);
        Intent intent = new Intent(context, OkPostingActivity.class);
        intent.putExtra(Shared.PARAM_APP_ID, appId);
        intent.putExtra(Shared.PARAM_ATTACHMENT, attachment);
        intent.putExtra(Shared.PARAM_ACCESS_TOKEN, accessToken);
        intent.putExtra(Shared.PARAM_WIDGET_ARGS, args);
        intent.putExtra(Shared.PARAM_SESSION_SECRET_KEY, sessionSecretKey);
        intent.putExtra(Shared.PARAM_USER_TEXT_ENABLE, userTextEnabled);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }

    /**
     * Calls application invite widget
     *
     * @param listener callback notification listener
     * @param args     widget arguments as specified in documentation
     */
    public void performAppInvite(OkListener listener, HashMap<String, String> args) {
        setOkListener(RequestCode.INVITE, listener);
        performAppSuggestInvite(OkAppInviteActivity.class, args);
    }

    /**
     * Calls application suggest widget
     *
     * @param listener callback notification listener
     * @param args     widget arguments as specified in documentation
     */
    public void performAppSuggest(OkListener listener, HashMap<String, String> args) {
        setOkListener(RequestCode.SUGGEST, listener);
        performAppSuggestInvite(OkAppSuggestActivity.class, args);
    }

    private void performAppSuggestInvite(Class<? extends AbstractWidgetActivity> clazz,
                                         HashMap<String, String> args) {
        Intent intent = new Intent(context, clazz);
        intent.putExtra(Shared.PARAM_APP_ID, appId);
        intent.putExtra(Shared.PARAM_ACCESS_TOKEN, accessToken);
        intent.putExtra(Shared.PARAM_SESSION_SECRET_KEY, sessionSecretKey);
        intent.putExtra(Shared.PARAM_WIDGET_ARGS, args);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }

    private void signParameters(final Map<String, String> params) {
        final StringBuilder sb = new StringBuilder();
        for (final Entry<String, String> entry : params.entrySet()) {
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        final String paramsString = sb.toString();
        final String sig = OkEncryptUtil.toMD5(paramsString + sessionSecretKey);
        params.put(Shared.PARAM_SIGN, sig);
    }

    public final void setOkListener(OkListener listener) {
        setOkListener(RequestCode.LOGIN, listener);
    }

    /**
     * Set a listener for the specified event type<br/>
     * If some response of this type were reached, the listener will be notified of them immediately<br/>
     * Recommended to be set in onResume()<br/>
     *
     * @param code     event code
     * @param listener listener (passing null will not change the listeners!)
     * @see RequestCode
     * @see #removeOkListener(RequestCode)
     */
    public final void setOkListener(RequestCode code, OkListener listener) {
        if (listener != null) {
            sendDeferredData(code, listener);
            listenersByRequest.put(code, listener);
        }
    }

    public final void removeOkListener() {
        removeOkListener(RequestCode.LOGIN);
    }

    /**
     * Removes a listener for the specified event type<br/>
     * Recommended to be unset in onPause()
     *
     * @param code event code
     * @see RequestCode
     */
    public final void removeOkListener(RequestCode code) {
        listenersByRequest.remove(code);
    }

    private void sendDeferredData(RequestCode code, OkListener listener) {
        Queue<DeferredResponse> queue = this.deferredResponses.get(code);
        while (true) {
            final DeferredResponse data = queue.poll();
            if (data == null) {
                return;
            }
            if (data.isError()) {
                notifyClientFailed(listener, data.getErrorCode());
            } else {
                notifyClientSuccess(listener, data.getResponse());
            }
        }
    }

    /**
     * Clears all token information from sdk and webView cookies
     */
    public final void clearTokens() {
        accessToken = null;
        sessionSecretKey = null;
        TokenStore.removeStoredTokens(context);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            clearCookies();
        } else {
            clearCookiesOld();
        }
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private void clearCookies() {
        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.removeAllCookies(null);
    }

    private void clearCookiesOld() {
        CookieSyncManager.createInstance(context);
        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.removeAllCookie();
    }

    private static class DeferredResponse {
        private String errorCode;
        private JSONObject response;

        public DeferredResponse(String errorCode) {
            this.errorCode = errorCode;
        }

        public DeferredResponse(JSONObject response) {
            this.response = response;
        }

        public String getErrorCode() {
            return errorCode;
        }

        public JSONObject getResponse() {
            return response;
        }

        public boolean isError() {
            return errorCode != null;
        }

        @Override
        public String toString() {
            return isError() ? errorCode : response.toString();
        }
    }
}