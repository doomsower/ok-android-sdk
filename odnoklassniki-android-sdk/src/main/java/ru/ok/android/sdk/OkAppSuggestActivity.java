package ru.ok.android.sdk;

import ru.ok.android.sdk.util.RequestCode;

public class OkAppSuggestActivity extends OkAppInviteActivity {

    protected int getActivityView() {
        return R.layout.ok_app_suggest_activity;
    }

    @Override
    protected String getWidgetId() {
        return "WidgetSuggest";
    }

    @Override
    protected RequestCode getRequestCode() {
        return RequestCode.SUGGEST;
    }

    @Override
    protected int getCancelledMessageId() {
        return R.string.suggest_canceled;
    }

}
