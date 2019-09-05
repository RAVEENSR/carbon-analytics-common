/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.analytics.idp.client.apim;

/**
 * External IdP Client Constants.
 */
public class CustomIdPClientConstants {

    public static final String EXTERNAL_IDP_CLIENT_TYPE = "custom"; //TODO: change this

    public static final String ADMIN_SERVICE_USERNAME = "adminServiceUsername";
    public static final String ADMIN_SERVICE_PASSWORD = "adminServicePassword";
    public static final String ADMIN_SERVICE_BASE_URL = "adminServiceBaseUrl";
    public static final String BASE_URL = "baseUrl";
    public static final String GRANT_TYPE = "grantType";
    public static final String KM_TOKEN_URL = "kmTokenUrl";
    public static final String KM_DCR_URL = "kmDcrUrl";
    public static final String KM_USERNAME = "kmUsername";
    public static final String KM_PASSWORD = "kmPassword";
    public static final String PORTAL_APP_CONTEXT = "portalAppContext";
    public static final String BR_DB_APP_CONTEXT = "businessRulesAppContext";
    public static final String SP_CLIENT_ID = "spClientId";
    public static final String PORTAL_CLIENT_ID = "portalClientId";
    public static final String BR_DB_CLIENT_ID = "businessRulesClientId";
    public static final String SP_CLIENT_SECRET = "spClientSecret";
    public static final String PORTAL_CLIENT_SECRET = "portalClientSecret";
    public static final String BR_DB_CLIENT_SECRET = "businessRulesClientSecret";
    public static final String CACHE_TIMEOUT = "cacheTimeout";
    public static final String DCR_APP_OWNER = "dcrAppOwner";
    public static final String CONNECTION_TIMEOUT = "connectionTimeout";
    public static final String READ_TIMEOUT = "readTimeout";
    public static final String EXTERNAL_SSO_LOGOUT_URL = "externalLogoutUrl";

    public static final String DEFAULT_ADMIN_SERVICE_USERNAME = "admin";
    public static final String DEFAULT_ADMIN_SERVICE_PASSWORD = "admin";
    public static final String DEFAULT_ADMIN_SERVICE_BASE_URL = "https://localhost:9443";
    public static final String DEFAULT_BASE_URL = "https://localhost:9643";
    public static final String DEFAULT_KM_TOKEN_URL = "https://localhost:9443/oauth2";
    public static final String DEFAULT_KM_DCR_URL = "https://localhost:9443/client-registration/v0.14/register";
    public static final String DEFAULT_KM_USERNAME = "admin";
    public static final String DEFAULT_KM_PASSWORD = "admin";
    public static final String DEFAULT_SP_APP_CONTEXT = "sp";
    public static final String DEFAULT_PORTAL_APP_CONTEXT = "portal";
    public static final String DEFAULT_BR_DB_APP_CONTEXT = "business-rules";
    public static final String DEFAULT_CACHE_TIMEOUT = "900";
    public static final String DEFAULT_CONNECTION_TIMEOUT = "10000";
    public static final String DEFAULT_READ_TIMEOUT = "60000";
    public static final String DEFAULT_EXTERNAL_SSO_LOGOUT_URL = "https://localhost:9443/oidc/logout";
    public static final String SSO_LOGING_ID_TOKEN_TAIL = "?id_token_hint=";
    public static final String POST_LOGOUT_REDIRECT_URI_PHRASE = "&post_logout_redirect_uri=";

    public static final String AUTHENTICATION_ADMIN_SERVICE_ENDPOINT_POSTFIX = "/services/AuthenticationAdmin";
    public static final String REMOTE_USER_STORE_MANAGER_SERVICE_ENDPOINT_POSTFIX
            = "/services/RemoteUserStoreManagerService";
    public static final String OAUTH_ADMIN_SERVICE_ENDPOINT_POSTFIX = "/services/OAuthAdminService";

    public static final String SP_APP_NAME = "sp";
    public static final String PORTAL_APP_NAME = "sp_portal";
    public static final String BR_DB_APP_NAME = "sp_business_rules";

    public static final String INTROSPECTION_URL = "introspectionUrl";

    public static final String CALLBACK_URL = "/login/callback/";
    public static final String REGEX_BASE_START = "regexp=(";
    public static final String FORWARD_SLASH = "/";
    public static final String REGEX_BASE = ".*|";
    public static final String REGEX_BASE_END = ")";

    public static final String REVOKE_POSTFIX = "/revoke";
    public static final String TOKEN_POSTFIX = "/token";
    public static final String INTROSPECT_POSTFIX = "/introspect";
    public static final String AUTHORIZE_POSTFIX = "/authorize";

    private CustomIdPClientConstants() {
    }
}
