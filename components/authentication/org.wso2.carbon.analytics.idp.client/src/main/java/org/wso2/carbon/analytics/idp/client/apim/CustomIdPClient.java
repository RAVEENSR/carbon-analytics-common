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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import feign.Response;
import feign.gson.GsonDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.analytics.idp.client.apim.dto.DCRClientInfo;
import org.wso2.carbon.analytics.idp.client.apim.dto.DCRClientResponse;
import org.wso2.carbon.analytics.idp.client.apim.dto.DCRError;
import org.wso2.carbon.analytics.idp.client.core.exception.AuthenticationException;
import org.wso2.carbon.analytics.idp.client.core.exception.IdPClientException;
import org.wso2.carbon.analytics.idp.client.core.models.Role;
import org.wso2.carbon.analytics.idp.client.core.models.User;
import org.wso2.carbon.analytics.idp.client.core.utils.IdPClientConstants;
import org.wso2.carbon.analytics.idp.client.external.ExternalIdPClient;
import org.wso2.carbon.analytics.idp.client.external.dto.OAuth2IntrospectionResponse;
import org.wso2.carbon.analytics.idp.client.external.impl.DCRMServiceStub;
import org.wso2.carbon.analytics.idp.client.external.impl.OAuth2ServiceStubs;
import org.wso2.carbon.analytics.idp.client.external.models.ExternalSession;
import org.wso2.carbon.analytics.idp.client.external.models.OAuthApplicationInfo;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceIdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceUserStoreExceptionException;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.analytics.idp.client.apim.CustomIdPClientConstants.FORWARD_SLASH;
import static org.wso2.carbon.analytics.idp.client.apim.CustomIdPClientConstants.POST_LOGOUT_REDIRECT_URI_PHRASE;
import static org.wso2.carbon.analytics.idp.client.apim.CustomIdPClientConstants.REGEX_BASE;
import static org.wso2.carbon.analytics.idp.client.apim.CustomIdPClientConstants.REGEX_BASE_END;

/**
 * Implementation class for custom IdP based on OAuth2.
 */
public class CustomIdPClient extends ExternalIdPClient {

    private static final Logger LOG = LoggerFactory.getLogger(CustomIdPClient.class);

    private DCRMServiceStub dcrmServiceStub;
    private OAuth2ServiceStubs oAuth2ServiceStubs;
    private String kmUserName;
    private String baseUrl;
    private String adminRoleDisplayName;
    private Cache<String, ExternalSession> tokenCache;
    private boolean isSSOEnabled;
    private String ssoLogoutURL;
    private RemoteUserStoreManagerServiceClient remoteUserStoreManagerServiceClient;
    private OAuthAdminServiceClient oAuthAdminServiceClient;

    // Here the user given context are mapped to the OAuthApp Info.
    private Map<String, OAuthApplicationInfo> oAuthAppInfoMap;

    public CustomIdPClient(String baseUrl, String authorizeEndpoint, String grantType, String adminRoleDisplayName,
                           Map<String, OAuthApplicationInfo> oAuthAppInfoMap, int cacheTimeout, String kmUserName,
                           DCRMServiceStub dcrmServiceStub, OAuth2ServiceStubs oAuth2ServiceStubs, boolean isSSOEnabled,
                           String ssoLogoutURL, RemoteUserStoreManagerServiceClient remoteUserStoreManagerServiceClient,
                           OAuthAdminServiceClient oAuthAdminServiceClient) {
        super(baseUrl,authorizeEndpoint, grantType, null, adminRoleDisplayName, oAuthAppInfoMap, cacheTimeout,
                null, dcrmServiceStub, oAuth2ServiceStubs, null, null,
                isSSOEnabled, ssoLogoutURL);
        this.baseUrl = baseUrl;
        this.oAuthAppInfoMap = oAuthAppInfoMap;
        this.adminRoleDisplayName = adminRoleDisplayName;
        this.kmUserName = kmUserName;
        this.dcrmServiceStub = dcrmServiceStub;
        this.oAuth2ServiceStubs = oAuth2ServiceStubs;
        this.tokenCache = CacheBuilder.newBuilder()
                .expireAfterWrite(cacheTimeout, TimeUnit.SECONDS)
                .build();
        this.isSSOEnabled = isSSOEnabled;
        this.ssoLogoutURL = ssoLogoutURL;
        this.remoteUserStoreManagerServiceClient = remoteUserStoreManagerServiceClient;
        this.oAuthAdminServiceClient = oAuthAdminServiceClient;
    }

    @Override
    public void init(String kmUserName) throws IdPClientException {
        for (Map.Entry<String, OAuthApplicationInfo> entry : this.oAuthAppInfoMap.entrySet()) {
            String appContext = entry.getKey();
            OAuthApplicationInfo oAuthApp = entry.getValue();

            String clientId = oAuthApp.getClientId();
            String clientSecret = oAuthApp.getClientSecret();
            String clientName = oAuthApp.getClientName();
            if (clientId != null && clientSecret != null) {
                OAuthApplicationInfo newOAuthApp = new OAuthApplicationInfo(clientName, clientId, clientSecret);
                this.oAuthAppInfoMap.replace(appContext, newOAuthApp);
            } else {
                registerApplication(appContext, clientName, kmUserName);
            }
        }
    }

    @Override
    public List<Role> getAllRoles() throws IdPClientException {
        try {
            String[] roleNames = this.remoteUserStoreManagerServiceClient.getRoleNames();
            return getRolesFromArray(roleNames);
        } catch (RemoteException | RemoteUserStoreManagerServiceUserStoreExceptionException e) {
            throw new IdPClientException("Error occurred while getting all the role names.", e);
        }
    }

    @Override
    public Role getAdminRole() throws IdPClientException {
        List<Role> allRoles = getAllRoles();
        for (Role role : allRoles) {
            if (role.getDisplayName().equalsIgnoreCase(this.adminRoleDisplayName)) {
                return role;
            }
        }
        throw new IdPClientException("No admin role found.");
    }

    @Override
    public User getUser(String name) throws IdPClientException {
        try {
            String[] roleNames = this.remoteUserStoreManagerServiceClient.getRoleListOfUser(name);
            ArrayList<Role> roles = getRolesFromArray(roleNames);
            Map<String, String> properties = new HashMap<>();
            return new User(name, properties, roles);
        } catch (RemoteException | RemoteUserStoreManagerServiceUserStoreExceptionException e) {
            throw new IdPClientException("Error occurred while getting the user.", e);
        }
    }

    /**
     * This method returns a list of Roles from a given String array role.
     * @param roleNames String array which contains role names
     * @return Array List of roles
     * @throws IdPClientException thrown when the node list is empty.
     */
    private ArrayList<Role> getRolesFromArray(String[] roleNames) throws IdPClientException {
        if (roleNames.length == 0) {
            throw new IdPClientException("Cannot get roles from the list as the role list is empty.");
        }
        ArrayList<Role> roles = new ArrayList<>();
        Role newRole;
        for (int i = 0; i < roleNames.length; i++) {
            newRole = new Role(Integer.toString(i), roleNames[i]);
            roles.add(newRole);
        }
        return roles;
    }

    /**
     * This method checks whether a given oAuth application exists using OAuthAdminService.
     * @param oAuthAppName oAuth application name
     * @return whether the application exists
     * @throws IdPClientException thrown when an error occurred when retrieving applications data from
     * OAuthAdminService service
     */
    private boolean isOAuthApplicationExists(String oAuthAppName) throws IdPClientException {
        try {
            OAuthConsumerAppDTO[] oAuthApps = this.oAuthAdminServiceClient.getAllOAuthApplicationData();
            for (int i = 0; i < oAuthApps.length; i++) {
                if (oAuthApps[i].getApplicationName().equalsIgnoreCase(oAuthAppName)) {
                    return true;
                }
            }
        } catch (RemoteException | OAuthAdminServiceIdentityOAuthAdminException e) {
            throw new IdPClientException("Error occurred while getting all the OAuth application data.", e);
        }
        return false;
    }

    /**
     * This methods returns data of a OAuthApplication using OAuthAdminService.
     * @param oAuthAppName oAuth application name
     * @return properties Map of OAuthApplication data which includes oauthConsumerKey and oauthConsumerSecret
     * @throws IdPClientException thrown when an error occurred when retrieving application data from
     * OAuthAdminService service
     */
    private Map<String, String> getOAuthApplicationData(String oAuthAppName) throws IdPClientException {
        Map <String, String> oAuthAppDataMap = new HashMap<>();
        try {
            OAuthConsumerAppDTO oAuthApp = this.oAuthAdminServiceClient.getOAuthApplicationDataByAppName(oAuthAppName);
            oAuthAppDataMap.put("oauthConsumerKey", oAuthApp.getOauthConsumerKey());
            oAuthAppDataMap.put("oauthConsumerSecret",oAuthApp.getOauthConsumerSecret());
        } catch (RemoteException | OAuthAdminServiceIdentityOAuthAdminException e) {
            throw new IdPClientException("Error occurred while getting the OAuth application data for the " +
                    "application name:" + oAuthAppName, e);
        }
        if (oAuthAppDataMap.isEmpty()) {
            throw new IdPClientException("No OAuth Application data found for the application name: " + oAuthAppName);
        }
        return oAuthAppDataMap;
    }

    @Override
    public Map<String, String> login(Map<String, String> properties) throws IdPClientException {
        this.init(this.kmUserName);
        return super.login(properties);
    }

    @Override
    public Map<String, String> logout(Map<String, String> properties) throws IdPClientException {
        String token = properties.get(IdPClientConstants.ACCESS_TOKEN);
        String oAuthAppContext = properties.getOrDefault(IdPClientConstants.APP_NAME,
                CustomIdPClientConstants.DEFAULT_SP_APP_CONTEXT);
        if (!this.oAuthAppInfoMap.keySet().contains(oAuthAppContext)) {
            oAuthAppContext = CustomIdPClientConstants.DEFAULT_SP_APP_CONTEXT;
        }
        tokenCache.invalidate(token);
        oAuth2ServiceStubs.getRevokeServiceStub().revokeAccessToken(
                token,
                this.oAuthAppInfoMap.get(oAuthAppContext).getClientId(),
                this.oAuthAppInfoMap.get(oAuthAppContext).getClientSecret());

        Map<String, String> returnProperties = new HashMap<>();
        String idToken = properties.getOrDefault(IdPClientConstants.ID_TOKEN_KEY, null);
        // TODO: Id token null check needs to be removed after all apps support sso
        if (!isSSOEnabled || idToken == null) {
            returnProperties.put(IdPClientConstants.RETURN_LOGOUT_PROPERTIES, "false");
        } else {
            String postLogoutRedirectUrl = this.baseUrl + FORWARD_SLASH + oAuthAppContext;

            returnProperties.put(IdPClientConstants.RETURN_LOGOUT_PROPERTIES, "true");
            String targetURIForRedirection = ssoLogoutURL
                    .concat(CustomIdPClientConstants.SSO_LOGING_ID_TOKEN_TAIL)
                    .concat(idToken)
                    .concat(POST_LOGOUT_REDIRECT_URI_PHRASE)
                    .concat(postLogoutRedirectUrl);
            returnProperties.put(CustomIdPClientConstants.EXTERNAL_SSO_LOGOUT_URL, targetURIForRedirection);
        }
        return returnProperties;
    }

    @Override
    public String authenticate(String token) throws AuthenticationException, IdPClientException {
        ExternalSession session = tokenCache.getIfPresent(token);
        if (session != null) {
            return session.getUserName();
        }

        Response response = oAuth2ServiceStubs.getIntrospectionServiceStub()
                .introspectAccessToken(token);

        if (response == null) {
            String error = "Error occurred while authenticating token '" + token + "'. Response is null.";
            LOG.error(error);
            throw new IdPClientException(error);
        }
        try {
            if (response.status() == 200) {  //200 - OK
                OAuth2IntrospectionResponse introspectResponse = (OAuth2IntrospectionResponse) new GsonDecoder()
                        .decode(response, OAuth2IntrospectionResponse.class);
                if (introspectResponse.isActive()) {
                    String username = introspectResponse.getUsername();
                    tokenCache.put(username, new ExternalSession(username, token));
                    return username;
                } else {
                    throw new AuthenticationException("The token is not active");
                }
            } else if (response.status() == 400) {  //400 - Known Error
                try {
                    DCRError error = (DCRError) new GsonDecoder().decode(response, DCRError.class);
                    throw new IdPClientException("Error occurred while introspecting the token. Error: " +
                            error.getErrorCode() + ". Error Description: " + error.getErrorDescription() +
                            ". Status Code: " + response.status());
                } catch (IOException e) {
                    throw new IdPClientException("Error occurred while parsing the Introspection error message.", e);
                }
            } else {  //Unknown Error
                throw new IdPClientException("Error occurred while authenticating. Error: '" +
                        response.body().toString() + "'. Status Code: '" + response.status() + "'.");
            }
        } catch (IOException e) {
            throw new IdPClientException("Error occurred while parsing the authentication response.", e);
        }
    }

    /**
     * This method registers a application using a DCR call if the OAuth application does not exists. If is exists it
     * retrieves the application data and saved in oAuthAppInfoMap.
     * @param appContext  context of the application
     * @param clientName name of the client
     * @param kmUserName username of the key manager
     * @throws IdPClientException thrown when an error occurred when sending the DCR call or retrieving application
     * data using OAuthAdminService service
     */
    private void registerApplication(String appContext, String clientName, String kmUserName)
            throws IdPClientException {

        if (isOAuthApplicationExists( kmUserName + "_" + clientName)) {
            Map <String, String> oAuthAppDataMap = getOAuthApplicationData(kmUserName + "_" + clientName);
            OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo(
                    clientName, oAuthAppDataMap.get("oauthConsumerKey"), oAuthAppDataMap.get("oauthConsumerSecret")
            );
            this.oAuthAppInfoMap.replace(appContext, oAuthApplicationInfo);
            return;
        }

        String grantType =
                IdPClientConstants.PASSWORD_GRANT_TYPE + " " + IdPClientConstants.AUTHORIZATION_CODE_GRANT_TYPE + " " +
                        IdPClientConstants.REFRESH_GRANT_TYPE;
        String callBackUrl;
        String postLogoutRedirectUrl = this.baseUrl + FORWARD_SLASH + appContext;
        if (clientName.equals(CustomIdPClientConstants.DEFAULT_SP_APP_CONTEXT)) {
            callBackUrl = CustomIdPClientConstants.REGEX_BASE_START + this.baseUrl +
                    CustomIdPClientConstants.CALLBACK_URL + REGEX_BASE + postLogoutRedirectUrl + REGEX_BASE_END;
        } else {
            callBackUrl = CustomIdPClientConstants.REGEX_BASE_START + this.baseUrl +
                    CustomIdPClientConstants.CALLBACK_URL + appContext + REGEX_BASE + postLogoutRedirectUrl
                    + REGEX_BASE_END;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating OAuth2 application of name '" + clientName + "'.");
        }
        DCRClientInfo dcrClientInfo = new DCRClientInfo();
        dcrClientInfo.setClientName(clientName);
        dcrClientInfo.setGrantType(grantType);
        dcrClientInfo.setCallbackUrl(callBackUrl);
        dcrClientInfo.setSaasApp(true);
        dcrClientInfo.setOwner(kmUserName);

        Response response = dcrmServiceStub.registerApplication(new Gson().toJson(dcrClientInfo));
        if (response == null) {
            String error = "Error occurred while DCR application '" + dcrClientInfo + "' creation. " +
                    "Response is null.";
            LOG.error(error);
            throw new IdPClientException(error);
        }
        if (response.status() == 200) {  //200 - OK
            try {
                DCRClientResponse dcrClientInfoResponse = (DCRClientResponse) new GsonDecoder()
                        .decode(response, DCRClientResponse.class);
                OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo(
                        clientName, dcrClientInfoResponse.getClientId(), dcrClientInfoResponse.getClientSecret()
                );
                this.oAuthAppInfoMap.replace(appContext, oAuthApplicationInfo);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("OAuth2 application created: " + oAuthApplicationInfo.toString());
                }
            } catch (IOException e) {
                String error = "Error occurred while parsing the DCR application creation response " +
                        "message. Response: '" + response.body().toString() + "'.";
                LOG.error(error, e);
                throw new IdPClientException(error, e);
            }
        } else if (response.status() == 400) {  //400 - Known Error
            try {
                DCRError error = (DCRError) new GsonDecoder().decode(response, DCRError.class);
                String errorMessage = "Error occurred while DCR application creation. Error: " +
                        error.getErrorCode() + ". Error Description: " + error.getErrorDescription() +
                        ". Status Code: " + response.status();
                LOG.error(errorMessage);
                throw new IdPClientException(errorMessage);
            } catch (IOException e) {
                String error = "Error occurred while parsing the DCR error message. Error: " +
                        "'" + response.body().toString() + "'.";
                LOG.error(error, e);
                throw new IdPClientException(error, e);
            }
        } else {  //Unknown Error
            String error = "Error occurred while DCR application creation. Error: '" +
                    response.body().toString() + "'. Status Code: '" + response.status() + "'.";
            LOG.error(error);
            throw new IdPClientException(error);
        }
    }
}
