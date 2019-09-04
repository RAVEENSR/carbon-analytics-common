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
import org.w3c.dom.NodeList;
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

import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.analytics.idp.client.apim.CustomIdPClientConstants.*;
import static org.wso2.carbon.analytics.idp.client.apim.soap.SoapClient.callSoapWebService;
import static org.wso2.carbon.analytics.idp.client.apim.soap.SoapRequestConstants.*;

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
    private String adminServiceUsername;
    private String adminServicePassword;
    private String remoteUserStoreManagerServiceEndpointUrl;
    private String oAuthAdminServiceEndpointUrl;

    //Here the user given context are mapped to the OAuthApp Info.
    private Map<String, OAuthApplicationInfo> oAuthAppInfoMap;

    public CustomIdPClient(String baseUrl, String authorizeEndpoint, String grantType, String adminRoleDisplayName,
                           Map<String, OAuthApplicationInfo> oAuthAppInfoMap, int cacheTimeout, String kmUserName,
                           DCRMServiceStub dcrmServiceStub, OAuth2ServiceStubs oAuth2ServiceStubs, boolean isSSOEnabled,
                           String ssoLogoutURL, String adminServiceUsername, String adminServicePassword,
                           String adminServiceBaseUrl) {
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
        this.adminServiceUsername = adminServiceUsername;
        this.adminServicePassword = adminServicePassword;
        this.remoteUserStoreManagerServiceEndpointUrl =
                adminServiceBaseUrl + REMOTE_USER_STORE_MANAGER_SERVICE_ENDPOINT_POSTFIX;
        this.oAuthAdminServiceEndpointUrl = adminServiceBaseUrl + OAUTH_ADMIN_SERVICE_ENDPOINT_POSTFIX;
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

    /**
     * Sample SOAP response for getRoleNames:
     * <soapenv:Envelope xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope">
     *    <soapenv:Body>
     *       <ns:getRoleNamesResponse xmlns:ns="http://service.ws.um.carbon.wso2.org"
     *       xmlns:ax2957="http://common.mgt.user.carbon.wso2.org/xsd"
     *       xmlns:ax2948="http://core.user.carbon.wso2.org/xsd"
     *       xmlns:ax2949="http://api.user.carbon.wso2.org/xsd"
     *       xmlns:ax2952="http://tenant.core.user.carbon.wso2.org/xsd"
     *       xmlns:ax2955="http://dao.service.ws.um.carbon.wso2.org/xsd">
     *          <ns:return>admin</ns:return>
     *          <ns:return>Internal/everyone</ns:return>
     *          <ns:return>Internal/publisher</ns:return>
     *          <ns:return>Internal/creator</ns:return>
     *          <ns:return>Internal/subscriber</ns:return>
     *          <ns:return>Internal/system</ns:return>
     *          <ns:return>Application/admin_sp_business_rules</ns:return>
     *          <ns:return>Application/admin_sp_portal</ns:return>
     *          <ns:return>Application/admin_sp_status_dashboard</ns:return>
     *          <ns:return>Application/admin_sp</ns:return>
     *          <ns:return>Application/admin_store</ns:return>
     *       </ns:getRoleNamesResponse>
     *    </soapenv:Body>
     * </soapenv:Envelope>
     */
    @Override
    public List<Role> getAllRoles() throws IdPClientException {
        String soapAction = "getRoleNames";
        MimeHeaders headers = getSOAPRequestHeaders(adminServiceUsername, adminServicePassword, soapAction);
        SOAPMessage response
                = callSoapWebService(GET_ROLE_NAMES, headers, this.remoteUserStoreManagerServiceEndpointUrl);
        try {
            SOAPBody body = response.getSOAPBody();
            NodeList list = body.getElementsByTagName("ns:getRoleNamesResponse");
            return getRolesFromNodeList(list);
        } catch (SOAPException e) {
            throw new IdPClientException("Error occurred while accessing the SOAP body from the response for " +
                    "getAllRoles.", e);
        }
    }

    @Override
    public Role getAdminRole() throws IdPClientException {
        List<Role> allRoles = getAllRoles();
        for (Role allRole : allRoles) {
            if (allRole.getDisplayName().equalsIgnoreCase(this.adminRoleDisplayName)) {
                return allRole;
            }
        }
        throw new IdPClientException("No admin role found.");
    }

    /**
     * Sample SOAP response for getRoleListOfUser:
     * <soapenv:Envelope xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope">
     *    <soapenv:Body>
     *       <ns:getRoleListOfUserResponse xmlns:ns="http://service.ws.um.carbon.wso2.org"
     *       xmlns:ax2957="http://common.mgt.user.carbon.wso2.org/xsd"
     *       xmlns:ax2948="http://core.user.carbon.wso2.org/xsd"
     *       xmlns:ax2949="http://api.user.carbon.wso2.org/xsd"
     *       xmlns:ax2952="http://tenant.core.user.carbon.wso2.org/xsd"
     *       xmlns:ax2955="http://dao.service.ws.um.carbon.wso2.org/xsd">
     *          <ns:return>Internal/everyone</ns:return>
     *       </ns:getRoleListOfUserResponse>
     *    </soapenv:Body>
     * </soapenv:Envelope>
     */
    @Override
    public User getUser(String name) throws IdPClientException {
        String soapAction = "getRoleListOfUser";
        MimeHeaders headers = getSOAPRequestHeaders(adminServiceUsername, adminServicePassword, soapAction);
        String soapMessageContent = GET_ROLE_LIST_OF_USER.replaceAll("\\{name}", name);
        SOAPMessage response
                = callSoapWebService(soapMessageContent, headers, this.remoteUserStoreManagerServiceEndpointUrl);
        try {
            SOAPBody body = response.getSOAPBody();
            NodeList list = body.getElementsByTagName("ns:getRoleListOfUserResponse");
            ArrayList<Role> roles = getRolesFromNodeList(list);
            Map<String, String> properties = new HashMap<>();
            return new User(name, properties, roles);
        } catch (SOAPException e) {
            throw new IdPClientException("Error occurred while accessing the SOAP body from the response for " +
                    "getRoleListOfUser.", e);
        }
    }

    /**
     * This method returns a list of Role from a given node list.
     * @param list node list which contains role details
     * @return Array List of roles
     * @throws IdPClientException thrown when the node list is empty.
     */
    private ArrayList<Role> getRolesFromNodeList(NodeList list) throws IdPClientException {
        if (list.getLength() == 0) {
            throw new IdPClientException("Cannot get roles from the list as the node list is empty.");
        }
        ArrayList<Role> roles = new ArrayList<>();
        for (int i = 0; i < list.getLength(); i++) {
            NodeList innerList = list.item(i).getChildNodes();
            Role newRole;
            for (int j = 0; j < innerList.getLength(); j++) {
                newRole = new Role(Integer.toString(j), innerList.item(j).getTextContent());
                roles.add(newRole);
            }
        }
        return roles;
    }

    /**
     * This returns base64 encoded credentials as a string.
     * Ex: If username is "admin" and password is "admin" this will return encoded version for "admin:admin" which is
     * YWRtaW46YWRtaW4=
     *
     * @param username username
     * @param password password
     * @return String of encoded credentials
     */
    private String getBase64EncodedCredentials(String username, String password) {
        String credentials = username + ":" + password;
        return Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    /**
     *
     * This returns headers required for soap request which are Authorization and SOAPAction.
     * @param username username for authorization
     * @param password password for authorization
     * @param soapAction action name of the soap request
     * @return MimeHeaders which includes authorization and SOAPAction headers
     */
    private MimeHeaders getSOAPRequestHeaders(String username, String password, String soapAction) {
        String encodedCredentials = getBase64EncodedCredentials(username, password);
        MimeHeaders headers = new MimeHeaders();
        headers.addHeader("Authorization", "Basic " + encodedCredentials);
        headers.addHeader("SOAPAction", soapAction);
        return headers;
    }


    /**
     * Sample SOAP response for getAllOAuthApplicationData:
     * <soapenv:Envelope xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope">
     *    <soapenv:Body>
     *       <ns:getAllOAuthApplicationDataResponse xmlns:ns="http://org.apache.axis2/xsd"
     *       xmlns:ax2510="http://base.identity.carbon.wso2.org/xsd"
     *       xmlns:ax2509="http://oauth.identity.carbon.wso2.org/xsd"
     *       xmlns:ax2513="http://dto.oauth.identity.carbon.wso2.org/xsd">
     *          <ns:return xsi:type="ax2513:OAuthConsumerAppDTO" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
     *             <ax2513:OAuthVersion>OAuth-2.0</ax2513:OAuthVersion>
     *             <ax2513:applicationAccessTokenExpiryTime>3600</ax2513:applicationAccessTokenExpiryTime>
     *             <ax2513:applicationName>admin_sp_business_rules</ax2513:applicationName>
     *             <ax2513:backChannelLogoutUrl xsi:nil="true"/>
     *             <ax2513:bypassClientCredentials>false</ax2513:bypassClientCredentials>
     *             <ax2513:callbackUrl>regexp=(https://localhost:9643/login/callback/business-rules.*|
     *             https://localhost:9643/business-rules)</ax2513:callbackUrl>
     *             <ax2513:frontchannelLogoutUrl xsi:nil="true"/>
     *             <ax2513:grantTypes>password authorization_code refresh_token</ax2513:grantTypes>
     *             <ax2513:idTokenEncryptionAlgorithm>null</ax2513:idTokenEncryptionAlgorithm>
     *             <ax2513:idTokenEncryptionEnabled>false</ax2513:idTokenEncryptionEnabled>
     *             <ax2513:idTokenEncryptionMethod>null</ax2513:idTokenEncryptionMethod>
     *             <ax2513:idTokenExpiryTime>3600</ax2513:idTokenExpiryTime>
     *             <ax2513:oauthConsumerKey>nurUBoAhQKCh6llBGnZqX340NNka</ax2513:oauthConsumerKey>
     *             <ax2513:oauthConsumerSecret>tMAFcVD2u3LNKaQHpcJ7TdqsoZAa</ax2513:oauthConsumerSecret>
     *             <ax2513:pkceMandatory>false</ax2513:pkceMandatory>
     *             <ax2513:pkceSupportPlain>false</ax2513:pkceSupportPlain>
     *             <ax2513:refreshTokenExpiryTime>86400</ax2513:refreshTokenExpiryTime>
     *             <ax2513:renewRefreshTokenEnabled xsi:nil="true"/>
     *             <ax2513:requestObjectSignatureValidationEnabled>false</ax2513:requestObjectSignatureValidationEnabled>
     *             <ax2513:state xsi:nil="true"/>
     *             <ax2513:tokenType xsi:nil="true"/>
     *             <ax2513:userAccessTokenExpiryTime>3600</ax2513:userAccessTokenExpiryTime>
     *             <ax2513:username>admin@carbon.super</ax2513:username>
     *          </ns:return>
     *          <ns:return xsi:type="ax2513:OAuthConsumerAppDTO" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
     *             <ax2513:OAuthVersion>OAuth-2.0</ax2513:OAuthVersion>
     *             <ax2513:applicationAccessTokenExpiryTime>3600</ax2513:applicationAccessTokenExpiryTime>
     *             <ax2513:applicationName>admin_sp_portal</ax2513:applicationName>
     *             <ax2513:backChannelLogoutUrl xsi:nil="true"/>
     *             <ax2513:bypassClientCredentials>false</ax2513:bypassClientCredentials>
     *             <ax2513:callbackUrl>regexp=(https://localhost:9643/login/callback/portal.*
     *             |https://localhost:9643/portal)</ax2513:callbackUrl>
     *             <ax2513:frontchannelLogoutUrl xsi:nil="true"/>
     *             <ax2513:grantTypes>password authorization_code refresh_token</ax2513:grantTypes>
     *             <ax2513:idTokenEncryptionAlgorithm>null</ax2513:idTokenEncryptionAlgorithm>
     *             <ax2513:idTokenEncryptionEnabled>false</ax2513:idTokenEncryptionEnabled>
     *             <ax2513:idTokenEncryptionMethod>null</ax2513:idTokenEncryptionMethod>
     *             <ax2513:idTokenExpiryTime>3600</ax2513:idTokenExpiryTime>
     *             <ax2513:oauthConsumerKey>1tRvedePy4XG1TNutcBZJtfY6Isa</ax2513:oauthConsumerKey>
     *             <ax2513:oauthConsumerSecret>HYnrFeqffhF9O5cfBxvNkrEhgqYa</ax2513:oauthConsumerSecret>
     *             <ax2513:pkceMandatory>false</ax2513:pkceMandatory>
     *             <ax2513:pkceSupportPlain>false</ax2513:pkceSupportPlain>
     *             <ax2513:refreshTokenExpiryTime>86400</ax2513:refreshTokenExpiryTime>
     *             <ax2513:renewRefreshTokenEnabled xsi:nil="true"/>
     *             <ax2513:requestObjectSignatureValidationEnabled>false</ax2513:requestObjectSignatureValidationEnabled>
     *             <ax2513:state xsi:nil="true"/>
     *             <ax2513:tokenType xsi:nil="true"/>
     *             <ax2513:userAccessTokenExpiryTime>3600</ax2513:userAccessTokenExpiryTime>
     *             <ax2513:username>admin@carbon.super</ax2513:username>
     *          </ns:return>
     *       </ns:getAllOAuthApplicationDataResponse>
     *    </soapenv:Body>
     * </soapenv:Envelope>
     *
     * This method checks whether a given oAuth application exists using OAuthAdminService.
     * @param oAuthAppName oAuth application name
     * @return whether the application exists
     * @throws IdPClientException thrown when an error occurred when retrieving applications data from
     * OAuthAdminService service
     */
    private boolean isOAuthApplicationExists(String oAuthAppName) throws IdPClientException {
        String soapAction = "getAllOAuthApplicationData";
        MimeHeaders headers = getSOAPRequestHeaders(adminServiceUsername, adminServicePassword, soapAction);
        SOAPMessage response =
                callSoapWebService(GET_ALL_OAUTH_APPLICATION_DATA, headers, this.oAuthAdminServiceEndpointUrl);
        try {
            SOAPBody body = response.getSOAPBody();
            NodeList list = body.getElementsByTagName("ns:getAllOAuthApplicationDataResponse");
            for (int i = 0; i < list.getLength(); i++) {
                NodeList firstStepInnerList = list.item(i).getChildNodes();
                for (int j = 0; j < firstStepInnerList.getLength(); j++) {
                    NodeList secondStepInnerList = firstStepInnerList.item(j).getChildNodes();
                    //TODO: can be optimized
                    for (int k = 0; k < secondStepInnerList.getLength(); k++) {
                        if (secondStepInnerList.item(k).getNodeName().equalsIgnoreCase("ax2504:applicationName") &&
                                secondStepInnerList.item(k).getTextContent().equalsIgnoreCase(oAuthAppName)) {
                            return true;
                        }
                    }
                }  // TODO: Consider the 200 response from response for a fault soap request
            }
        } catch (SOAPException e) {
            throw new IdPClientException("Error occurred while accessing the SOAP body from the response for " +
                    "getAllOAuthApplicationData.", e);
        }
        return false;
    }

    /**
     * Sample SOAP response for getOAuthApplicationDataByAppName:
     * <soapenv:Envelope xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope">
     *    <soapenv:Body>
     *       <ns:getOAuthApplicationDataByAppNameResponse xmlns:ns="http://org.apache.axis2/xsd">
     *          <ns:return xsi:type="ax2513:OAuthConsumerAppDTO"
     *          xmlns:ax2510="http://base.identity.carbon.wso2.org/xsd"
     *          xmlns:ax2509="http://oauth.identity.carbon.wso2.org/xsd"
     *          xmlns:ax2513="http://dto.oauth.identity.carbon.wso2.org/xsd"
     *          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
     *             <ax2513:OAuthVersion>OAuth-2.0</ax2513:OAuthVersion>
     *             <ax2513:applicationAccessTokenExpiryTime>3600</ax2513:applicationAccessTokenExpiryTime>
     *             <ax2513:applicationName>admin_sp_business_rules</ax2513:applicationName>
     *             <ax2513:backChannelLogoutUrl xsi:nil="true"/>
     *             <ax2513:bypassClientCredentials>false</ax2513:bypassClientCredentials>
     *             <ax2513:callbackUrl>regexp=(https://localhost:9643/login/callback/business-rules.*
     *             |https://localhost:9643/business-rules)</ax2513:callbackUrl>
     *             <ax2513:frontchannelLogoutUrl xsi:nil="true"/>
     *             <ax2513:grantTypes>password authorization_code refresh_token</ax2513:grantTypes>
     *             <ax2513:idTokenEncryptionAlgorithm>null</ax2513:idTokenEncryptionAlgorithm>
     *             <ax2513:idTokenEncryptionEnabled>false</ax2513:idTokenEncryptionEnabled>
     *             <ax2513:idTokenEncryptionMethod>null</ax2513:idTokenEncryptionMethod>
     *             <ax2513:idTokenExpiryTime>3600</ax2513:idTokenExpiryTime>
     *             <ax2513:oauthConsumerKey>nurUBoAhQKCh6llBGnZqX340NNka</ax2513:oauthConsumerKey>
     *             <ax2513:oauthConsumerSecret>tMAFcVD2u3LNKaQHpcJ7TdqsoZAa</ax2513:oauthConsumerSecret>
     *             <ax2513:pkceMandatory>false</ax2513:pkceMandatory>
     *             <ax2513:pkceSupportPlain>false</ax2513:pkceSupportPlain>
     *             <ax2513:refreshTokenExpiryTime>86400</ax2513:refreshTokenExpiryTime>
     *             <ax2513:renewRefreshTokenEnabled xsi:nil="true"/>
     *             <ax2513:requestObjectSignatureValidationEnabled>false</ax2513:requestObjectSignatureValidationEnabled>
     *             <ax2513:state xsi:nil="true"/>
     *             <ax2513:tokenType xsi:nil="true"/>
     *             <ax2513:userAccessTokenExpiryTime>3600</ax2513:userAccessTokenExpiryTime>
     *             <ax2513:username>admin@carbon.super</ax2513:username>
     *          </ns:return>
     *       </ns:getOAuthApplicationDataByAppNameResponse>
     *    </soapenv:Body>
     * </soapenv:Envelope>
     *
     * This methods returns data of a OAuthApplication using OAuthAdminService.
     * @param oAuthAppName oAuth application name
     * @return properties Map of OAuthApplication data which includes oauthConsumerKey and oauthConsumerSecret
     * @throws IdPClientException thrown when an error occurred when retrieving application data from
     * OAuthAdminService service
     */
    private Map<String, String> getOAuthApplicationData(String oAuthAppName) throws IdPClientException {
        Map <String, String> oAuthAppDataMap = new HashMap<>();
        String soapAction = "getOAuthApplicationDataByAppName";
        MimeHeaders headers = getSOAPRequestHeaders(adminServiceUsername, adminServicePassword, soapAction);
        String soapMessageContent = GET_OAUTH_APPLICATION_DATA_BY_APP_NAME.replaceAll("\\{oAuthAppName}", oAuthAppName);
        SOAPMessage response = callSoapWebService(soapMessageContent, headers, this.oAuthAdminServiceEndpointUrl);
        try {
            SOAPBody body = response.getSOAPBody();
            NodeList list = body.getElementsByTagName("ns:getOAuthApplicationDataByAppNameResponse");
            for (int i = 0; i < list.getLength(); i++) {
                NodeList firstStepInnerList = list.item(i).getChildNodes();
                for (int j = 0; j < firstStepInnerList.getLength(); j++) {
                    NodeList secondStepInnerList = firstStepInnerList.item(j).getChildNodes();
                    //TODO: can be optimized
                    for (int k = 0; k < secondStepInnerList.getLength(); k++) {
                        if (secondStepInnerList.item(k).getNodeName().equalsIgnoreCase("ax2504:oauthConsumerKey")) {
                            oAuthAppDataMap.put("oauthConsumerKey", secondStepInnerList.item(k).getTextContent());
                        }
                        if (secondStepInnerList.item(k).getNodeName().equalsIgnoreCase("ax2504:oauthConsumerSecret")) {
                            oAuthAppDataMap.put("oauthConsumerSecret", secondStepInnerList.item(k).getTextContent());
                        }
                    }
                }
            }

        } catch (SOAPException e) {
            throw new IdPClientException("Error occurred while accessing the SOAP body from the response for " +
                    "getOAuthApplicationDataByAppName.", e);
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
        // TODO: 30/04/19 Id token null check needs to be removed after all apps support sso
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
