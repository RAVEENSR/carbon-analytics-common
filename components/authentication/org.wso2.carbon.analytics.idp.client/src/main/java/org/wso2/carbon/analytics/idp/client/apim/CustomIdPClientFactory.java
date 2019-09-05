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

import org.apache.axis2.AxisFault;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.analytics.idp.client.core.api.AnalyticsHttpClientBuilderService;
import org.wso2.carbon.analytics.idp.client.core.api.IdPClient;
import org.wso2.carbon.analytics.idp.client.core.exception.IdPClientException;
import org.wso2.carbon.analytics.idp.client.core.spi.IdPClientFactory;
import org.wso2.carbon.analytics.idp.client.core.utils.IdPClientConstants;
import org.wso2.carbon.analytics.idp.client.core.utils.config.IdPClientConfiguration;
import org.wso2.carbon.analytics.idp.client.external.impl.DCRMServiceStub;
import org.wso2.carbon.analytics.idp.client.external.impl.OAuth2ServiceStubs;
import org.wso2.carbon.analytics.idp.client.external.models.OAuthApplicationInfo;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.datasource.core.api.DataSourceService;
import org.wso2.carbon.secvault.SecretRepository;

import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Map;

/**
 * Factory for Custom IdPClient.
 */
@Component(
        name = "CustomIdPClientFactory",
        immediate = true
)
public class CustomIdPClientFactory implements IdPClientFactory {
    private static final Logger LOG = LoggerFactory.getLogger(CustomIdPClientFactory.class);
    private DataSourceService dataSourceService;
    private SecretRepository secretRepository;
    private AnalyticsHttpClientBuilderService analyticsHttpClientBuilderService;

    @Activate
    protected void activate(BundleContext bundleContext) {
        LOG.debug("External IDP client factory activated.");
    }

    @Deactivate
    protected void deactivate(BundleContext bundleContext) {
        LOG.debug("External IDP client factory deactivated.");
    }

    /**
     * Register datasource service.
     *
     * @param dataSourceService
     */
    @Reference(
            name = "org.wso2.carbon.datasource.DataSourceService",
            service = DataSourceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterDataSourceService"
    )
    protected void registerDataSourceService(DataSourceService dataSourceService) {
        this.dataSourceService = dataSourceService;
    }

    /**
     * Unregister datasource service.
     *
     * @param dataSourceService datasource service
     */
    protected void unregisterDataSourceService(DataSourceService dataSourceService) {
        this.dataSourceService = null;
    }

    /**
     * Register secret repository.
     *
     * @param secretRepository
     */
    @Reference(
            name = "org.wso2.carbon.secvault.repository.DefaultSecretRepository",
            service = SecretRepository.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterSecretRepository"
    )
    protected void registerSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    /**
     * Unregister secret repository.
     *
     * @param secretRepository
     */
    protected void unregisterSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = null;
    }

    @Reference(
            service = AnalyticsHttpClientBuilderService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterAnalyticsHttpClient"
    )
    protected void registerAnalyticsHttpClient(AnalyticsHttpClientBuilderService service) {
        this.analyticsHttpClientBuilderService = service;
        LOG.debug("@Reference(bind) AnalyticsHttpClientBuilderService at '{}'",
                AnalyticsHttpClientBuilderService.class.getName());
    }

    protected void unregisterAnalyticsHttpClient(AnalyticsHttpClientBuilderService service) {
        LOG.debug("@Reference(unbind) AnalyticsHttpClientBuilderService at '{}'",
                AnalyticsHttpClientBuilderService.class.getName());
        this.analyticsHttpClientBuilderService = null;
    }

    @Override
    public String getType() {
        return CustomIdPClientConstants.EXTERNAL_IDP_CLIENT_TYPE;
    }

    @Override
    public IdPClient getIdPClient(IdPClientConfiguration idPClientConfiguration)
            throws IdPClientException {
        Map<String, String> properties = idPClientConfiguration.getProperties();
        String adminServiceUsername = properties.getOrDefault(CustomIdPClientConstants.ADMIN_SERVICE_USERNAME,
                CustomIdPClientConstants.DEFAULT_ADMIN_SERVICE_USERNAME);
        String adminServicePassword = properties.getOrDefault(CustomIdPClientConstants.ADMIN_SERVICE_PASSWORD,
                CustomIdPClientConstants.DEFAULT_ADMIN_SERVICE_PASSWORD);
        String adminServiceBaseUrl = properties.getOrDefault(CustomIdPClientConstants.ADMIN_SERVICE_BASE_URL,
                CustomIdPClientConstants.DEFAULT_ADMIN_SERVICE_BASE_URL);

        String dcrEndpoint = properties.getOrDefault(CustomIdPClientConstants.KM_DCR_URL,
                CustomIdPClientConstants.DEFAULT_KM_DCR_URL);
        String kmUsername = properties.getOrDefault(CustomIdPClientConstants.KM_USERNAME,
                CustomIdPClientConstants.DEFAULT_KM_USERNAME);
        String kmPassword = properties.getOrDefault(CustomIdPClientConstants.KM_PASSWORD,
                CustomIdPClientConstants.DEFAULT_KM_PASSWORD);
        String kmTokenUrl = properties.getOrDefault(CustomIdPClientConstants.KM_TOKEN_URL,
                CustomIdPClientConstants.DEFAULT_KM_TOKEN_URL);
        String dcrAppOwner = properties.getOrDefault(CustomIdPClientConstants.DCR_APP_OWNER, kmUsername);
        String introspectUrl = properties.getOrDefault(CustomIdPClientConstants.INTROSPECTION_URL,
                kmTokenUrl + CustomIdPClientConstants.INTROSPECT_POSTFIX);

        String baseUrl = properties.getOrDefault(CustomIdPClientConstants.BASE_URL,
                CustomIdPClientConstants.DEFAULT_BASE_URL);
        String grantType = properties.getOrDefault(CustomIdPClientConstants.GRANT_TYPE,
                IdPClientConstants.PASSWORD_GRANT_TYPE);


        String portalAppContext = properties.getOrDefault(CustomIdPClientConstants.PORTAL_APP_CONTEXT,
                CustomIdPClientConstants.DEFAULT_PORTAL_APP_CONTEXT);
        String businessAppContext = properties.getOrDefault(CustomIdPClientConstants.BR_DB_APP_CONTEXT,
                CustomIdPClientConstants.DEFAULT_BR_DB_APP_CONTEXT);

        OAuthApplicationInfo spOAuthApp = new OAuthApplicationInfo(
                CustomIdPClientConstants.SP_APP_NAME,
                properties.get(CustomIdPClientConstants.SP_CLIENT_ID),
                properties.get(CustomIdPClientConstants.SP_CLIENT_SECRET));
        OAuthApplicationInfo portalOAuthApp = new OAuthApplicationInfo(
                CustomIdPClientConstants.PORTAL_APP_NAME,
                properties.get(CustomIdPClientConstants.PORTAL_CLIENT_ID),
                properties.get(CustomIdPClientConstants.PORTAL_CLIENT_SECRET));
        OAuthApplicationInfo businessOAuthApp = new OAuthApplicationInfo(
                CustomIdPClientConstants.BR_DB_APP_NAME,
                properties.get(CustomIdPClientConstants.BR_DB_CLIENT_ID),
                properties.get(CustomIdPClientConstants.BR_DB_CLIENT_SECRET));

        Map<String, OAuthApplicationInfo> oAuthAppInfoMap = new HashMap<>();
        oAuthAppInfoMap.put(CustomIdPClientConstants.DEFAULT_SP_APP_CONTEXT, spOAuthApp);
        oAuthAppInfoMap.put(portalAppContext, portalOAuthApp);
        oAuthAppInfoMap.put(businessAppContext, businessOAuthApp);

        int cacheTimeout, connectionTimeout, readTimeout;
        try {
            cacheTimeout = Integer.parseInt(properties.getOrDefault(CustomIdPClientConstants.CACHE_TIMEOUT,
                    CustomIdPClientConstants.DEFAULT_CACHE_TIMEOUT));
            connectionTimeout = Integer.parseInt(properties.getOrDefault(CustomIdPClientConstants.CONNECTION_TIMEOUT,
                    CustomIdPClientConstants.DEFAULT_CONNECTION_TIMEOUT));
            readTimeout = Integer.parseInt(properties.getOrDefault(CustomIdPClientConstants.READ_TIMEOUT,
                    CustomIdPClientConstants.DEFAULT_READ_TIMEOUT));
        } catch (NumberFormatException e) {
            throw new IdPClientException("Cache timeout overriding property '" +
                    properties.get(CustomIdPClientConstants.CACHE_TIMEOUT) + "' is invalid.");
        }

        DCRMServiceStub dcrmServiceStub = this.analyticsHttpClientBuilderService
                .build(kmUsername, kmPassword, connectionTimeout, readTimeout, DCRMServiceStub.class, dcrEndpoint);
        OAuth2ServiceStubs keyManagerServiceStubs = new OAuth2ServiceStubs(
                this.analyticsHttpClientBuilderService, kmTokenUrl + CustomIdPClientConstants.TOKEN_POSTFIX,
                kmTokenUrl + CustomIdPClientConstants.REVOKE_POSTFIX, introspectUrl,
                kmUsername, kmPassword, connectionTimeout, readTimeout);

        String adminRoleDisplayName = idPClientConfiguration.getUserManager().getAdminRole();

        String targetURIForRedirection = properties.getOrDefault(CustomIdPClientConstants.EXTERNAL_SSO_LOGOUT_URL,
                            CustomIdPClientConstants.DEFAULT_EXTERNAL_SSO_LOGOUT_URL);

        LoginAdminServiceClient login;
        String session;
        try {
            login = new LoginAdminServiceClient(adminServiceBaseUrl);
            session = login.authenticate(adminServiceUsername, adminServicePassword,adminServiceBaseUrl);
        } catch (AxisFault axisFault) {
            throw new IdPClientException("Error occurred while creating Login admin Service Client.",
                    axisFault.getCause());
        } catch (RemoteException | LoginAuthenticationExceptionException e) {
            throw new IdPClientException("Error occurred while authenticating admin user using Login admin Service " +
                    "Client.", e);
        }

        RemoteUserStoreManagerServiceClient remoteUserStoreManagerServiceClient;
        OAuthAdminServiceClient oAuthAdminServiceClient;

        try {
            remoteUserStoreManagerServiceClient
                    = new RemoteUserStoreManagerServiceClient(adminServiceBaseUrl, session);
        } catch (AxisFault axisFault) {
            throw new IdPClientException("Error occurred while creating Remote User Store Manager Service Client.",
                    axisFault.getCause());
        }

        try {
            oAuthAdminServiceClient
                    = new OAuthAdminServiceClient(adminServiceBaseUrl, session);
        } catch (AxisFault axisFault) {
            throw new IdPClientException("Error occurred while creating OAuth Admin Service Client.",
                    axisFault.getCause());
        }

        return new CustomIdPClient(baseUrl, kmTokenUrl + CustomIdPClientConstants.AUTHORIZE_POSTFIX, grantType,
                adminRoleDisplayName, oAuthAppInfoMap, cacheTimeout, dcrAppOwner, dcrmServiceStub,
                keyManagerServiceStubs, idPClientConfiguration.isSsoEnabled(), targetURIForRedirection,
                remoteUserStoreManagerServiceClient, oAuthAdminServiceClient);
    }
}
