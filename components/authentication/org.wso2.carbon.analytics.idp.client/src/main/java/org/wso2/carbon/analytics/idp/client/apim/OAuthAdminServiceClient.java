package org.wso2.carbon.analytics.idp.client.apim;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceIdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceStub;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;

import java.rmi.RemoteException;

import static org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING;
import static org.wso2.carbon.analytics.idp.client.apim.CustomIdPClientConstants.OAUTH_ADMIN_SERVICE_ENDPOINT_POSTFIX;

public class OAuthAdminServiceClient {
  private OAuthAdminServiceStub oAuthAdminServiceStub;

  public OAuthAdminServiceClient(String adminServiceBaseUrl, String sessionCookie) throws AxisFault {
    String endPoint = adminServiceBaseUrl + OAUTH_ADMIN_SERVICE_ENDPOINT_POSTFIX;
    oAuthAdminServiceStub = new OAuthAdminServiceStub(endPoint);

    ServiceClient serviceClient = oAuthAdminServiceStub._getServiceClient();
    Options option = serviceClient.getOptions();
    option.setManageSession(true); 
    option.setProperty(COOKIE_STRING, sessionCookie);
  } 
   
  public OAuthConsumerAppDTO[] getAllOAuthApplicationData() throws RemoteException,
          OAuthAdminServiceIdentityOAuthAdminException {
    return oAuthAdminServiceStub.getAllOAuthApplicationData();
  }

  public OAuthConsumerAppDTO getOAuthApplicationDataByAppName(String oAuthAppName) throws RemoteException,
          OAuthAdminServiceIdentityOAuthAdminException {
    return oAuthAdminServiceStub.getOAuthApplicationDataByAppName(oAuthAppName);
  }
}
