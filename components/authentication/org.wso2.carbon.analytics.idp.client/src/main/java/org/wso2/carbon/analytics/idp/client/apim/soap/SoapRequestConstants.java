/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.analytics.idp.client.apim.soap;

/**
 * Soap request body content related constants.
 */
public class SoapRequestConstants {

    public static final String GET_ROLE_NAMES =
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:ser=\"http://service.ws.um.carbon.wso2.org\">\n" +
            "   <soap:Header/>\n" +
            "   <soap:Body>\n" +
            "      <ser:getRoleNames/>\n" +
            "   </soap:Body>\n" +
            "</soap:Envelope>";

    public static final String GET_ROLE_LIST_OF_USER =
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
                    "xmlns:ser=\"http://service.ws.um.carbon.wso2.org\">\n" +
                    "   <soap:Header/>\n" +
                    "   <soap:Body>\n" +
                    "      <ser:getRoleListOfUser>\n" +
                    "         <!--Optional:-->\n" +
                    "         <ser:userName>{name}</ser:userName>\n" +
                    "      </ser:getRoleListOfUser>\n" +
                    "   </soap:Body>\n" +
                    "</soap:Envelope>";

    public static final String GET_ALL_OAUTH_APPLICATION_DATA =
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
                    "xmlns:xsd=\"http://org.apache.axis2/xsd\">\n" +
                    "   <soap:Header/>\n" +
                    "   <soap:Body>\n" +
                    "      <xsd:getAllOAuthApplicationData/>\n" +
                    "   </soap:Body>\n" +
                    "</soap:Envelope>";

    public static final String GET_OAUTH_APPLICATION_DATA_BY_APP_NAME =
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
                    "xmlns:xsd=\"http://org.apache.axis2/xsd\">\n" +
                    "   <soap:Header/>\n" +
                    "   <soap:Body>\n" +
                    "      <xsd:getOAuthApplicationDataByAppName>\n" +
                    "         <!--Optional:-->\n" +
                    "         <xsd:appName>{oAuthAppName}</xsd:appName>\n" +
                    "      </xsd:getOAuthApplicationDataByAppName>\n" +
                    "   </soap:Body>\n" +
                    "</soap:Envelope>";
}
