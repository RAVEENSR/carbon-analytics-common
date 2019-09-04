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

import org.wso2.carbon.analytics.idp.client.core.exception.IdPClientException;

import javax.xml.soap.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class SoapClient {

    /**
     * TODO: Give and example for soapMessageContent, headers, soapEndpointUrl
     * @return SOAPMessage Soap message response
     * */
    public static SOAPMessage callSoapWebService(String soapMessageContent, MimeHeaders headers,
                                                String soapEndpointUrl) throws IdPClientException {
        try {
            // Create SOAP Connection
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            SOAPConnection soapConnection = soapConnectionFactory.createConnection();

            // Send SOAP Message to SOAP Server
            SOAPMessage soapResponse // TODO: Consider the 200 response from response for a fault soap request
                    = soapConnection.call(createSOAPRequest(soapMessageContent, headers), soapEndpointUrl);
            soapConnection.close(); //TODO: ERROR {com.sun.xml.internal.messaging.saaj.client.p2p} - SAAJ0009: Message
            // send failed
            return soapResponse;
        } catch (SOAPException e) {
            throw new IdPClientException("Error occurred while sending the SOAP message.", e);
        }
    }

    private static SOAPMessage createSOAPRequest(String soapMessageContent, MimeHeaders headers) {
        InputStream is = new ByteArrayInputStream(soapMessageContent.getBytes());

        SOAPMessage soapMessage = null;
        try {
            soapMessage = MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL).createMessage(headers, is);
            soapMessage.saveChanges();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SOAPException e) {
            e.printStackTrace();
        }
        return soapMessage;
    }
}
