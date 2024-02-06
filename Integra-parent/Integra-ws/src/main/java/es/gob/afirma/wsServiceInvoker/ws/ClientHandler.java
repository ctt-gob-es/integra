// Copyright (C) 2012-13 MINHAP, Gobierno de España
// This program is licensed and may be used, modified and redistributed under the terms
// of the European Public License (EUPL), either version 1.1 or (at your
// option) any later version as soon as they are approved by the European Commission.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and
// more details.
// You should have received a copy of the EUPL1.1 license
// along with this program; if not, you may find it at
// https://eupl.eu/1.1/es/

/**
 * <b>File:</b><p>es.gob.afirma.wsServiceInvoker.ws.ClientHandler.java.</p>
 * <b>Description:</b><p>Class secures SOAP messages of @Firma requests.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>03/10/2011.</p>
 * @author Gobierno de España.
 * @version 1.4, 17/03/2020.
 */
package es.gob.afirma.wsServiceInvoker.ws;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.saaj.SOAPElementImpl;
import org.apache.axis2.saaj.SOAPHeaderElementImpl;
import org.apache.axis2.saaj.util.SAAJUtil;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.utils.UtilsAxis;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class secures SOAP messages of @Firma requests.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.4, 17/03/2020.
 */
class ClientHandler extends AbstractCommonHandler {

    /**
     * Constant attribute that represents the handler name. 
     */
    private static final String HANDLER_NAME = "clientHandlerIntegra";

    /**
     * Constant attribute that identifies UserNameToken authorization method.
     */
    static final String USERNAMEOPTION = WSConstants.USERNAME_TOKEN_LN;

    /**
     * Constant attribute that identifies BinarySecurityToken authorization method.
     */
    static final String CERTIFICATEOPTION = WSConstants.BINARY_TOKEN_LN;

    /**
     * Constant attribute that identifies none authorization method.
     */
    static final String NONEOPTION = "none";

    /**
     * Attribute that indicates the current authorization method.
     */
    private String securityOption = "";

    /**
     * Constructor method for the class ClientHandler.java.
     * @param securityOpt Parameter that represents the authorization method.
     * @throws WSServiceInvokerException If the method fails.
     */
    ClientHandler(String securityOpt) throws WSServiceInvokerException {
	this.handlerDesc.setName(HANDLER_NAME);
	this.handlerDesc.getRules().setPhaseLast(true);
	if (securityOpt == null) {
	    throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.CH_LOG001));
	}

	if (securityOpt.equals(USERNAMEOPTION)) {
	    this.securityOption = USERNAMEOPTION;
	} else if (securityOpt.equals(CERTIFICATEOPTION)) {
	    this.securityOption = CERTIFICATEOPTION;
	} else if (securityOpt.equals(NONEOPTION)) {
	    this.securityOption = NONEOPTION;
	} else {
	    throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.CH_LOG002, new Object[ ] { securityOpt }));
	}

    }

    /**
     * {@inheritDoc}
     * @return 
     * @see org.apache.axis.Handler#invoke(org.apache.axis.MessageContext)
     */
    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {
	SOAPMessage secMsg;
	Document doc = null;

	secMsg = null;

	try {
	    // Obtención del documento XML que representa la petición SOAP.
	    doc = SAAJUtil.getDocumentFromSOAPEnvelope(msgContext.getEnvelope());
	    // Securización de la petición SOAP según la opcion de seguridad
	    // configurada
	    if (this.securityOption.equals(USERNAMEOPTION)) {
		secMsg = this.createUserNameToken(doc);
	    } else if (this.securityOption.equals(CERTIFICATEOPTION)) {
		secMsg = this.createBinarySecurityToken(doc);
	    }

	    if (!this.securityOption.equals(NONEOPTION)) {
		// Modificación de la petición SOAP...

		// Eliminamos el contenido del body e insertamos el nuevo body
		// generado.
		msgContext.getEnvelope().getBody().removeChildren();
		SOAPBody body = msgContext.getEnvelope().getBody();
		updateSoapBody(body, secMsg.getSOAPBody());

		// Añadimos las cabeceras generadas.
		Iterator<?> headers = secMsg.getSOAPHeader().getChildElements();
		while (headers.hasNext()) {
		    msgContext.getEnvelope().getHeader().addChild(fromSOAPHeaderToOMElement((SOAPHeaderElementImpl) headers.next()));
		}
	    }
	} catch (Exception e) {
	    throw AxisFault.makeFault(e);
	}
	return InvocationResponse.CONTINUE;
    }

    /**
     * Method that transforms a SOAPHeader into a OMElement.
     * 
     * @param headers SOAP header to transform.
     * @return a new OMElement that represents the SOAP header.
     */
    private OMElement fromSOAPHeaderToOMElement(SOAPHeaderElementImpl headers) {
	OMFactory fac = OMAbstractFactory.getOMFactory();
	// Generamos los distintos elementos incluidos en el elemento principal.
	return UtilsAxis.parseElements((SOAPElementImpl<?>) headers, fac);
    }

    /**
     * Method that update the current SOAP body with the new generated body.
     * @param body Current SOAP body to update.
     * @param soapBody new SOAP body.
     */
    private void updateSoapBody(SOAPBody body, javax.xml.soap.SOAPBody soapBody) {
	OMFactory fac = OMAbstractFactory.getOMFactory();
	NamedNodeMap attrs = soapBody.getAttributes();

	// añadimos los atributos
	for (int i = 0; i < attrs.getLength(); i++) {
	    OMAttribute attr = null;
	    attr = fac.createOMAttribute(attrs.item(i).getNodeName(), null, attrs.item(i).getNodeValue());
	    body.addAttribute(attr);
	}

	Iterator<?> it = soapBody.getChildElements();
	while (it.hasNext()) {
	    body.addChild(UtilsAxis.parseElements((SOAPElementImpl<?>) it.next(), fac));
	}
    }

    /**
     * Method that creates a request secured by UserNameToken.
     * @param soapEnvelopeRequest Parameter that represents the unsecured request.
     * @return the secured request.
     * @throws TransformerException If an unrecoverable error occurs during the course of the transformation.
     * @throws IOException If there is a problem in reading data from the input stream.
     * @throws SOAPException If the message is invalid.
     * @throws WSSecurityException If the method fails.
     */
    private SOAPMessage createUserNameToken(Document soapEnvelopeRequest) throws TransformerException, IOException, SOAPException, WSSecurityException {
	ByteArrayOutputStream baos;
	Document secSOAPReqDoc;
	DOMSource source;
	Element element;
	SOAPMessage res;
	StreamResult streamResult;
	String secSOAPReq;
	WSSecUsernameToken wsSecUsernameToken;
	WSSecHeader wsSecHeader;

	// Eliminamos el provider ApacheXMLDSig de la lista de provider para que
	// no haya conflictos con el nuestro.
	Provider apacheXMLDSigProvider = Security.getProvider("ApacheXMLDSig");
	Security.removeProvider("ApacheXMLDSig");

	try {
	    // Inserción del tag wsse:Security y userNameToken
	    wsSecHeader = new WSSecHeader(null, false, soapEnvelopeRequest);
	    wsSecHeader.insertSecurityHeader();
	    
	    wsSecUsernameToken = new WSSecUsernameToken(wsSecHeader);
	    wsSecUsernameToken.setPasswordType(getPasswordType());
	    wsSecUsernameToken.setUserInfo(getUserAlias(), getPassword());
	    
	    wsSecUsernameToken.prepare();
	    // Añadimos una marca de tiempo inidicando la fecha de creación del
	    // tag
	    wsSecUsernameToken.addCreated();
	    wsSecUsernameToken.addNonce();
	    // Modificación de la petición
	    secSOAPReqDoc = wsSecUsernameToken.build();
	    element = secSOAPReqDoc.getDocumentElement();

	    // Transformación del elemento DOM a String
	    source = new DOMSource(element);
	    baos = new ByteArrayOutputStream();
	    streamResult = new StreamResult(baos);
	    TransformerFactory.newInstance().newTransformer().transform(source, streamResult);
	    secSOAPReq = new String(baos.toByteArray());

	    // Creación de un nuevo mensaje SOAP a partir del mensaje SOAP
	    // securizado formado
	    MessageFactory mf = new org.apache.axis2.saaj.MessageFactoryImpl();
	    res = mf.createMessage(null, new ByteArrayInputStream(secSOAPReq.getBytes()));

	} finally {
	    // Restauramos el provider ApacheXMLDSig eliminado inicialmente.
	    if (apacheXMLDSigProvider != null) {
		// Eliminamos de nuevo el provider por si se ha añadido otra
		// versión durante la generación de la petición.
		Security.removeProvider("ApacheXMLDSig");
		// Añadimos el provider.
		Security.insertProviderAt(apacheXMLDSigProvider, 1);
	    }
	}

	return res;
    }

    /**
     * Method that creates a request secured by BinarySecurityToken.
     * @param soapEnvelopeRequest Parameter that represents the unsecured request.
     * @return the secured request.
     * @throws TransformerException If an unrecoverable error occurs during the course of the transformation.
     * @throws IOException If there is a problem in reading data from the input stream.
     * @throws SOAPException May be thrown if the message is invalid.
     * @throws WSSecurityException If the method fails.
     */
    private SOAPMessage createBinarySecurityToken(Document soapEnvelopeRequest) throws TransformerException, IOException, SOAPException, WSSecurityException {
	ByteArrayOutputStream baos;
	Crypto crypto;
	Document secSOAPReqDoc;
	DOMSource source;
	Element element;
	StreamResult streamResult;
	String secSOAPReq;
	SOAPMessage res;
	WSSecSignature wsSecSignature;
	WSSecHeader wsSecHeader;

	// Eliminamos el provider ApacheXMLDSig de la lista de provider para que
	// no haya conflictos con el nuestro.
	Provider apacheXMLDSigProvider = Security.getProvider("ApacheXMLDSig");
	Security.removeProvider("ApacheXMLDSig");

	try {
	    crypto = null;
	    wsSecHeader = null;
	    wsSecSignature = null;
	    // Inserción del tag wsse:Security y BinarySecurityToken
	    wsSecHeader = new WSSecHeader(null, false, soapEnvelopeRequest);
	    wsSecHeader.insertSecurityHeader();
	    wsSecSignature = new WSSecSignature(wsSecHeader);
	    crypto = getCryptoInstance();
	    // Indicación para que inserte el tag BinarySecurityToken
	    wsSecSignature.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
	    wsSecSignature.setUserInfo(getUserAlias(), getPassword());

	    wsSecSignature.prepare(crypto);

	    // Modificación y firma de la petición
	    secSOAPReqDoc = wsSecSignature.build(crypto);
	    element = secSOAPReqDoc.getDocumentElement();
	    // Transformación del elemento DOM a String
	    source = new DOMSource(element);
	    baos = new ByteArrayOutputStream();
	    streamResult = new StreamResult(baos);
	    TransformerFactory.newInstance().newTransformer().transform(source, streamResult);
	    secSOAPReq = new String(baos.toByteArray());

	    // Creación de un nuevo mensaje SOAP a partir del mensaje SOAP
	    // securizado formado
	    MessageFactory mf = new org.apache.axis2.saaj.MessageFactoryImpl();
	    res = mf.createMessage(null, new ByteArrayInputStream(secSOAPReq.getBytes()));

	} finally {
	    // Eliminamos de nuevo el provider por si se ha añadido otra
	    // versión durante la generación de la petición.
	    Security.removeProvider("ApacheXMLDSig");

	    // Restauramos el provider ApacheXMLDSig eliminado inicialmente.
	    if (apacheXMLDSigProvider != null) {
		// Añadimos el provider.
		Security.insertProviderAt(apacheXMLDSigProvider, 1);
	    }
	}
	
	return res;
    }

}
