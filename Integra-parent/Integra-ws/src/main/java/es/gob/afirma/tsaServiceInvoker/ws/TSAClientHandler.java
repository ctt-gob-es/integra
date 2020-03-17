// Copyright (C) 2020 MINHAP, Gobierno de España
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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/**
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.ws.TSAClientHandler.java.</p>
 * <b>Description:</b><p>Class secures SOAP messages of TS@ requests.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2020.</p>
 * @author Gobierno de España.
 * @version 1.3, 17/03/2020.
 */
package es.gob.afirma.tsaServiceInvoker.ws;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.axiom.soap.SOAPBody;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.saaj.SOAPHeaderElementImpl;
import org.apache.axis2.saaj.util.SAAJUtil;
import org.apache.log4j.Logger;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSAMLToken;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.Conditions;
import com.sun.xml.wss.saml.NameIdentifier;
import com.sun.xml.wss.saml.SAMLAssertionFactory;
import com.sun.xml.wss.saml.Subject;
import com.sun.xml.wss.saml.SubjectConfirmation;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.utils.NumberConstants;
import es.gob.afirma.utils.UtilsAxis;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class secures SOAP messages of TS@ requests.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 17/03/2020.
 */
class TSAClientHandler extends AbstractTSAHandler {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TSAClientHandler.class);

    /**
     * Constant attribute that represents the handler name. 
     */
    private static final String HANDLER_NAME = "tsaClientHandlerIntegra";

    /**
     * Constant attribute that identifies UserNameToken authorization method.
     */
    static final String USERNAME_OPTION = "UserNameToken";

    /**
     * Constant attribute that identifies BinarySecurityToken authorization method.
     */
    static final String CERTIFICATE_OPTION = "X509CertificateToken";

    /**
     * Constant attribute that identifies none authorization method.
     */
    static final String SAML_OPTION = "SAMLToken";

    /**
     * Constant attribute that identifies the URI of an XML timestamp containing an XML signature.
     */
    public static final String URI_XML_TIMESTAMP = "urn:oasis:names:tc:dss:1.0:core:schema:XMLTimeStampToken";

    /**
     * Constant attribute that identifies the URI of an XML timestamp containing an ASN.1 TimeStampToken.
     */
    public static final String URI_RFC_3161_TIMESTAMP = "urn:ietf:rfc:3161";

    /**
     * Constant attribute that identifies the URI type value of an XML timestamp.
     */
    public static final String VALUE_TYPE_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

    /**
     * Attribute that indicates the current authorization method.
     */
    private String securityOption = "";

    /**
     * Constructor method for the class ClientHandler.java.
     * @param securityOpt Parameter that represents the authorization method.
     * @throws WSServiceInvokerException If the method fails.
     */
    TSAClientHandler(String securityOpt) throws WSServiceInvokerException {
	this.handlerDesc.setName(HANDLER_NAME);
	if (securityOpt == null) {
	    throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.CH_LOG001));
	}

	if (securityOpt.equals(USERNAME_OPTION)) {
	    this.securityOption = USERNAME_OPTION;
	} else if (securityOpt.equals(CERTIFICATE_OPTION)) {
	    this.securityOption = CERTIFICATE_OPTION;
	} else if (securityOpt.equals(SAML_OPTION)) {
	    this.securityOption = SAML_OPTION;
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
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TCH_LOG001, new Object[ ] { this.securityOption }));
	    if (this.securityOption.equals(USERNAME_OPTION)) {
		secMsg = this.createUserNameToken(doc);
	    } else if (this.securityOption.equals(CERTIFICATE_OPTION)) {
		secMsg = this.createBinarySecurityToken(doc);
	    } else if (this.securityOption.equals(SAML_OPTION)) {
		secMsg = this.createSAMLToken(doc);
	    }

	    // Modificación de la petición SOAP...
	    if (secMsg != null) {
		// Eliminamos el contenido del body e insertamos el nuevo body
		// generado.
		msgContext.getEnvelope().getBody().removeChildren();
		SOAPBody body = msgContext.getEnvelope().getBody();
		UtilsAxis.updateSoapBody(body, secMsg.getSOAPBody());

		// Añadimos las cabeceras generadas.
		Iterator<?> headers = secMsg.getSOAPHeader().getChildElements();
		while (headers.hasNext()) {
		    msgContext.getEnvelope().getHeader().addChild(UtilsAxis.fromSOAPHeaderToOMElement((SOAPHeaderElementImpl) headers.next()));
		}
	    } else {
		throw new IllegalArgumentException();
	    }
	} catch (Exception e) {
	    throw AxisFault.makeFault(e);
	}
	return InvocationResponse.CONTINUE;
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
	    wsSecHeader = new WSSecHeader(null, false);
	    wsSecUsernameToken = new WSSecUsernameToken();
	    wsSecUsernameToken.setPasswordType(getPasswordType());
	    wsSecUsernameToken.setUserInfo(getUserAlias(), getPassword());
	    wsSecHeader.insertSecurityHeader(soapEnvelopeRequest);
	    wsSecUsernameToken.prepare(soapEnvelopeRequest);
	    // Añadimos una marca de tiempo inidicando la fecha de creación del
	    // tag
	    wsSecUsernameToken.addCreated();
	    wsSecUsernameToken.addNonce();
	    // Modificación de la petición
	    secSOAPReqDoc = wsSecUsernameToken.build(soapEnvelopeRequest, wsSecHeader);
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
		// versión
		// durante la generación de la petición.
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
	Crypto crypto = null;
	Document secSOAPReqDoc;
	DOMSource source;
	Element element;
	StreamResult streamResult;
	String secSOAPReq;
	SOAPMessage res;
	WSSecSignature wsSecSignature = null;
	WSSecHeader wsSecHeader = null;

	// Eliminamos el provider ApacheXMLDSig de la lista de provider para que
	// no haya conflictos con el nuestro.
	Provider apacheXMLDSigProvider = Security.getProvider("ApacheXMLDSig");
	Security.removeProvider("ApacheXMLDSig");

	try {
	    // Inserción del tag wsse:Security y X509CertificateToken
	    wsSecHeader = new WSSecHeader(null, false);
	    wsSecHeader.setMustUnderstand(true);
	    wsSecSignature = new WSSecSignature();
	    crypto = getCryptoInstance();
	    // Indicación para que inserte el tag X509CertificateToken
	    wsSecSignature.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
	    wsSecSignature.setUserInfo(getUserAlias(), getPassword());
	    wsSecHeader.insertSecurityHeader(soapEnvelopeRequest);
	    wsSecSignature.prepare(soapEnvelopeRequest, crypto, wsSecHeader);

	    // Modificación y firma de la petición
	    secSOAPReqDoc = wsSecSignature.build(soapEnvelopeRequest, crypto, wsSecHeader);
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
     * Method that creates a request secured by SAML Token.
     * @param doc Parameter that represents the unsecured request.
     * @return the secured request.
     */
    private SOAPMessage createSAMLToken(Document doc) {
	SOAPMessage res = null;
	try {
	    String samlMethod = getSamlMethod();
	    if (samlMethod.equalsIgnoreCase("HOK")) {
		res = createSAMLTokenHOK(doc);
	    } else if (samlMethod.equalsIgnoreCase("SV")) {
		res = createSAMLTokenSV(doc);
	    } else {
		throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TCH_LOG002, new Object[ ] { samlMethod }));
	    }
	} catch (Exception e) {
	    throw new IllegalArgumentException(e);
	}
	return res;
    }

    /**
     * Method that creates a request secured by SAML HOK Token.
     * @param doc Parameter that represents the unsecured request.
     * @return the secured request.
     * @throws Exception if something during the creation process fails.
     */
    private SOAPMessage createSAMLTokenHOK(Document doc) throws Exception {
	ByteArrayOutputStream baos;
	Document secSOAPReqDoc;
	DOMSource source;
	Element element;
	SOAPMessage res;
	StreamResult streamResult;
	String secSOAPReq;
	WSSecSAMLToken wsSecSamlToken;
	WSSecHeader wsSecHeader;

	res = null;
	try {
	    Provider apacheXMLDSigProvider = Security.getProvider("ApacheXMLDSig");
	    Security.removeProvider("ApacheXMLDSig");

	    try {
		wsSecHeader = new WSSecHeader(null, false);
		wsSecSamlToken = new WSSecSAMLToken();

		wsSecSamlToken.setUserInfo(getUserAlias(), getPassword());
		wsSecHeader.insertSecurityHeader(doc);
		AssertionWrapper assertion;
		assertion = new AssertionWrapper(createHOKSAMLAssertion());
		wsSecSamlToken.prepare(doc, assertion);

		// Modificación de la petición
		secSOAPReqDoc = wsSecSamlToken.build(doc, assertion, wsSecHeader);
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
	} catch (Exception e) {
	    throw e;
	}
	return res;
    }

    /**
     * Method that creates a request secured by SAML SV Token.
     * @param doc Parameter that represents the unsecured request.
     * @return the secured request.
     * @throws Exception if something during the creation process fails.
     */
    private SOAPMessage createSAMLTokenSV(Document doc) throws Exception {
	ByteArrayOutputStream baos;
	Document secSOAPReqDoc;
	DOMSource source;
	Element element;
	SOAPMessage res;
	StreamResult streamResult;
	String secSOAPReq;
	WSSecSAMLToken wsSecSamlToken;
	WSSecHeader wsSecHeader;

	res = null;
	Provider apacheXMLDSigProvider = Security.getProvider("ApacheXMLDSig");
	Security.removeProvider("ApacheXMLDSig");

	try {
	    wsSecHeader = new WSSecHeader(null, false);
	    wsSecSamlToken = new WSSecSAMLToken();

	    wsSecSamlToken.setUserInfo(getUserAlias(), getPassword());
	    wsSecHeader.insertSecurityHeader(doc);
	    AssertionWrapper assertion;
	    assertion = new AssertionWrapper(createSVSAMLAssertion());
	    wsSecSamlToken.prepare(doc, assertion);

	    // Modificación de la petición
	    secSOAPReqDoc = wsSecSamlToken.build(doc, assertion, wsSecHeader);
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

	} catch (Exception e) {
	    throw e;
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
     * Method that creates a SAML assertion using the method Holder-of-Key (HOV).
     * @return an element that represents the SAML assertion
     * @throws IOException If the method fails.
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private Element createHOKSAMLAssertion() throws IOException {
	Assertion assertion = null;
	X509Certificate certificateSOAPRequest = null;
	PrivateKey privateKeySOAPRequest = null;
	try {
	    // Recuperamos el keystore que usaremos para generar el token.
	    KeyStore ks = KeyStore.getInstance(getUserKeystoreType());
	    InputStream is = new FileInputStream(new File(getUserKeystore()));
	    ks.load(is, getUserKeystorePass().toCharArray());

	    // Obtenemos el certificado a utilizar de los certificados
	    // contenidos en el keystore.
	    String alias = getUserAlias();
	    KeyStore.ProtectionParameter keyPassword = new KeyStore.PasswordProtection(getPassword().toCharArray());
	    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, keyPassword);

	    // Recuperamos la clave privada del certificado.
	    privateKeySOAPRequest = entry.getPrivateKey();

	    // Recuperamos la parte pública del certificado.
	    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	    InputStream in = new ByteArrayInputStream(entry.getCertificate().getEncoded());
	    certificateSOAPRequest = (X509Certificate) certFactory.generateCertificate(in);

	    // Obtenemos el Issuer del certificado
	    String issuer = certificateSOAPRequest.getIssuerDN().toString();
	    // Creamos el ID de la afirmación en base a la fecha actual
	    String assertionID = Long.toString(System.currentTimeMillis());

	    GregorianCalendar c = new GregorianCalendar();
	    long beforeTime = c.getTimeInMillis();
	    // roll the time by one hour
	    long offsetHours = NumberConstants.INT_60 * NumberConstants.INT_60 * NumberConstants.INT_1000;

	    c.setTimeInMillis(beforeTime - offsetHours);
	    GregorianCalendar before = (GregorianCalendar) c.clone();

	    c = new GregorianCalendar();
	    long afterTime = c.getTimeInMillis();
	    c.setTimeInMillis(afterTime + offsetHours);
	    GregorianCalendar after = (GregorianCalendar) c.clone();

	    GregorianCalendar issueInstant = new GregorianCalendar();

	    SAMLAssertionFactory factory = SAMLAssertionFactory.newInstance(SAMLAssertionFactory.SAML1_1);

	    // statements
	    List statements = new LinkedList();
	    NameIdentifier nmId = factory.createNameIdentifier(issuer, null, "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

	    // Obtenemos la clave pública del certificado.
	    PublicKey pubKey = certificateSOAPRequest.getPublicKey();
	    DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();

	    Document doc = docFactory.newDocumentBuilder().newDocument();

	    KeyInfo keyInfo = new KeyInfo(doc);
	    keyInfo.addKeyValue(pubKey);

	    List subConfirmation = new ArrayList();
	    subConfirmation.add("urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");

	    SubjectConfirmation scf = factory.createSubjectConfirmation(subConfirmation, null, keyInfo.getElement());

	    Subject subj = factory.createSubject(nmId, scf);

	    List attributes = new LinkedList();

	    statements.add(factory.createAttributeStatement(subj, attributes));

	    Conditions conditions = factory.createConditions(before, after, null, null, null);

	    assertion = factory.createAssertion(assertionID, issuer, issueInstant, conditions, null, statements);
	    assertion.setMajorVersion(certificateSOAPRequest.getSerialNumber());
	    assertion.setMinorVersion(BigInteger.ONE);

	    // Realizamos la firma.
	    return assertion.sign(pubKey, privateKeySOAPRequest);
	} catch (Exception e) {
	    String callBackError = Language.getResIntegra(ILogConstantKeys.TCBH_LOG011);
	    throw new IOException(callBackError, e);
	}

    }

    /**
     * Method that creates a SAML assertion using the method Sender-Vouches (SV).
     * @return an element that represents the SAML assertion
     * @throws IOException If the method fails.
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private Element createSVSAMLAssertion() throws IOException {
	Assertion assertion = null;
	X509Certificate certificateSOAPRequest = null;
	try {
	    // Recuperamos el keystore que usaremos para generar el token.
	    KeyStore ks = KeyStore.getInstance(getUserKeystoreType());
	    InputStream is = new FileInputStream(new File(getUserKeystore()));
	    ks.load(is, getUserKeystorePass().toCharArray());

	    // Obtenemos el certificado a utilizar de los certificados
	    // contenidos en el keystore.
	    String alias = getUserAlias();
	    KeyStore.ProtectionParameter keyPassword = new KeyStore.PasswordProtection(getPassword().toCharArray());
	    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, keyPassword);

	    // Recuperamos la parte pública del certificado.
	    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	    InputStream in = new ByteArrayInputStream(entry.getCertificate().getEncoded());
	    certificateSOAPRequest = (X509Certificate) certFactory.generateCertificate(in);

	    // Obtenemos el Issuer del certificado
	    String issuer = certificateSOAPRequest.getIssuerDN().toString();
	    // Creamos el ID de la afirmación en base a la fecha actual
	    String assertionID = Long.toString(System.currentTimeMillis());

	    GregorianCalendar c = new GregorianCalendar();
	    long beforeTime = c.getTimeInMillis();
	    // roll the time by one hour
	    long offsetHours = NumberConstants.INT_60 * NumberConstants.INT_60 * NumberConstants.INT_1000;

	    c.setTimeInMillis(beforeTime - offsetHours);
	    GregorianCalendar before = (GregorianCalendar) c.clone();

	    c = new GregorianCalendar();
	    long afterTime = c.getTimeInMillis();
	    c.setTimeInMillis(afterTime + offsetHours);
	    GregorianCalendar after = (GregorianCalendar) c.clone();

	    GregorianCalendar issueInstant = new GregorianCalendar();
	    // statements
	    List statements = new LinkedList();

	    SAMLAssertionFactory factory = SAMLAssertionFactory.newInstance(SAMLAssertionFactory.SAML1_1);

	    NameIdentifier nmId = factory.createNameIdentifier(issuer, null, "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

	    SubjectConfirmation scf = factory.createSubjectConfirmation("urn:oasis:names:tc:SAML:1.0:cm:sender-vouches");

	    Subject subj = factory.createSubject(nmId, scf);

	    List attributes = new LinkedList();

	    statements.add(factory.createAttributeStatement(subj, attributes));

	    Conditions conditions = factory.createConditions(before, after, null, null, null);

	    assertion = factory.createAssertion(assertionID, issuer, issueInstant, conditions, null, statements);
	    assertion.setMajorVersion(certificateSOAPRequest.getSerialNumber());
	    assertion.setMinorVersion(BigInteger.ONE);

	    return assertion.toElement(null);
	} catch (Exception e) {
	    String callBackError = Language.getResIntegra(ILogConstantKeys.TCBH_LOG012);
	    throw new IOException(callBackError, e);
	}
    }
}
