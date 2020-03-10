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
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.ws.TSAResponseHandler.java.</p>
 * <b>Description:</b><p>Class that represents handler used to verify the signature response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 10/03/2020.
 */
package es.gob.afirma.tsaServiceInvoker.ws;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.saaj.util.SAAJUtil;
import org.apache.log4j.Logger;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.components.crypto.CryptoType.TYPE;
import org.apache.xml.crypto.dsig.XMLSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.signature.xades.IdRegister;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;
import es.gob.afirma.utils.UtilsAxis;
import es.gob.afirma.utils.UtilsCertificateCommons;
import es.gob.afirma.utils.UtilsResourcesCommons;

/**
 * <p>Class that represents handler used to verify the signature response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 10/03/2020.
 */
@SuppressWarnings("deprecation")
public class TSAResponseHandler extends AbstractTSAHandler {

    /**
     * Constant attribute that represents the handler name. 
     */
    private static final String HANDLER_NAME = "tsaResponseHandlerIntegra";
    
    /**
     * Attribute that represents the 'KeyIdentifier' security header token. 
     */
    private static final String KEY_IDENTIFIER_TOKEN = "KeyIdentifier";

    /**
     * Attribute that represents the 'X509IssuerSerial' security header token. 
     */
    private static final String X509_ISSUER_SERIAL_TOKEN = "X509IssuerSerial";

    /**
     * Attribute that represents the 'BinarySecurityToken' security header token. 
     */
    private static final String BINARY_SECURITY_TOKEN = "BinarySecurityToken";

    /**
     * Attribute that represents the 'X509IssuerSerial' security header token. 
     */
    private static final String SAML_TOKEN = "Assertion";

    /**
     * Attribute that represents the kind of security header that can be received from TS@.
     */
    private static final List<String> RESPONSE_HEADER_TYPES = Arrays.asList(new String[ ] { KEY_IDENTIFIER_TOKEN, X509_ISSUER_SERIAL_TOKEN, BINARY_SECURITY_TOKEN, SAML_TOKEN });

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TSAResponseHandler.class);

    /**
     * Constructor method for the class TSAResponseHandler.java. 
     */
    public TSAResponseHandler() {
	this.handlerDesc.setName(HANDLER_NAME);
    }

    /**
     * Constructor method for the class TSAResponseHandler.java.
     * @param keystorePath keystore path.
     * @param keystorePass keystore password.
     * @param keystoreType keystore type.
     * @param autUser alias of certificate stored in keystore.
     * @param autPassword password of certificate (private key).
     * @param samlKeystorePath SAML keystore path.
     * @param samlKeystorePass SAML keystore password.
     * @param samlKeystoreType SAML keystore type.
     * @param samlAutUser SAML certificate alias stored in keystore.
     */
    public TSAResponseHandler(String keystorePath, String keystorePass, String keystoreType, String autUser, String autPassword, String samlKeystorePath, String samlKeystorePass, String samlKeystoreType, String samlAutUser) {
	this.handlerDesc.setName(HANDLER_NAME);
	setResponseKeystore(keystorePath);
	setResponseKeystorePass(keystorePass);
	setResponseKeystoreType(keystoreType);
	setResponseCertificateAlias(autUser);
	setPassword(autPassword);
	setResponseSAMLCertificateAlias(samlAutUser);
	setResponseSAMLKeystore(samlKeystorePath);
	setResponseSAMLKeystorePass(samlKeystorePass);
	setResponseSAMLKeystoreType(samlKeystoreType);
    }

    /**
     * {@inheritDoc}
     * @see org.apache.axis.Handler#invoke(org.apache.axis.MessageContext)
     */
    @Override
    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {
	Document doc = null;
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.RH_LOG001));
	try {
	    // Obtención del documento XML que representa la petición SOAP.
	    doc = SAAJUtil.getDocumentFromSOAPEnvelope(msgContext.getEnvelope());
	    // Obtenemos el objeto signature.
	    Element sigElement = null;
	    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	    if (nl.getLength() > 0) {
		// Si existe más de un nodo Signature, cogemos aquel que cuelgue
		// de "Security".
		if (nl.getLength() > 1) {
		    for (int i = 0; i < nl.getLength(); i++) {
			if (((Element) nl.item(i)).getParentNode().getLocalName().equals("Security")) {
			    sigElement = (Element) nl.item(i);
			    break;
			}
		    }
		} else {
		    sigElement = (Element) nl.item(0);
		}
		// creamos un manejador de la firma (para validarlo) a partir
		// del xml de la firma.
		org.apache.xml.security.Init.init();
		org.apache.xml.security.signature.XMLSignature signature = new org.apache.xml.security.signature.XMLSignature(sigElement, "");

		IdRegister.registerElements(doc.getDocumentElement());
		// Obtenemos la clave pública usada en el servidor para las
		// respuestas a partir del almacén de certificados.
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.RH_LOG003, new Object[ ] { getUserAlias() }));
		CryptoType aliasCertificate = new CryptoType(TYPE.ALIAS);
		aliasCertificate.setAlias(getResponseCertificateAlias());
		X509Certificate[ ] certificates = getResponseCryptoInstance().getX509Certificates(aliasCertificate);
		if (certificates != null && certificates.length > 0) {
		    X509Certificate certificate = certificates[0];
		    if (signature.checkSignatureValue(certificate)) {
			LOGGER.debug(Language.getResIntegra(ILogConstantKeys.RH_LOG004));

			// Firma válida. Comrpobamos si tiene alguna cabecera de
			// seguridad y la validamos.
			verifySecurityHeader(SAAJUtil.getSOAPEnvelopeFromDOOMDocument(doc));
		    } else {
			throw new AxisFault(Language.getFormatResIntegra(ILogConstantKeys.RH_LOG005, new Object[ ] { certificate.getSubjectDN(), certificate.getSerialNumber() }));
		    }
		} else {
		    throw new AxisFault(Language.getResIntegra(ILogConstantKeys.RH_LOG006));
		}
	    } else {
		throw new AxisFault(Language.getResIntegra(ILogConstantKeys.RH_LOG002));
	    }
	} catch (Exception e) {
	    throw AxisFault.makeFault(e);
	}
	return InvocationResponse.CONTINUE;
    }

    /**
     * Method that checks if there exists some security header in the response message and verifies it. 
     * @param soapEnvelopeResponse SOAP envelope to check.
     * @throws IOException if there is some error in the resources management.
     * @throws CertificateException if there is some error in the verify process. 
     */
    private void verifySecurityHeader(SOAPEnvelope soapEnvelopeResponse) throws IOException, CertificateException {
	// Recuperamos la cabecera.
	SOAPHeader header = soapEnvelopeResponse.getHeader();
	if (header != null) {

	    // Buscamos si la cabecera es de algún tipo de autenticación
	    // reconocido.
	    String headerType = getHeaderType(header);

	    // Si tiene algún tipo de cabecera reconocida, la validamos.
	    if (headerType != null) {
		switch (headerType) {
		    case KEY_IDENTIFIER_TOKEN:
			verifySecurityHeaderKeyIdentifier(header);
			break;

		    case X509_ISSUER_SERIAL_TOKEN:
			verifySecurityHeaderX509IssuerSerial(header);
			break;

		    case BINARY_SECURITY_TOKEN:
			verifySecurityBinarySecurityToken(header);
			break;

		    case SAML_TOKEN:
			verifySecuritySaml(header);
			break;

		    default:
			throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TRH_LOG001, new Object[ ] { headerType }));
		}
	    } else {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TRH_LOG002));
	    }
	}
    }

    /**
     * Method that verify the response security header for the key identifier token case.
     * @param header Response security header.
     * @throws IOException if there is some problem in the verify process.
     */
    private void verifySecurityHeaderKeyIdentifier(SOAPHeader header) throws IOException {
	if (header != null) {
	    // Recuperamos el elemento keyIdentifier de la cabecera.
	    OMElement keyIdentifier = UtilsAxis.findElementByTagName(header, KEY_IDENTIFIER_TOKEN);
	    if (keyIdentifier == null) {
		throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TRH_LOG003, new Object[ ] { KEY_IDENTIFIER_TOKEN }));
	    }
	    SubjectKeyIdentifier skiRequest = new SubjectKeyIdentifier(Base64.getDecoder().decode(keyIdentifier.getText()));

	    InputStream is = null;
	    ASN1InputStream asn1is = null;
	    try {
		// cargamos el certificado para la validación.
		X509Certificate certificateSOAPResponse = getResponseValidationX509Certificate();
		// Obtenemos el SubjectKeyIdentifier del certificado definido
		// para firmar las respuestas SOAP.
		is = new ByteArrayInputStream(certificateSOAPResponse.getPublicKey().getEncoded());
		asn1is = new ASN1InputStream(is);
		ASN1Sequence asn1Sequence = (ASN1Sequence) asn1is.readObject();
		SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(asn1Sequence);
		SubjectKeyIdentifier skiApp = new SubjectKeyIdentifier(spki);
		// Comprobamos que el SubjectKeyIdentifier sea el mismo. En caso
		// de no serlo, se lanza una excepción.
		if (!skiRequest.equals(skiApp)) {
		    String callBackError = Language.getResIntegra(ILogConstantKeys.TCBH_LOG003);
		    LOGGER.error(callBackError);
		    throw new IOException(callBackError);
		}
	    } finally {
		UtilsResourcesCommons.safeCloseInputStream(asn1is);
		UtilsResourcesCommons.safeCloseInputStream(is);
	    }

	} else {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TRH_LOG004);
	    LOGGER.error(errorMsg);
	    throw new IOException(errorMsg);
	}
    }

    /**
     * Method that verify the response security header for the key identifier token case.
     * @param header Response security header.
     * @throws CertificateException if there is some problem in the verify process.
     * @throws IOException if the input parameter is null.
     */
    private void verifySecurityHeaderX509IssuerSerial(SOAPHeader header) throws CertificateException, IOException {
	if (header != null) {
	    String issuerNameRes = null;
	    BigInteger serialNumberRes = null;
	    // Obtenemos de la petición SOAP el IssuerName y el SerialNumber
	    OMElement keyIdentifier = UtilsAxis.findElementByTagName(header, X509_ISSUER_SERIAL_TOKEN);
	    if (keyIdentifier != null) {
		issuerNameRes = UtilsAxis.findElementByTagName(keyIdentifier, "X509IssuerName").getText();
		serialNumberRes = new BigInteger(UtilsAxis.findElementByTagName(keyIdentifier, "X509SerialNumber").getText());
	    }

	    if (keyIdentifier == null || issuerNameRes == null || serialNumberRes == null) {
		throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.TRH_LOG005));
	    }

	    // cargamos el certificado para la validación.
	    X509Certificate certificateSOAPResponse = getResponseValidationX509Certificate();
	    // Obtenemos el issuerName y el SerialNumber del certificado
	    // definido para firmar las respuestas SOAP

	    String issuerNameApp = new X509Name(certificateSOAPResponse.getIssuerDN().getName()).toString();
	    BigInteger serialNumberApp = certificateSOAPResponse.getSerialNumber();

	    // Normalizamos ambos issuerName y comparamos
	    String canonicalizedIssuerNameReq = UtilsCertificateCommons.canonicalizeX500Principal(issuerNameRes);
	    String canonicalizedIssuerNameApp = UtilsCertificateCommons.canonicalizeX500Principal(issuerNameApp);

	    if (!canonicalizedIssuerNameReq.equals(canonicalizedIssuerNameApp) && serialNumberRes.equals(serialNumberApp)) {
		String callBackError = Language.getResIntegra(ILogConstantKeys.TCBH_LOG003);
		LOGGER.error(callBackError);
		throw new CertificateException(callBackError);
	    }
	} else {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TRH_LOG006);
	    LOGGER.error(errorMsg);
	    throw new IOException(errorMsg);
	}

    }

    /**
     * Method that verify the response security header for the binary security token case.
     * @param header Response security header.
     * @throws CertificateException if there is some problem in the verify process.
     * @throws IOException  if the input parameter is null.
     */
    private void verifySecurityBinarySecurityToken(SOAPHeader header) throws CertificateException, IOException {
	if (header != null) {
	    // Recuperamos el elemento "SecurityTokenReference", donde se
	    // encuentra la referencia al binarySecurityToken.
	    OMElement securityTokenReference = UtilsAxis.findElementByTagName(header, TSAServiceInvokerConstants.SOAPElements.SECURITY_TOKEN_REFERENCE);
	    if (securityTokenReference == null) {
		throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TRH_LOG007, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.SECURITY_TOKEN_REFERENCE }));
	    }

	    // recuperamos el elemento "reference".
	    OMElement reference = UtilsAxis.findElementByTagName(securityTokenReference, TSAServiceInvokerConstants.SOAPElements.REFERENCE);
	    if (reference == null) {
		throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TRH_LOG007, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.REFERENCE }));
	    }

	    // Recuperamos el atributo URI que hace referencia al
	    // BinarySecurityToken a validar.
	    String bstRef = reference.getAttributeValue(new javax.xml.namespace.QName(TSAServiceInvokerConstants.SOAPElements.URI)).replace("#", "");

	    // Buscamos el elemento BinarySecurityToken por la URI
	    // recuperada.
	    OMElement bst = UtilsAxis.findElementByTagNameAndId(header, TSAServiceInvokerConstants.SOAPElements.BINARY_SECURITY_TOKEN, bstRef);

	    // Si hemos encontrado el elemento, recuperamos su valor.
	    if (bst == null) {
		throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TRH_LOG007, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.BINARY_SECURITY_TOKEN }));
	    }
	    String certValue = bst.getText();

	    // Convertimos el base64 de entrada en un certificado del tipo
	    // X509Certificate.
	    CertificateFactory factory;
	    factory = CertificateFactory.getInstance("X.509");
	    X509Certificate resCert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certValue)));

	    // Recuperamos el certificado configurado para la validación de
	    // respuestas SOAP.
	    X509Certificate configResCert = getResponseValidationX509Certificate();

	    // Verificamos que ambos certificados coincidan.
	    if (!UtilsCertificateCommons.equals(resCert, configResCert)) {
		throw new CertificateException(Language.getResIntegra(ILogConstantKeys.TRH_LOG008));
	    }
	} else {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TRH_LOG006);
	    LOGGER.error(errorMsg);
	    throw new IOException(errorMsg);
	}

    }

    /**
     * Method that verifies a SAML security header.
     * @param header SOAP header to verify.
     * @throws CertificateException if something in the validation is wrong.
     * @throws IOException if the input parameter is null.
     */
    private void verifySecuritySaml(SOAPHeader header) throws CertificateException, IOException {
	if (header != null) {
	    // Recuperamos el elemento "SecurityTokenReference", donde se
	    // encuentra la referencia al SAML assertion.
	    OMElement securityTokenReference = UtilsAxis.findElementByTagName(header, TSAServiceInvokerConstants.SOAPElements.SECURITY_TOKEN_REFERENCE);
	    if (securityTokenReference == null) {
		throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TRH_LOG007, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.SECURITY_TOKEN_REFERENCE }));
	    }

	    // Recuperamos el elemento "KeyIdentifier".
	    OMElement keyIdentifier = UtilsAxis.findElementByTagName(securityTokenReference, TSAServiceInvokerConstants.SOAPElements.KEY_IDENTIFIER);
	    if (keyIdentifier == null) {
		throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TRH_LOG007, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.KEY_IDENTIFIER }));
	    }

	    // Obtenemos el valor del elemento, que corresponde con el ID del
	    // SAML assertion de la cabecera.
	    String assertionId = keyIdentifier.getText();

	    // Buscamos el elemento Assertion por la URI
	    // recuperada.
	    OMElement assertionElem = UtilsAxis.findElementByTagNameAndAttribute(header, TSAServiceInvokerConstants.SOAPElements.ASSERTION, TSAServiceInvokerConstants.SOAPElements.ASSERTION_ID, assertionId);
	    if (assertionElem == null) {
		throw new IllegalArgumentException(Language.getFormatResIntegra(ILogConstantKeys.TRH_LOG007, new Object[ ] { TSAServiceInvokerConstants.SOAPElements.ASSERTION }));
	    }

	    // Tal y como se ha estado haciendo hasta ahora, comparamos los
	    // atributos MajorVersion y MinorVersion.
	    BigInteger majorVersion = new BigInteger(UtilsAxis.findAttributeValue(assertionElem, TSAServiceInvokerConstants.SOAPElements.MAJOR_VERSION));
	    BigInteger minorVersion = new BigInteger(UtilsAxis.findAttributeValue(assertionElem, TSAServiceInvokerConstants.SOAPElements.MINOR_VERSION));

	    if (majorVersion != minorVersion) {
		throw new CertificateException(Language.getResIntegra(ILogConstantKeys.TRH_LOG009));
	    }

	} else {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TRH_LOG006);
	    LOGGER.error(errorMsg);
	    throw new IOException(errorMsg);
	}
    }

    /**
     * Auxiliary method that determines the security header type.
     * @param elem Element to analyze.
     * @return the header type.
     */
    private String getHeaderType(OMElement elem) {
	String res = null;
	OMElement element = null;
	Iterator<?> it = elem.getChildElements();
	String localName;
	while (it.hasNext() && res == null) {
	    element = (OMElement) it.next();
	    localName = element.getLocalName();
	    
	    // Si el elemento coincide con alguno de los tipos de cabeceras
	    // definidos, lo devolvemos.
	    if (RESPONSE_HEADER_TYPES.contains(localName)) {
		res = localName;
		break;
	    }
	    
	    // Si el elemento tiene hijos, los recorremos recursivamente.
	    if (element.getChildElements().hasNext()) {
		res = getHeaderType(element);
	    }
	}
	return res;
    }

    /**
     * Method that gets the X509Certificate used to verify the security response header.
     * @return the X509Certificate necessary for the validation or null if some error occurred.
     */
    private X509Certificate getResponseValidationX509Certificate() {
	X509Certificate res = null;
	try {
	    // Cargamos el keystore.
	    KeyStore keystore = KeyStore.getInstance(getResponseKeystoreType());
	    InputStream is = new FileInputStream(new File(getResponseKeystore()));
	    keystore.load(is, getResponseKeystorePass().toCharArray());

	    // Obtenemos el certificado a utilizar de los certificados
	    // contenidos en el keystore.
	    String alias = getResponseCertificateAlias();
	    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	    InputStream in = new ByteArrayInputStream(keystore.getCertificate(alias).getEncoded());
	    res = (X509Certificate) certFactory.generateCertificate(in);

	} catch (KeyStoreException e) {
	   LOGGER.error(Language.getResIntegra(ILogConstantKeys.TRH_LOG010));
	} catch (FileNotFoundException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.TRH_LOG011));
	} catch (NoSuchAlgorithmException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.TRH_LOG012));
	} catch (CertificateException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.TRH_LOG013));
	} catch (IOException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.TRH_LOG014));
	}

	return res;
    }

}
