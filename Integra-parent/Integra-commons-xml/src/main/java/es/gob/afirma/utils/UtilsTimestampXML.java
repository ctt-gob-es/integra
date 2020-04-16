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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsTimestampSML.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.6, 16/04/2020.
 */
package es.gob.afirma.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;

import org.apache.xml.crypto.MarshalException;
import org.apache.xml.crypto.dsig.CanonicalizationMethod;
import org.apache.xml.crypto.dsig.DigestMethod;
import org.apache.xml.crypto.dsig.XMLSignature;
import org.apache.xml.crypto.dsig.XMLSignatureException;
import org.apache.xml.crypto.dsig.XMLSignatureFactory;
import org.apache.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.xades.IXMLConstants;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;

/**
 * <p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.6, 16/04/2020.
 */
public final class UtilsTimestampXML {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    public static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsTimestampXML.class);

    /**
     * Constructor method for the class TimestampUtils.java.
     */
    private UtilsTimestampXML() {
    }

    /**
     * Method that obtain the the signing certificate of a timestamp.
     * @param tst Parameter that represents the timestamp.
     * @return an object that represents the certificate.
     * @throws SigningException If the method fails.
     */
    @SuppressWarnings("unchecked")
    public static X509Certificate getSigningCertificate(TimeStampToken tst) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG020));
	try {
	    // Comprobamos que el sello de tiempo no sea nulo
	    GenericUtilsCommons.checkInputParameterIsNotNull(tst, Language.getResIntegra(ILogConstantKeys.TSU_LOG014));

	    // Obtenemos al colección de certificados definidos en el almacén de
	    // certificados dentro del sello de tiempo
	    CertStore certStore = null;

	    try {
		certStore = tst.getCertificatesAndCRLs("Collection", BouncyCastleProvider.PROVIDER_NAME);
		Collection<X509Certificate> collectionSigningCertificate = (Collection<X509Certificate>) certStore.getCertificates(tst.getSID());

		if (collectionSigningCertificate.size() != 1) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG015);
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		return collectionSigningCertificate.iterator().next();
	    } catch (NoSuchAlgorithmException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG016);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg, e);

	    } catch (NoSuchProviderException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG017);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg, e);
	    } catch (CMSException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG018);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg, e);
	    } catch (CertStoreException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG019);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg, e);
	    }
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG039));
	}
    }

    /**
     * Method that validates a XML timestamp.
     * @param tst Parameter that represents the XML timestamp.
     * @throws SigningException If the validation fails.
     */
    public static void validateXMLTimestamp(Element tst) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG040));
	try {
	    // Comprobamos que el sello de tiempo no es nulo
	    GenericUtilsCommons.checkInputParameterIsNotNull(tst, Language.getResIntegra(ILogConstantKeys.TSU_LOG014));

	    // Obtenemos la factoría para firmas XML
	    XMLSignatureFactory fac;
	    String providerName = System.getProperty("jsr105Provider", "org.apache.xml.dsig.internal.dom.XMLDSigRI");
	    try {
		fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
	    } catch (Exception e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG029);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg, e);
	    }

	    // Buscamos el nodo que representa la firma del sello de tiempo XML
	    Node nodeToValidate = tst;
	    if (nodeToValidate.getLocalName().equals(IXMLConstants.ELEMENT_TIMESTAMP) || nodeToValidate.getLocalName().equals(IXMLConstants.ELEMENT_XML_TIMESTAMP)) {
		nodeToValidate = getXMLSignatureNode(tst);
	    }
	    if (nodeToValidate == null) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG120);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    // Obtenemos el contexto de validación
	    DOMValidateContext valContext = new DOMValidateContext(new KeyValueSelector(), nodeToValidate);

	    // Unmarshal the XMLSignature
	    XMLSignature signature = null;
	    try {
		signature = fac.unmarshalXMLSignature(valContext);
	    } catch (MarshalException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG022);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }

	    // Validamos el núcleo de firma del sello de tiempo
	    try {
		if (!signature.getSignatureValue().validate(valContext)) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG030);
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
	    } catch (XMLSignatureException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG031);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG041));
	}
    }

    //
    /**
     * Method that validates an ASN.1 timestamp.
     * @param tst Parameter that represents the ASN.1 timestamp to validate.
     * @throws SigningException If the method fails or the timestamp isn't valid.
     */
    public static void validateASN1Timestamp(TimeStampToken tst) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG042));
	try {
	    // Comprobamos que el sello de tiempo no es nulo
	    GenericUtilsCommons.checkInputParameterIsNotNull(tst, Language.getResIntegra(ILogConstantKeys.TSU_LOG014));

	    // Obtenemos el certificado firmante del sello de tiempo
	    X509Certificate signingCertificate = getSigningCertificate(tst);

	    // Validamos la firma del sello de tiempo
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG021));
	    try {
		JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
		jcaContentVerifierProviderBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);

		ContentVerifierProvider contentVerifierProvider = jcaContentVerifierProviderBuilder.build(signingCertificate);

		JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
		digestCalculatorProviderBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();

		SignerInformationVerifier signerInformationVerifier = new SignerInformationVerifier(contentVerifierProvider, digestCalculatorProvider);

		tst.validate(signerInformationVerifier);

	    } catch (TSPValidationException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG022);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg, e);
	    } catch (Exception e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG023);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG043));
	}
    }

    /**
     * Method that obtains the gentime from a XML timestamp.
     * @param xmlTimestamp Parameter that represents the XML timestamp.
     * @return an object that represents the gentime.
     * @throws SigningException If the gentime cannot parse to UTC format.
     */
    public static Date getGenTimeXMLTimestamp(Element xmlTimestamp) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG046));
	try {
	    // Comprobamos que se ha indicado el nodo con el sello de tiempo
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlTimestamp, Language.getResIntegra(ILogConstantKeys.TSU_LOG027));

	    // Obtenemos la lista de References
	    NodeList nl = xmlTimestamp.getChildNodes().item(0).getChildNodes();

	    // Obtenemos el elemento SignedInfo
	    Node si = getXMLSignedInfo(nl);

	    // Obtenemos la URI del sello de tiempo
	    String uriTST = getXMLURITimestamp(si);

	    // Obtenemos el gentime del sello de tiempo
	    return searchXMLGenTimeTimestamp(nl, uriTST);
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG024));
	}
    }

    /**
     * Method that obtains the ds:SignedInfo element from a nodes list.
     * @param nl Parameter that represents the nodes list.
     * @return an object that represents the ds:SignedInfo element.
     */
    private static Node getXMLSignedInfo(NodeList nl) {
	Node si = null;
	int i = 0;
	while (si == null && i < nl.getLength()) {
	    if (nl.item(0).getLocalName().equals(IXMLConstants.ELEMENT_SIGNED_INFO)) {
		si = nl.item(i);
	    }
	    i++;
	}
	return si;
    }

    /**
     * Method that obtains the URI of a XML timestamp.
     * @param signedInfo Parameter that represents the ds:SignedInfo element of the XML timestamp.
     * @return the URI.
     */
    private static String getXMLURITimestamp(Node signedInfo) {
	String uriTST = null;
	if (signedInfo != null) {
	    NodeList refs = signedInfo.getChildNodes();
	    int i = 0;
	    while (uriTST == null && i < refs.getLength()) {
		if (refs.item(i).getLocalName().equals(IXMLConstants.ELEMENT_REFERENCE)) {
		    NamedNodeMap attsRef = refs.item(i).getAttributes();
		    if (attsRef.getNamedItem(IXMLConstants.ATTRIBUTE_TYPE) != null && attsRef.getNamedItem(IXMLConstants.ATTRIBUTE_TYPE).getNodeValue().equals("urn:oasis:names:tc:dss:1.0:core:schema:XMLTimeStampToken") && attsRef.getNamedItem(IXMLConstants.ATTRIBUTE_URI) != null) {
			uriTST = attsRef.getNamedItem(IXMLConstants.ATTRIBUTE_URI).getNodeValue();
		    }

		}
		i++;
	    }
	}
	return uriTST;
    }

    /**
     * Method that searchs the gentime of a XML timestamp from a nodes list.
     * @param nl Parameter that represents the nodes list.
     * @param uriTST Parameter that represents the URI of the timestamp.
     * @return the gentime of the XML timestamp or null if it cannot be found.
     * @throws SigningException If the gentime cannot parse to UTC format.
     */
    // CHECKSTYLE:OFF For cyclomatic complex
    private static Date searchXMLGenTimeTimestamp(NodeList nl, String uriTST) throws SigningException {
	// CHECKSTYLE:ON
	boolean enc = false;
	Date genTime = null;
	int i = 0;
	if (nl != null && uriTST != null) {
	    while (i < nl.getLength() && !enc) {
		if (nl.item(i).getLocalName().equals(IXMLConstants.ELEMENT_OBJECT) && nl.item(i).getFirstChild().getLocalName().equals(IXMLConstants.ELEMENT_TST_INFO)) {
		    NamedNodeMap attsObject = nl.item(i).getAttributes();
		    String idValue = attsObject.getNamedItem(IXMLConstants.ATTRIBUTE_ID).getNodeValue();
		    enc = uriTST.equals("#" + idValue);
		    if (!enc) {
			NamedNodeMap attsTst = nl.item(i).getFirstChild().getAttributes();
			idValue = attsTst.getNamedItem(IXMLConstants.ATTRIBUTE_ID).getNodeValue();
			enc = uriTST.equals("#" + idValue);
		    }
		    if (enc) {
			NodeList childs = nl.item(i).getFirstChild().getChildNodes();
			int j = 0;
			while (j < childs.getLength() && genTime == null) {
			    if (childs.item(j).getLocalName().equals(IXMLConstants.ELEMENT_CREATION_TIME)) {
				genTime = parseDateToUTCDate(childs.item(j).getFirstChild().getNodeValue());
			    }
			    j++;
			}
		    }
		}
		i++;
	    }
	}
	return genTime;
    }

    /**
     * Method that obtains a date with UTC format.
     * @param dateToParse Parameter that represents the date to parse.
     * @return the date with UTC format
     * @throws SigningException If the date cannot parse to UTC format.
     */
    private static Date parseDateToUTCDate(String dateToParse) throws SigningException {
	SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
	try {
	    return sdf.parse(dateToParse);
	} catch (ParseException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG028);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that checks if the canonicalization algorithm used to canonicalize the data is null or not.
     * @param inputCanonicalizationAlgorithm Parameter that represents the canonicalization algorithm used to canonicalize the data.
     * @return <code>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</code> canonicalization algorithm when the input data is null, or the value of the canonicalization algorithm defined
     * as input data if the value isn't null.
     */
    private static String defineCanonicalizationAlgorithm(String inputCanonicalizationAlgorithm) {
	String canonicalizationAlgorithm = CanonicalizationMethod.INCLUSIVE;
	if (inputCanonicalizationAlgorithm != null) {
	    canonicalizationAlgorithm = inputCanonicalizationAlgorithm;
	}
	return canonicalizationAlgorithm;
    }

    /**
     * Method that obtains the data to stamp with a time-stamp to include into a <code>xades:SignatureTimeStamp</code> element.
     * @param dsSignature Parameter that represents the <code>ds:Signature</code> element of the XML signature.
     * @param inputCanonicalizationAlgorithm Parameter that represents the canonicalization algorithm to use for generating the time-stamp.
     * @return the data to stamp with the timestamp.
     * @throws SigningException If the method fails.
     */
    public static byte[ ] getSignatureTimeStampDataToStamp(Element dsSignature, String inputCanonicalizationAlgorithm) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG079));
	try {
	    // Comprobamos que se ha indicado el elemento ds:Signature
	    GenericUtilsCommons.checkInputParameterIsNotNull(dsSignature, Language.getResIntegra(ILogConstantKeys.TSU_LOG081));

	    // Instanciamos el array de bytes a devolver
	    byte[ ] dataToStamp = new byte[0];

	    // Si no se ha indicado algoritmo de canonicalización, se usará
	    // "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", definido
	    // como "Inclusivo"
	    String canonicalizationAlgorithm = defineCanonicalizationAlgorithm(inputCanonicalizationAlgorithm);
	    Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationAlgorithm);

	    // Accedemos al elemento ds:SignatureValue
	    NodeList listSignatureValue = dsSignature.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE_VALUE);
	    if (listSignatureValue == null || listSignatureValue.getLength() == 0) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG082);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    Node signatureValue = listSignatureValue.item(0);

	    // Canonicalizamos el elemento ds:SignatureValue
	    dataToStamp = canonicalizer.canonicalizeSubtree(signatureValue);
	    return dataToStamp;

	} catch (CanonicalizationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG083);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (InvalidCanonicalizerException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG083);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG080));
	}
    }

    /**
     * Method that obtains the signing certificate of a XML time-stamp.
     * @param xmlTimestamp Parameter that represents the <code>dss:Timestamp</code> element.
     * @return an object that represents the signing certificate.
     * @throws SigningException If the certificate cannot be retrieved.
     */
    public static X509Certificate getCertificateFromXMLTimestamp(Element xmlTimestamp) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG104));
	try {
	    // Comprobamos que se ha indicado el elemento dss:Timestamp
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlTimestamp, Language.getResIntegra(ILogConstantKeys.TSU_LOG106));

	    // Recorremos el árbol de elementos hasta encontrar la firma
	    X509Certificate cert = null;
	    Node xmlSigNode = getXMLSignatureNode(xmlTimestamp);

	    // Una vez hemos encontrada la firma
	    if (xmlSigNode != null) {
		try {
		    org.apache.xml.security.signature.XMLSignature sig = new org.apache.xml.security.signature.XMLSignature((Element) xmlSigNode, "");
		    if (sig.getKeyInfo() != null && sig.getKeyInfo().getX509Certificate() != null) {
			// Accedemos al certificado
			cert = UtilsCertificateCommons.generateCertificate(sig.getKeyInfo().getX509Certificate().getEncoded());
		    }
		} catch (Exception e) {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG107);
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		}
	    }
	    if (cert == null) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG108);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    return cert;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG105));
	}
    }

    /**
     * Method that obtains the ds:Signature element from a XML timestamp.
     * @param xmlTimestamp Parameter that represents the XML timestamp.
     * @return an object that represents the ds:Signature element.
     */
    private static Node getXMLSignatureNode(Element xmlTimestamp) {
	Node xmlSigNode = null;
	NodeList childElements = xmlTimestamp.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
	int i = 0;
	while (i < childElements.getLength() && xmlSigNode == null) {
	    Node currentNode = childElements.item(i);
	    if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
		xmlSigNode = currentNode;
	    }
	    i++;
	}
	return xmlSigNode;
    }

    /**
     * Method that validates the references contained inside of a XML time-stamp.
     * @param xmlTST Parameter that represents the node as the XML time-stamp.
     * @param stampedData Parameter that represents the data stamped to compare with it.
     * @param signatureTimeStampId Parameter that represents the value of <code>Id</code> attribute of the <code>xades:SignatureTimeStamp</code> element.
     * @throws SigningException If the validation fails.
     */
    public static void validateTimeStampReferences(Node xmlTST, byte[ ] stampedData, String signatureTimeStampId) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG117));

	try {
	    // Comprobamos que se ha indicado el elemento dss:Timestamp
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlTST, Language.getResIntegra(ILogConstantKeys.TSU_LOG106));

	    // Comprobamos que se han indicado los datos sellados
	    GenericUtilsCommons.checkInputParameterIsNotNull(stampedData, Language.getResIntegra(ILogConstantKeys.TSU_LOG109));

	    // Accedemos al elemento ds:Signature
	    Element signature = getSignatureElement(xmlTST, signatureTimeStampId);

	    // Obtenemos el elemento ds:SignedInfo
	    Element signedInfo = getSignedInfoElement(signature, signatureTimeStampId);

	    // Obtenemos el elemento dss:TstInfo
	    Element tstInfo = getTstInfo(signature, signatureTimeStampId);

	    // Validamos las referencias del sello de tiempo
	    validateReferences(signedInfo, signatureTimeStampId, tstInfo, stampedData);

	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG119));
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.TSU_LOG118));
	}
    }

    /**
     * Method that validates the references contained inside of a XML timestamp.
     * @param signedInfo Parameter that represents the <code>SignedInfo</code> element.
     * @param signatureTimeStampId Parameter that represents the value of <code>Id</code> attribute of the <code>xades:SignatureTimeStamp</code> element.
     * @param tstInfo Parameter that represents the <code>Object</code> which contains the <code>TstInfo</code> element from a XML timestamp.
     * @param stampedData Parameter that represents the original data stamped by the XML timestamp.
     * @throws SigningException If the validation fails.
     */
    private static void validateReferences(Element signedInfo, String signatureTimeStampId, Element tstInfo, byte[ ] stampedData) throws SigningException {
	// Recorremos las referencias, que deberían ser 2, una para los datos
	// sellados, y otra para el elemento dss:TstInfo
	NodeList referencesList = signedInfo.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_REFERENCE);
	for (int i = 0; i < referencesList.getLength(); i++) {
	    Element reference = (Element) referencesList.item(i);
	    String referenceId = reference.getAttribute(IXMLConstants.ATTRIBUTE_ID);
	    // Comprobamos si la referencia es hacia el sello de tiempo
	    String type = reference.getAttribute(IXMLConstants.ATTRIBUTE_TYPE);
	    if (type != null && type.equalsIgnoreCase("urn:oasis:names:tc:dss:1.0:core:schema:XMLTimeStampToken")) {
		validateReferenceToTstInfo(tstInfo, reference, signatureTimeStampId, referenceId);
	    }
	    // Si la referencia es hacia los datos firmados
	    else {
		validateReferenceToOriginalData(stampedData, reference, tstInfo, signatureTimeStampId, referenceId);
	    }
	}
    }

    /**
     * Method that validates the reference to the original data stamped by a XML timestamp.
     * @param stampedData Parameter that represents the original data stamped by the XML timestamp.
     * @param reference Parameter that represents the <code>Reference</code> element.
     * @param tstInfo Parameter that represents the <code>Object</code> which contains the <code>TstInfo</code> element from a XML timestamp.
     * @param signatureTimeStampId Parameter that represents the value of <code>Id</code> attribute of the <code>xades:SignatureTimeStamp</code> element.
     * @param referenceId Parameter that represents the value of <code>Id</code> attribute of <code>Reference</code>.
     * @throws SigningException If the validation fails.
     */
    private static void validateReferenceToOriginalData(byte[ ] stampedData, Element reference, Element tstInfo, String signatureTimeStampId, String referenceId) throws SigningException {
	// Obtenemos la lista de transformadas de la referencia
	byte[ ] stampedDataProcessed = stampedData.clone();
	Element transforms = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORMS).item(0);
	if (transforms != null) {
	    NodeList transformsList = transforms.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORM);
	    for (int j = 0; j < transformsList.getLength(); j++) {
		Element transform = (Element) transformsList.item(j);
		String canonicalizationAlgorithm = transform.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
		try {
		    stampedDataProcessed = Canonicalizer.getInstance(canonicalizationAlgorithm).canonicalizeSubtree(tstInfo);
		} catch (Exception e) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG114, new Object[ ] { signatureTimeStampId, referenceId });
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		}
	    }
	}
	// Obtenemos el algoritmo de resumen utilizado, en caso de
	// estar. En caso contrario se supone haber usado SHA-1
	String uriHashAlgorithm = DigestMethod.SHA1;
	MessageDigest md = null;
	String stampedDataProcessedString = null;
	Element digestMethod = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).item(0);
	if (digestMethod != null) {
	    uriHashAlgorithm = digestMethod.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
	}

	try {
	    // Calculamos el resumen de los datos canonicalizados
	    String hashAlgorithm = CryptoUtilXML.translateXmlDigestAlgorithm(uriHashAlgorithm);
	    if (hashAlgorithm == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG114, new Object[ ] { referenceId, signatureTimeStampId, uriHashAlgorithm });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    md = MessageDigest.getInstance(hashAlgorithm);
	    md.update(stampedDataProcessed);
	    stampedDataProcessedString = new String(Base64.encode(md.digest()));
	} catch (Exception e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG114, new Object[ ] { signatureTimeStampId, referenceId });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}

	// Comprobamos si los datos coinciden
	String digestValueString = null;
	Element digestValue = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).item(0);
	if (digestValue != null) {
	    digestValueString = digestValue.getTextContent();
	}
	if (!stampedDataProcessedString.equals(digestValueString)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG116, new Object[ ] { signatureTimeStampId, referenceId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that validates the reference of <code>dss:TstInfo</code> element inside of a XML timestamp.
     * @param tstInfo Parameter that represents the <code>Object</code> which contains the dss:TstInfo element from a XML timestamp.
     * @param reference Parameter that represents the <code>Reference</code> element.
     * @param signatureTimeStampId Parameter that represents the value of <code>Id</code> attribute of the <code>xades:SignatureTimeStamp</code> element.
     * @param referenceId Parameter that represents the value of <code>Id</code> attribute of <code>Reference</code>.
     * @throws SigningException If the validation fails.
     */
    private static void validateReferenceToTstInfo(Element tstInfo, Element reference, String signatureTimeStampId, String referenceId) throws SigningException {
	// Comprobamos si la URI coincide con el Id del elemento TstInfo
	if (!tstInfo.getAttribute(IXMLConstants.ATTRIBUTE_ID).equals(reference.getAttribute(IXMLConstants.ATTRIBUTE_URI).replace("#", ""))) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG113, new Object[ ] { signatureTimeStampId, referenceId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	// Obtenemos la lista de transformadas de la referencia
	byte[ ] tstInfoProcessed = null;
	Element transforms = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORMS).item(0);
	if (transforms != null) {
	    NodeList transformsList = transforms.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORM);
	    for (int j = 0; j < transformsList.getLength(); j++) {
		Element transform = (Element) transformsList.item(j);
		String canonicalizationAlgorithm = transform.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
		try {
		    tstInfoProcessed = Canonicalizer.getInstance(canonicalizationAlgorithm).canonicalizeSubtree(tstInfo);
		} catch (Exception e) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG114, new Object[ ] { signatureTimeStampId, referenceId });
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		}
	    }
	}
	// Obtenemos el algoritmo de resumen utilizado, en caso de
	// estar. En caso contrario se supone haber usado SHA-1
	String hashAlgorithm = DigestMethod.SHA1;
	Element digestMethod = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD).item(0);
	if (digestMethod != null) {
	    hashAlgorithm = digestMethod.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
	}
	// Calculamos el resumen de los datos canonicalizados
	String tstInfoProcessedString = null;
	try {
	    MessageDigest md = MessageDigest.getInstance(CryptoUtilXML.translateXmlDigestAlgorithm(hashAlgorithm));
	    if (md == null) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG114, new Object[ ] { signatureTimeStampId, referenceId });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	    md.update(tstInfoProcessed);
	    tstInfoProcessedString = new String(Base64.encode(md.digest()));
	} catch (NoSuchAlgorithmException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG114, new Object[ ] { signatureTimeStampId, referenceId });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}

	// Comprobamos si los datos coinciden
	String digestValueString = null;
	Element digestValue = (Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE).item(0);
	if (digestValue != null) {
	    digestValueString = digestValue.getTextContent();
	}
	if (!tstInfoProcessedString.equals(digestValueString)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG115, new Object[ ] { signatureTimeStampId, referenceId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that obtains the <code>ds:Signature</code> element from a XAdES signature.
     * @param xmlTST Parameter that represents the XMLTimeStamp element of a XAdES signature.
     * @param signatureTimeStampId Parameter that represents the value of <code>Id</code> attribute of the <code>xades:SignatureTimeStamp</code> element.
     * @return an object that represents the <code>ds:Signature</code> element.
     * @throws SigningException If the method fails.
     */
    private static Element getSignatureElement(Node xmlTST, String signatureTimeStampId) throws SigningException {
	NodeList xmlTimestampChildNodes = xmlTST.getChildNodes();
	int i = 0;
	Element signature = null;
	while (i < xmlTimestampChildNodes.getLength() && signature == null) {
	    if (xmlTimestampChildNodes.item(i).getNodeType() == Node.ELEMENT_NODE && xmlTimestampChildNodes.item(i).getNamespaceURI().equals(XMLSignature.XMLNS) && xmlTimestampChildNodes.item(i).getLocalName().equals(IXMLConstants.ELEMENT_SIGNATURE)) {
		signature = (Element) xmlTimestampChildNodes.item(i);
	    }
	    i++;
	}
	if (signature == null) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG110, new Object[ ] { signatureTimeStampId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	return signature;
    }

    /**
     * Method that obtains the <code>ds:SignedInfo</code> element from a XAdES signature.
     * @param signature Parameter that represents the <code>ds:Signature</code> element.
     * @param signatureTimeStampId Parameter that represents the value of <code>Id</code> attribute of the <code>xades:SignatureTimeStamp</code> element.
     * @return an object that represents the <code>ds:SignedInfo</code> element.
     * @throws SigningException If the method fails.
     */
    private static Element getSignedInfoElement(Element signature, String signatureTimeStampId) throws SigningException {
	// Obtenemos el elemento ds:SignedInfo
	NodeList signatureChildNodes = signature.getChildNodes();
	Element signedInfo = null;
	int i = 0;
	while (i < signatureChildNodes.getLength() && signedInfo == null) {
	    if (signatureChildNodes.item(i).getNodeType() == Node.ELEMENT_NODE && signatureChildNodes.item(i).getNamespaceURI().equals(XMLSignature.XMLNS) && signatureChildNodes.item(i).getLocalName().equals(IXMLConstants.ELEMENT_SIGNED_INFO)) {
		signedInfo = (Element) signatureChildNodes.item(i);
	    }
	    i++;
	}
	if (signedInfo == null) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG111, new Object[ ] { signatureTimeStampId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	return signedInfo;
    }

    /**
     * Method that check if a XML timestamp contains the <code>dss:TstInfo</code> element and returns it.
     * @param signature Parameter that represents the <code>ds:Signature</code> element of the XML timestamp.
     * @param signatureTimeStampId Parameter that represents the value of <code>Id</code> attribute of the <code>xades:SignatureTimeStamp</code> element.
     * @return an object that represents the <code>dss:TstInfo</code>.
     * @throws SigningException If the method fails.
     */
    private static Element checkTstInfoElementExists(Element signature, String signatureTimeStampId) throws SigningException {
	// Obtenemos el elemento dss:TstInfo
	NodeList signatureChildNodes = signature.getChildNodes();
	Element tstInfo = null;
	int i = 0;
	while (i < signatureChildNodes.getLength() && tstInfo == null) {
	    if (signatureChildNodes.item(i).getNodeType() == Node.ELEMENT_NODE && signatureChildNodes.item(i).getNamespaceURI().equals(XMLSignature.XMLNS) && signatureChildNodes.item(i).getLocalName().equals(IXMLConstants.ELEMENT_OBJECT) && signatureChildNodes.item(i).getFirstChild().getLocalName().equals(IXMLConstants.ELEMENT_TST_INFO)) {
		tstInfo = (Element) signatureChildNodes.item(i).getFirstChild();
	    }
	    i++;
	}
	if (tstInfo == null) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG112, new Object[ ] { signatureTimeStampId });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	return tstInfo;
    }

    /**
     * Method that obtains the <code>ds:Object</code> which contains the <code>dss:TstInfo</code> element from a XML timestamp.
     * @param signature Parameter that represents the <code>ds:Signature</code> element of the XML timestamp.
     * @param signatureTimeStampId Parameter that represents the value of <code>Id</code> attribute of the <code>xades:SignatureTimeStamp</code> element.
     * @return the parent element of TstInfo element.
     * @throws SigningException If the method fails.
     */
    private static Element getTstInfo(Element signature, String signatureTimeStampId) throws SigningException {
	// Obtenemos el elemento dss:TstInfo
	Element tstInfo = checkTstInfoElementExists(signature, signatureTimeStampId);

	return (Element) tstInfo.getParentNode();
    }
}
