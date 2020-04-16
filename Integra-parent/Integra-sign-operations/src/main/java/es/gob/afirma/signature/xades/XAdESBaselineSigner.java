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
 * <b>File:</b><p>es.gob.afirma.signature.xades.XAdESBaselineSigner.java.</p>
 * <b>Description:</b><p>Class that manages the generation, validation and upgrade of XAdES Baseline signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.9, 16/04/2020.
 */
package es.gob.afirma.signature.xades;

import static es.gob.afirma.signature.SignatureConstants.SIGN_ALGORITHM_URI;
import static es.gob.afirma.signature.SignatureConstants.SIGN_FORMAT_XADES_DETACHED;
import static es.gob.afirma.signature.SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED;
import static es.gob.afirma.signature.SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING;
import static es.gob.afirma.signature.SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.apache.xml.crypto.MarshalException;
import org.apache.xml.crypto.XMLStructure;
import org.apache.xml.crypto.dom.DOMStructure;
import org.apache.xml.crypto.dsig.CanonicalizationMethod;
import org.apache.xml.crypto.dsig.DigestMethod;
import org.apache.xml.crypto.dsig.Manifest;
import org.apache.xml.crypto.dsig.Reference;
import org.apache.xml.crypto.dsig.Transform;
import org.apache.xml.crypto.dsig.XMLObject;
import org.apache.xml.crypto.dsig.XMLSignature;
import org.apache.xml.crypto.dsig.XMLSignatureException;
import org.apache.xml.crypto.dsig.XMLSignatureFactory;
import org.apache.xml.crypto.dsig.spec.TransformParameterSpec;
import org.apache.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.IntegraFacadeConstants;
import es.gob.afirma.integraFacade.pojo.TransformData;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetectorXades;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.Signer;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.policy.ISignPolicyConstants;
import es.gob.afirma.signature.policy.SignaturePolicyException;
import es.gob.afirma.signature.policy.SignaturePolicyManager;
import es.gob.afirma.signature.validation.ISignatureValidationTaskID;
import es.gob.afirma.signature.validation.ITimestampValidationTaskID;
import es.gob.afirma.signature.validation.SignerValidationResult;
import es.gob.afirma.signature.validation.TimeStampValidationInfo;
import es.gob.afirma.signature.validation.TimestampValidationResult;
import es.gob.afirma.signature.validation.ValidationInfo;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.DSSConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.IUtilsSignature;
import es.gob.afirma.utils.IUtilsTimestamp;
import es.gob.afirma.utils.IntegraProvider;
import es.gob.afirma.utils.UtilsCertificateCommons;
import es.gob.afirma.utils.UtilsResourcesSignOperations;
import es.gob.afirma.utils.UtilsSignatureCommons;
import es.gob.afirma.utils.UtilsSignatureOp;
import es.gob.afirma.utils.UtilsTimestampOcspRfc3161;
import es.gob.afirma.utils.UtilsTimestampPdfBc;
import es.gob.afirma.utils.UtilsTimestampWS;
import es.gob.afirma.utils.UtilsTimestampXML;
import es.gob.afirma.utils.UtilsXML;
import es.gob.afirma.utils.XAdESTimeStampType;
import net.java.xades.security.xml.XAdES.DataObjectFormat;
import net.java.xades.security.xml.XAdES.DataObjectFormatImpl;
import net.java.xades.security.xml.XAdES.SignerRole;
import net.java.xades.security.xml.XAdES.SignerRoleImpl;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_EPES;

/**
 * <p>Class that manages the generation, validation and upgrade of XAdES Baseline signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.9, 16/04/2020.
 */
public final class XAdESBaselineSigner implements Signer {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(XAdESBaselineSigner.class);

    /**
     * Attribute that represents factory for building XML documents.
     */
    private static DocumentBuilderFactory dBFactory = null;

    /**
     * Attribute that represents a factory for creating XMLSignature objects from scratch or for unmarshalling an XMLSignature object.
     */
    private static XMLSignatureFactory xmlSignatureFactory = null;

    /**
     * Attribute that represents default digest algorithm in the xml references.
     */
    private String digestAlgorithmRef = DigestMethod.SHA1;

    /**
     * Attribute that represents default digest algorithm in the xml references to ASICS signatures.
     */
    private String digestAlgorithmRefAsic = DigestMethod.SHA1;

    /**
     * Attribute that represents algorithm to encrypt data to be signed.
     */
    private String algorithmRefAsic = "SHA1";
    /**
     * Attribute that represents dataElement object.
     */
    private Element dataElement = null;

    /**
     * Attribute that represents contentId element.
     */
    private String contentId = null;

    /**
     * Attribute that represents data type of a document.
     */
    private int dataType = IXMLConstants.DATA_TYPE_BINARY;

    /**
     * Attribute that represents the <code>xades:DataObjectFormat</code> element.
     */
    private DataObjectFormat dataObjectFormat = null;

    static {
	AccessController.doPrivileged(new java.security.PrivilegedAction<Void>() {

	    public Void run() {
		try {
		    Security.insertProviderAt(new org.apache.xml.dsig.internal.dom.XMLDSigRI(), 1);
		} catch (final SecurityException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.XBS_LOG001), e);
		}
		return null;
	    }
	});
    }

    /**
     * Constructor method for the class XAdESBaselineSigner.java.
     */
    public XAdESBaselineSigner() {
	if (dBFactory == null) {
	    dBFactory = DocumentBuilderFactory.newInstance();
	    dBFactory.setNamespaceAware(true);
	}
	if (xmlSignatureFactory == null) {
	    xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", new IntegraProvider());
	}
	// Añadimos el proveedor criptográfico Bouncycastle en caso de que no
	// esté incluído
	if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
	    Security.addProvider(new BouncyCastleProvider());
	}
	org.apache.xml.security.Init.init();
    }

    /**
     * Method that defines the canonicalization algorithm to use for signature generation operations from the value defined by the user. If the user didn't define a valid value
     * the canonicalization algorithm to use will be {@link CanonicalizationMethod#EXCLUSIVE}.
     * @param optionalParams Parameter that represents the set o extra configuration parameters defined by the user.
     * @return the canonicalization algorithm to use for signature generation operations.
     */
    private String defineCanonicalizationMethod(Properties optionalParams) {
	String canonicalizationMethod = optionalParams.getProperty(SignatureProperties.XADES_CANONICALIZATION_METHOD);
	if (canonicalizationMethod == null || canonicalizationMethod.isEmpty()) {
	    canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
	}
	return canonicalizationMethod;
    }

    /**
     * Method that generates a XAdES Baseline signature.
     * @param data Parameter that represents the data to sign.
     * @param algorithm Parameter that represents the signature algorithm.
     * @param signatureFormat Parameter that represents the signing mode.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters.
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @param asicsSignature Parameter indicating that the XAdES signature that is generated will be included in a signature ASiC-S.
     * @param fileToSignName  Parameter that indicates the name of the document to sign.
     * @return the generated signature.
     * @throws SigningException If the method fails.
     * @throws MarshalException If the method fails.
     * @throws XMLSignatureException If the method fails.
     * @throws GeneralSecurityException If the method fails.
     * @throws ParserConfigurationException If the method fails.
     * @throws TransformersException If the method fails.
     * @throws UnsupportedEncodingException If the method fails.
     * @throws InvalidCanonicalizerException If the method fails.
     */
    private byte[ ] generateXAdESSignature(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient, boolean asicsSignature, String fileToSignName) throws SigningException, MarshalException, XMLSignatureException, GeneralSecurityException, ParserConfigurationException, TransformersException, UnsupportedEncodingException, InvalidCanonicalizerException {
	// Se crea documento XML
	Document docSignature = null;
	// Comprobamos que se ha indicado el algoritmo de firma y tiene un
	// valor admitido
	checkInputSignatureAlgorithm(algorithm);

	// Comprobamos que se ha indicado el formato de la firma a generar y
	// es un formato admitido
	checkInputSignatureForm(signatureForm);

	// Comprobamos que se ha indicado la clave privada
	checkInputPrivateKey(privateKey);

	// Comprobamos que se ha indicado el tipo de firma a generar y, en
	// consecuencia, los datos a firmar si es necesario
	checkInputSignatureFormat(signatureFormat, data);

	// Inicializamos los parámetros extra en caso de no haberse indicado
	Properties optionalParams = checkInputExtraParams(extraParams);

	// Comprobamos si en los parámetros extra se ha indicado la propiedad
	// SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP
	checkDataObjectFormatDescriptionInputParameter(optionalParams);

	// Comprobamos si en los parámetros extra se ha indicado la propiedad
	// SignatureProperties.XADES_DATA_FORMAT_MIME_PROP
	checkDataObjectFormatMimeType(optionalParams, data);

	// Obtenemos la URI del algoritmo de firma
	String uriSignAlgorithm = SIGN_ALGORITHM_URI.get(algorithm);

	// Obtenemos el algoritmo de hash
	digestAlgorithmRef = SignatureConstants.DIGEST_METHOD_ALGORITHMS_XADES.get(algorithm);

	// Creamos el documento XML
	if (asicsSignature) {
	    docSignature = createXMLDocument();

	} else {
	    // Creamos el nodo que contendrá los datos a firmar, menos en el
	    // caso de firmas Externally Detached
	    createDataNode(data, signatureFormat);
	    docSignature = createXMLDocument(signatureFormat);
	}

	// Generamos el objeto que representará la firma
	XAdES_EPES xades = generateXAdESElement(privateKey, optionalParams, docSignature.getDocumentElement());

	// Instanciamos el objeto que permite la generación de la firma
	// XAdES
	XadesExt signBuilder = XadesExt.newInstance(xades, true);

	// Asociamos el algoritmo de hash a la firma
	signBuilder.setDigestMethod(digestAlgorithmRef);

	// Asociamos el algoritmo de canonicalización a la firma
	signBuilder.setCanonicalizationMethod(defineCanonicalizationMethod(optionalParams));

	// Creamos el conjunto de referencias
	List<Reference> references = buildReferences(signBuilder, signatureFormat, optionalParams, fileToSignName, data);

	// Definimos una variable para determinar si añadir política de
	// firma
	boolean mustContainSignaturePolicy = false;
	String policyID = null;

	// Accedemos al archivo con las propiedades asociadas a las
	// políticas de firma
	Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	// Si se ha indicado política de firma
	if (signaturePolicyID != null) {
	    mustContainSignaturePolicy = true;

	    // Buscamos en el archivo con las propiedades asociadas a las
	    // políticas de firma si existe la política de firma para el
	    // identificador indicado
	    if (policyProperties.get(signaturePolicyID + ISignPolicyConstants.KEY_IDENTIFIER_XML) != null) {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG025, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE, signaturePolicyID }));
		policyID = signaturePolicyID;
	    } else {
		// Rescatamos del archivo con las propiedades asociadas a
		// las políticas de firma el identificador de la política de
		// firma
		// asociada a las firmas XML
		policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

		// Comprobamos que el identificador de la política de firma
		// para
		// XAdES no sea nulo ni vacío
		if (!GenericUtilsCommons.assertStringValue(policyID)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG026, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		    LOGGER.warn(errorMsg);
		    mustContainSignaturePolicy = false;
		} else {
		    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG042, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE, policyID }));
		}
	    }
	    // En caso de que la firma a generar deba incluir política de
	    // firma, comprobamos si el
	    // algoritmo de firma está soportado por la política de firma,
	    // si el algoritmo de hash está soportado por la política de
	    // firma, si
	    // el modo de firma está soportado por la política de firma, y
	    // añadimos a la firma los valores asociados a la política de
	    // firma
	    addSignPolicy(mustContainSignaturePolicy, uriSignAlgorithm, policyID, policyProperties, optionalParams, xades, signatureFormat, idClient);
	}
	// Definimos el Id de la nueva firma
	String signatureId = "Signature-" + UUID.randomUUID().toString();

	// Generamos la firma como tal
	signBuilder.sign((X509Certificate) privateKey.getCertificate(), privateKey.getPrivateKey(), uriSignAlgorithm, references, signatureId, null);

	// Si se esta realizando una firma enveloping quitamos el nodo raíz
	// y extraemos la firma.
	if (signatureFormat.equals(SIGN_FORMAT_XADES_ENVELOPING) && docSignature.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE).getLength() == 1) {
	    Document newdoc = dBFactory.newDocumentBuilder().newDocument();
	    newdoc.appendChild(newdoc.adoptNode(docSignature.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE).item(0)));
	    docSignature = newdoc;
	}

	// Accedemos al elemento ds:Signature que acabamos de crear
	Element dsSignature = UtilsSignatureOp.getXMLSignatureById(docSignature, signatureId + "-Signature");
	if (dsSignature == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Añadimos el sello de tiempo, en caso de ser necesario, y
	// validamos el
	// certificado firmante, respecto a la fecha actual si no se incluye
	// sello de tiempo,
	// o respecto a la fecha indicada en el sello de tiempo en caso de
	// que
	// se incluya
	addTimestampAndValidateSigningCertificate(includeTimestamp, dsSignature, (X509Certificate) privateKey.getCertificate(), idClient);

	// Comprobamos que la firma generada cumple con las características
	// de
	// la política de firma, en el caso de que la incluya
	if (mustContainSignaturePolicy) {
	    try {
		SignaturePolicyManager.validateGeneratedXAdESEPESSignature(dsSignature, policyID, policyProperties, idClient);
	    } catch (SignaturePolicyException e) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG034, new Object[ ] { e.getMessage() });
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	}

	// Informamos de que hemos generado la firma XAdES Baseline
	String xmlResult = UtilsXML.transformDOMtoString(docSignature);
	byte[ ] result = xmlResult.getBytes(SignatureConstants.UTF8_ENCODING);
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG035));

	// Escribimos la firma en el Log
	GenericUtilsCommons.printResult(result, LOGGER);

	// Devolvemos la firma XAdES generada
	return result;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#sign(byte[], java.lang.String, java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG002));
	try {
	    return generateXAdESSignature(data, algorithm, signatureFormat, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, idClient, false, null);
	} catch (UnsupportedEncodingException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (MarshalException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (XMLSignatureException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (GeneralSecurityException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (TransformersException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (InvalidCanonicalizerException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG003));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#sign(byte[], java.lang.String, java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException {
	return sign(data, algorithm, signatureFormat, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, null);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#sign(byte[], java.lang.String, java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */

    public byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, boolean asicsSignature, String signedFileName) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG002));
	try {
	    return generateXAdESSignature(data, algorithm, signatureFormat, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, null, true, signedFileName);
	} catch (UnsupportedEncodingException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (MarshalException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (XMLSignatureException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (GeneralSecurityException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (TransformersException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (InvalidCanonicalizerException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG036);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG003));
	}
    }

    /**
     * Method that checks if the property with the identifier of the client application for the communication with TS@ has been defined on the associated properties file (true) or not (false).
     * @param applicationID Parameter that represents the value for the identifier of the client application for the communication with TS@ defined on the associated properties file.
     * @throws SigningException If the method fails.
     */
    private void checkApplicationID(String applicationID) throws SigningException {
	if (applicationID == null || applicationID.trim().isEmpty()) {
	    String propertiesName = IIntegraConstants.PROPERTIES_FILE;
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG048, new Object[ ] { propertiesName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if the property with the communication mode with TS@ has been defined on the associated properties file (true) or not (false).
     * @param tsaCommunicationMode Parameter that represents the communication mode with TS@ defined on the associated properties file.
     * @throws SigningException If the method fails.
     */
    private void checkTSACommunicationMode(String tsaCommunicationMode) throws SigningException {
	if (tsaCommunicationMode == null || tsaCommunicationMode.trim().isEmpty()) {
	    String propertiesName = IIntegraConstants.PROPERTIES_FILE;
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG049, new Object[ ] { propertiesName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that checks if the property with the timestamp type to retrieve from TS@ has been defined on the associated properties file (true) or not (false).
     * @param timestampType Parameter that represents the timestamp type to retrieve from TS@ defined on the associated properties file.
     * @throws SigningException If the method fails.
     */
    private void checkTimestampType(String timestampType) throws SigningException {
	if (timestampType == null || timestampType.trim().isEmpty()) {
	    String propertiesName = IIntegraConstants.PROPERTIES_FILE;
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG050, new Object[ ] { propertiesName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that obtains a timestamp from TS@.
     * @param dataToStamp Parameter that represents the data to stamp.
     * @param idClient Parameter that represents the client application identifier.
     * @return an object that represents the timestamp. This object can be:
     * <ul>
     * <li>An instance of {@link TimeStampToken} when the timestamp is ASN.1 type.</li>
     * <li>An instance of {@link org.w3c.dom.Element} when the timestamp is XML type.</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private Object generateTimestamp(byte[ ] dataToStamp, String idClient) throws SigningException {
	String applicationID = null;
	String tsaCommunicationMode = null;
	String timestampType = null;

	Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);

	// Rescatamos del archivo de propiedades el identificador
	// de la aplicación cliente para conectarnos contra la TS@
	applicationID = (String) integraProperties.get(IntegraFacadeConstants.KEY_TSA_APP_ID);

	// Rescatamos del archivo de propiedades el modo en que
	// vamos a solicitar el sello de tiempo
	tsaCommunicationMode = (String) integraProperties.get(IntegraFacadeConstants.KEY_TSA_COMMUNICATION_TYPE);

	// Rescatamos del archivo de propiedades el tipo de sello
	// de tiempo a generar (ASN1 o XML)
	timestampType = (String) integraProperties.get(IntegraFacadeConstants.KEY_TSA_TIMESTAMP_TYPE);

	// Comprobamos que se ha indicado el identificador de la aplicación
	// cliente para la comunicación con TS@
	checkApplicationID(applicationID);

	// Comprobamos que se ha indicado el tipo de comunicación a usar para
	// obtener el sello de tiempo de TS@
	checkTSACommunicationMode(tsaCommunicationMode);

	// Comprobamos que se ha indicado el tipo de sello de tiempo a solicitar
	// a TS@
	checkTimestampType(timestampType);

	// Comprobamos que el tipo de sello de tiempo a generar es un valor
	// correcto
	if (timestampType.equals(IUtilsTimestamp.TIMESTAMP_TYPE_ASN1)) {
	    // Si el tipo de sello de tiempo a generar es ASN1, entonces,
	    // determinamos si se genera por el servicio RFC 3161 o bien por el
	    // servicio DSS

	    // Si el modo de comunicación es Servicio Web (DSS)
	    if (tsaCommunicationMode.equals(IUtilsTimestamp.TSA_DSS_COMMUNICATION)) {
		// Obtenemos el sello de tiempo
		TimeStampToken tst = (TimeStampToken) UtilsTimestampWS.getTimestampFromDssService(dataToStamp, applicationID, DSSConstants.TimestampForm.RFC_3161, idClient);

		// Validamos el sello de tiempo obtenido
		UtilsTimestampXML.validateASN1Timestamp(tst);

		// Devolvemos el sello de tiempo
		return tst;
	    }
	    // Si el modo de comunicación es RFC 3161
	    else {
		// Obtenemos el sello de tiempo
		TimeStampToken tst = UtilsTimestampOcspRfc3161.getTimestampFromRFC3161Service(dataToStamp, applicationID, tsaCommunicationMode);

		// Validamos el sello de tiempo obtenido
		UtilsTimestampXML.validateASN1Timestamp(tst);

		// Devolvemos el sello de tiempo
		return tst;
	    }
	} else if (timestampType.equals(IUtilsTimestamp.TIMESTAMP_TYPE_XML)) {
	    // El único modo de comunicación es DSS para obtener el sello de
	    // tiempo XML
	    Element tst = (Element) UtilsTimestampWS.getTimestampFromDssService(dataToStamp, applicationID, DSSConstants.TimestampForm.XML, idClient);

	    // Validamos el sello de tiempo obtenido
	    UtilsTimestampXML.validateXMLTimestamp(tst);

	    // Devolvemos el sello de tiempo
	    return tst;
	} else {
	    String propertiesName = IIntegraConstants.PROPERTIES_FILE;
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG033, new Object[ ] { timestampType, propertiesName });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that adds a timestamp to a XAdES signature if it's required to include the timestamp, and validates the signing certificate.
     * @param includeTimestamp Parameter that indicates if to include the timestamp (true) or not (false).
     * @param dsSignature Parameter that represents the <code>ds:Signature</code> element.
     * @param signerCertificate Parameter that represents the signing certificate.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     */
    private void addTimestampAndValidateSigningCertificate(boolean includeTimestamp, Element dsSignature, X509Certificate signerCertificate, String idClient) throws SigningException {
	// Definimos la fecha de validación del certificado firmante como la
	// fecha actual
	Date validationDate = Calendar.getInstance().getTime();
	// Comprobamos si es necesario añadir el sello de tiempo
	if (includeTimestamp) {

	    // Accedemos al elemento xades:QualifyingProperties
	    Element qualifyingProperties = UtilsSignatureOp.retrieveNode(dsSignature, IXMLConstants.ELEMENT_QUALIFIYING_PROPERTIES, IXMLConstants.XADES_1_3_2_NAMESPACE, true);

	    // Obtenemos los datos a sellar
	    byte[ ] dataToStamp = UtilsTimestampXML.getSignatureTimeStampDataToStamp(dsSignature, null);

	    // Obtenemos el sello de tiempo sobre el conjunto de datos
	    // procesados
	    Object tst = generateTimestamp(dataToStamp, idClient);

	    // Añadimos el elemento xades:UnsignedProperties, en caso de no
	    // estar
	    Element unsignedProperties = UtilsSignatureOp.retrieveNode(qualifyingProperties, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES, IXMLConstants.XADES_1_3_2_NAMESPACE, false);
	    if (unsignedProperties == null) {
		unsignedProperties = dsSignature.getOwnerDocument().createElementNS(DSSConstants.SignTypesURIs.XADES_V_1_3_2, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
		unsignedProperties.setPrefix(IXMLConstants.XADES_PREFIX);
		qualifyingProperties.appendChild(unsignedProperties);
	    }

	    // Añadimos el elemento UnsignedSignatureProperties, en caso de no
	    // estar
	    Element unsignedSignatureProperties = UtilsSignatureOp.retrieveNode(unsignedProperties, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES, IXMLConstants.XADES_1_3_2_NAMESPACE, false);
	    if (unsignedSignatureProperties == null) {
		unsignedSignatureProperties = dsSignature.getOwnerDocument().createElementNS(DSSConstants.SignTypesURIs.XADES_V_1_3_2, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
		unsignedSignatureProperties.setPrefix(IXMLConstants.XADES_PREFIX);
		unsignedProperties.appendChild(unsignedSignatureProperties);
	    }

	    // Añadimos el elemento SignatureTimeStamp
	    Element signatureTimeStamp = unsignedSignatureProperties.getOwnerDocument().createElementNS(DSSConstants.SignTypesURIs.XADES_V_1_3_2, IXMLConstants.ELEMENT_SIGNATURE_TIMESTAMP);
	    signatureTimeStamp.setPrefix(IXMLConstants.XADES_PREFIX);
	    signatureTimeStamp.setAttribute(IXMLConstants.ATTRIBUTE_ID, "SignatureTimeStamp-" + UUID.randomUUID().toString());

	    Element canonicalizationMethod = unsignedSignatureProperties.getOwnerDocument().createElementNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_CANONICALIZATION_METHOD);
	    canonicalizationMethod.setPrefix(IXMLConstants.DS_PREFIX);

	    canonicalizationMethod.setAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM, CanonicalizationMethod.INCLUSIVE);

	    signatureTimeStamp.appendChild(canonicalizationMethod);

	    // Diferenciamos el tipo de sello de tiempo obtenido
	    if (tst instanceof TimeStampToken) {
		// Sello de tiempo ASN.1
		Element encapsulatedTimeStamp = unsignedSignatureProperties.getOwnerDocument().createElementNS(DSSConstants.SignTypesURIs.XADES_V_1_3_2, IXMLConstants.ELEMENT_ENCAPSULATED_TIMESTAMP);
		encapsulatedTimeStamp.setPrefix(IXMLConstants.XADES_PREFIX);
		encapsulatedTimeStamp.setAttribute(IXMLConstants.ATTRIBUTE_ENCODING, "http://uri.etsi.org/01903/v1.2.2#DER");
		try {
		    encapsulatedTimeStamp.appendChild(unsignedSignatureProperties.getOwnerDocument().createTextNode(new String(Base64CoderCommons.encodeBase64(((TimeStampToken) tst).getEncoded()))));
		} catch (Exception e) {
		    throw new SigningException(Language.getResIntegra(ILogConstantKeys.XBS_LOG015), e);
		}
		signatureTimeStamp.appendChild(encapsulatedTimeStamp);

		// Obtenemos la fecha de generación del sello de tiempo
		validationDate = ((TimeStampToken) tst).getTimeStampInfo().getGenTime();
	    } else {
		// Sello de tiempo XML
		Element xmlTimeStamp = unsignedSignatureProperties.getOwnerDocument().createElementNS(DSSConstants.SignTypesURIs.XADES_V_1_3_2, IXMLConstants.ELEMENT_XML_TIMESTAMP);
		xmlTimeStamp.setPrefix(IXMLConstants.XADES_PREFIX);
		Node timestampNode = unsignedSignatureProperties.getOwnerDocument().importNode((Node) tst, true);
		xmlTimeStamp.appendChild(timestampNode);
		signatureTimeStamp.appendChild(xmlTimeStamp);

		// Obtenemos la fecha de generación del sello de tiempo
		validationDate = UtilsTimestampXML.getGenTimeXMLTimestamp(xmlTimeStamp);
	    }
	    unsignedSignatureProperties.appendChild(signatureTimeStamp);
	}
	// Validamos el certificado firmante
	UtilsSignatureOp.validateCertificate(signerCertificate, validationDate, false, idClient, false);
    }

    /**
     * Method that adds the elements related to the signature policy to the XAdES signature to generate if it must contain signature policy.
     * @param addSignaturePolicy Parameter that indicates if the XAdES signature will include signature policy (true) or not (false).
     * @param uriSignAlgorithm Parameter that represents the URI of the signature algorithm.
     * @param policyID Parameter that represents the identifier of the signature policy.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param extraParams Set of extra params.
     * @param xades Parameter that represents the signature.
     * @param signType Parameter that represents the signing mode.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     */
    private void addSignPolicy(boolean addSignaturePolicy, String uriSignAlgorithm, String policyID, Properties policyProperties, Properties extraParams, XAdES_EPES xades, String signType, String idClient) throws SigningException {
	if (addSignaturePolicy) {
	    // Comprobamos si el algoritmo de firma está soportado por la
	    // política de firma
	    if (!SignaturePolicyManager.isValidXMLSignAlgorithmByPolicy(uriSignAlgorithm, policyID, policyProperties, idClient)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG027, new Object[ ] { uriSignAlgorithm, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos si el algoritmo de hash está soportado por la
	    // política de firma
	    if (!SignaturePolicyManager.isValidXMLHashAlgorithmByPolicy(digestAlgorithmRef, policyID, policyProperties, idClient)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG028, new Object[ ] { digestAlgorithmRef, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Comprobamos si el modo de firma está soportado por la política de
	    // firma
	    String signingMode = IUtilsSignature.DETACHED_SIGNATURE_MODE;
	    if (signType.equals(SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED)) {
		signingMode = IUtilsSignature.ENVELOPED_SIGNATURE_MODE;
	    } else if (signType.equals(SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING)) {
		signingMode = IUtilsSignature.ENVELOPING_SIGNATURE_MODE;
	    }
	    if (!SignaturePolicyManager.isValidXMLSigningModeByPolicy(signingMode, policyID, policyProperties, idClient)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG029, new Object[ ] { signingMode, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Accedemos a la propiedad con el valor del
	    // elemento SigPolicyQualifier
	    String qualifier = extraParams.getProperty(SignatureProperties.XADES_POLICY_QUALIFIER_PROP);

	    // Procesamos los parámetros asociados a la política de firma
	    // que utilizar
	    try {
		SignaturePolicyManager.addXMLSignPolicy(xades, qualifier, policyID, policyProperties, idClient);
	    } catch (SignaturePolicyException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG030);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	}
    }

    /**
     * Method that obtains the digest method from {@link #digestAlgorithmRef}.
     * @return the generated digest method.
     * @throws SigningException If the method fails.
     */
    private DigestMethod getDigestMethod() throws SigningException {
	DigestMethod digestMethod = null;
	try {
	    digestMethod = xmlSignatureFactory.newDigestMethod(digestAlgorithmRef, null);
	} catch (GeneralSecurityException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG020, new Object[ ] { digestAlgorithmRef });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
	return digestMethod;
    }

    /**
     * Method that adds into the list with transforms the transform associated to the type of the data to sign.
     * @param transformList Parameter that represents the list with transforms to update.
     * @throws SigningException If the method fails.
     */
    private void addCanonicalization(List<Transform> transformList) throws SigningException {
	try {
	    // Añadimos la transformada para la canonicalización exclusiva
	    transformList.add(xmlSignatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null));
	} catch (Exception e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG021, new Object[ ] { CanonicalizationMethod.EXCLUSIVE });
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that generates an element to contain the signed data into the XML document and the associated reference.
     * @param referenceList Parameter that represents the list where to include the new reference.
     * @param transformList Parameter that represents the list with the transform to use on the generation of the new reference.
     * @param digestMethod Parameter that represents the digest method to use.
     * @param referenceId Parameter that represents the value of the <code>Id</code> attribute for the new reference.
     * @return an object that represents the new XML element.
     */
    private XMLObject newEnvelopingObject(List<Reference> referenceList, List<Transform> transformList, DigestMethod digestMethod, String referenceId) {
	// crea el nuevo elemento Object que contiene el documento a firmar
	final List<XMLStructure> structures = new ArrayList<XMLStructure>(1);

	// Si los datos se han convertido a base64, bien por ser binarios o
	// explicitos
	if (IXMLConstants.DATA_TYPE_BINARY_BASE64 == dataType || IXMLConstants.DATA_TYPE_BINARY == dataType) {
	    structures.add(new DOMStructure(dataElement.getFirstChild()));
	} else {
	    structures.add(new DOMStructure(dataElement));
	}

	String objectId = "Object-" + UUID.randomUUID().toString();
	String mime = IXMLConstants.DATA_TYPE_XML == dataType ? "text/xml" : "application/octet-stream";
	XMLObject envelopingObject = xmlSignatureFactory.newXMLObject(structures, objectId, mime, IXMLConstants.DATA_TYPE_XML == dataType ? null : IXMLConstants.ENCODING_BASE64);

	((DataObjectFormatImpl) dataObjectFormat).setObjectReference("#" + referenceId);

	// crea la referencia al nuevo elemento Object
	referenceList.add(xmlSignatureFactory.newReference("#" + objectId, digestMethod, transformList, IXMLConstants.OBJECT_URI, referenceId));
	return envelopingObject;
    }

    /**
     * Method that obtains a list with the references to include into a new XAdES signature.
     * @param xmlSignature Parameter that allows to generate the XAdES signature.
     * @param signatureFormat Parameter that represents the signing mode.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * @param extraParams Set with optional parameters.
     * @param signedFileName Parameter that represents the name of the data file to sign.
     * @param data Parameter that represents the input data to sign.
     * @return a list with the generated references.
     * @throws SigningException If the method fails.
     */
    private List<Reference> buildReferences(XadesExt xmlSignature, String signatureFormat, Properties extraParams, String signedFileName, byte[ ] data) throws SigningException {
	// Instanciamos una lista para ubicar las referencias a incluir en la
	// firma XML
	List<Reference> referenceList = new ArrayList<Reference>();

	// Obtenemos el algoritmo de resumen instanciado
	DigestMethod digestMethod = getDigestMethod();

	// Instanciamos una lista para ubicar las transformadas a utilizar en la
	// generación de las referencias
	List<Transform> transformList = new ArrayList<Transform>();

	// Generamos el identificador de la referencia
	String referenceId = "Reference-" + UUID.randomUUID().toString();

	// crea una referencia al documento insertado en un nodo Object para la
	// firma enveloping

	// Si la firma es Enveloping
	if (signatureFormat.equals(SIGN_FORMAT_XADES_ENVELOPING)) {
	    // Añadimos el algoritmo de canonicalización a la lista con las
	    // transformadas
	    addCanonicalization(transformList);

	    // Creamos el nodo para la firma Enveloping
	    XMLObject envelopingObject = newEnvelopingObject(referenceList, transformList, digestMethod, referenceId);

	    // incluimos el nuevo objeto en documento a firmar
	    xmlSignature.addXMLObject(envelopingObject);

	    // crea una referencia al documento mediante la URI hacia el
	    // identificador del nodo CONTENT
	} else if (signatureFormat.equals(SIGN_FORMAT_XADES_DETACHED)) {
	    try {
		addCanonicalization(transformList);
		if (signedFileName != null) {
		    ((DataObjectFormatImpl) dataObjectFormat).setObjectReference("#" + referenceId);

		    referenceList.add(createReferenceSignedDataAsics(referenceId, signedFileName, data));
		} else {

		    ((DataObjectFormatImpl) dataObjectFormat).setObjectReference("#" + referenceId);

		    // crea la referencia a los datos firmados que se
		    // encontraran en
		    // el mismo documento
		    referenceList.add(xmlSignatureFactory.newReference("#" + contentId, digestMethod, transformList, null, referenceId));
		}

	    } catch (DOMException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG022);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }

	    // crea una referencia indicando que se trata de una firma enveloped
	} else if (signatureFormat.equals(SIGN_FORMAT_XADES_ENVELOPED)) {
	    try {
		// Transformacion enveloped
		transformList.add(xmlSignatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));

		// Transformacion XPATH para eliminar el resto de firmas del
		// documento.
		transformList.add(xmlSignatureFactory.newTransform(Transform.XPATH, new XPathFilterParameterSpec("not(ancestor-or-self::" + IXMLConstants.DS_SIGNATURE_NODE_NAME + ")", Collections.singletonMap(IXMLConstants.DS_PREFIX, XMLSignature.XMLNS))));

		((DataObjectFormatImpl) dataObjectFormat).setObjectReference("#" + referenceId);

		// crea la referencia
		referenceList.add(xmlSignatureFactory.newReference("", digestMethod, transformList, null, referenceId));
	    } catch (GeneralSecurityException e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG022);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }

	    // crea una referencia para un objeto Manifest que contedrá las
	    // referencias externas al documento de la firma
	} else if (signatureFormat.equals(SIGN_FORMAT_XADES_EXTERNALLY_DETACHED) && extraParams.get(SignatureConstants.MF_REFERENCES_PROPERTYNAME) != null) {
	    addManifestObject(xmlSignature, referenceList, digestMethod, extraParams);

	}
	return referenceList;
    }

    /**
     * Method that obtains the reference to the signed data in a ASICS signatures.
     *
     * @param referenceId Parameter that represents the list of the references to include into the XAdES signature.
     * @param signedFileName Parameter that represents the name of the data file to sign.
     * @param data Parameter that represents the input data to sign.
     * @return Reference
     * @throws SigningException If the method fails.
     */
    private Reference createReferenceSignedDataAsics(String referenceId, String signedFileName, byte[ ] data) throws SigningException {

	Reference ref = null;
	byte[ ] digestValue = null;
	DigestMethod digestMethod = null;
	try {
	    digestValue = MessageDigest.getInstance(algorithmRefAsic).digest(data);
	    digestMethod = xmlSignatureFactory.newDigestMethod(digestAlgorithmRefAsic, null);

	    ref = xmlSignatureFactory.newReference(signedFileName, digestMethod, null, null, referenceId, digestValue);
	    return ref;

	} catch (NoSuchAlgorithmException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG052);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	} catch (InvalidAlgorithmParameterException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG052);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}

    }

    /**
     * Method that adds the <code>ds:Manifest</code> to a XAdES signature and include the associated reference into the list with the input references.
     * @param xmlSignature Parameter that allows to generate the XAdES signature.
     * @param referenceList Parameter that represents the list of the references to include into the XAdES signature.
     * @param digestMethod Parameter that represents the digest method.
     * @param extraParams Set with optional parameters.
     * @throws SigningException If the method fails.
     */
    @SuppressWarnings({ "unchecked" })
    private void addManifestObject(XadesExt xmlSignature, List<Reference> referenceList, DigestMethod digestMethod, Properties extraParams) throws SigningException {
	try {
	    // Recuperamos la lista que contiene los manifests y los data format
	    // object.
	    List<ReferenceDataBaseline> refAndDataFormatObjList = (List<ReferenceDataBaseline>) extraParams.get(SignatureConstants.MF_REFERENCES_PROPERTYNAME);

	    // Instanciamos el documento que contendrá el elemento Manifest de
	    // la firma.
	    Document mfDoc = UtilsXML.newDocument();

	    // Si existen pares de referencias/dataObjectFormat en los
	    // parámetros adicionales, los incluimos en el Manifest.
	    if (refAndDataFormatObjList.size() > 0) {

		// Instanciamos el elemento Manifest y lo incluimos en su nodo
		// padre.
		Element mfElement = mfDoc.createElement(IXMLConstants.MANIFEST_TAG_NAME);
		mfDoc.appendChild(mfElement);

		// Por cada par referencia/dataObjectFormat, los procesamos e
		// incluimos en la firma.
		for (ReferenceDataBaseline ref: refAndDataFormatObjList) {

		    // Incluimos la referencia en el Manifest.
		    if (ref instanceof ReferenceDataBaseline) {
			ReferenceData referenceData = new ReferenceData(ref.getDigestMethodAlg(), ref.getDigestValue());
			referenceData.setId(ref.getId());
			referenceData.setType(ref.getType());
			referenceData.setUri(ref.getUri());
			referenceData.setTransforms(ref.getTransforms());
			mfElement.appendChild(buildReferenceXmlNode(referenceData, mfDoc));
		    } else {
			String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG023);
			LOGGER.error(errorMsg);
			throw new SigningException(errorMsg);
		    }
		}
	    }

	    // Incluimos el elemento Manifest en la firma.
	    String manifestID = "ManifestObject-" + UUID.randomUUID().toString();
	    xmlSignature.addXMLObject(xmlSignatureFactory.newXMLObject(Collections.singletonList(new DOMStructure(mfDoc.getDocumentElement())), manifestID, null, null));

	    // Instanciamos el identificador para la referencia
	    String referenceId = "Reference-" + UUID.randomUUID().toString();

	    // Creamos la referencia al objeto manifest.
	    Reference ref = xmlSignatureFactory.newReference("#" + manifestID, digestMethod, null, Manifest.TYPE, referenceId);
	    referenceList.add(ref);

	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG024);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (ClassCastException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG024);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that adds into a XML document a reference.
     * @param rfData Parameter that represents the information about the reference to include.
     * @param doc Parameter that represents the XML document.
     * @return an element that represents the new reference.
     */
    private Element buildReferenceXmlNode(ReferenceData rfData, Document doc) {
	Element referenceElement = doc.createElement("ds:Reference");
	if (GenericUtilsCommons.assertStringValue(rfData.getId())) {
	    referenceElement.setAttribute(IXMLConstants.ATTRIBUTE_ID, rfData.getId());
	}
	if (GenericUtilsCommons.assertStringValue(rfData.getUri())) {
	    referenceElement.setAttribute(IXMLConstants.ATTRIBUTE_URI, rfData.getUri());
	}
	if (GenericUtilsCommons.assertStringValue(rfData.getType())) {
	    referenceElement.setAttribute(IXMLConstants.ATTRIBUTE_TYPE, rfData.getType());
	}

	if (rfData.getTransforms() != null) {
	    Element transformElements = UtilsXML.createChild(referenceElement, "ds:Transforms");
	    for (TransformData transform: rfData.getTransforms()) {
		if (transform != null) {
		    Element transfElement = UtilsXML.createChild(transformElements, "ds:Transform");
		    UtilsXML.insertAttributeValue(transfElement, "@Algorithm", transform.getAlgorithm());
		    if (transform.getXPath() != null) {
			for (String xPath: transform.getXPath()) {
			    if (GenericUtilsCommons.assertStringValue(xPath)) {
				UtilsXML.insertValueElement(transfElement, "ds:XPath", xPath);
			    }
			}
		    }
		}
	    }
	}
	UtilsXML.insertAttributeValue(referenceElement, "ds:DigestMethod@Algorithm", rfData.getDigestMethodAlg());
	UtilsXML.insertValueElement(referenceElement, "ds:DigestValue", rfData.getDigestValue());

	return referenceElement;
    }

    /**
     * Method that initializates the XAdES signature to generate.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra params.
     * @param element Parameter that represents the XML element where to include the XAdES signature.
     * @return the initializated XAdES signature.
     */
    @SuppressWarnings("unchecked")
    private XAdES_EPES generateXAdESElement(PrivateKeyEntry privateKey, Properties extraParams, Element element) {
	// Generamos el objeto que generará la firma
	XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.XADES_PREFIX, IXMLConstants.DS_PREFIX, digestAlgorithmRef, element);

	// Establecemos el elemento SigningTime
	xades.setSigningTime(Calendar.getInstance().getTime());

	// Establecemos el elemento SigningCertificate
	xades.setSigningCertificate((X509Certificate) privateKey.getCertificate());

	// Accedemos a la propiedad con los roles de la persona en
	// la firma electrónica
	String claimedRoles = extraParams.getProperty(SignatureProperties.XADES_CLAIMED_ROLE_PROP);
	// En caso de que se hayan indicado los roles de la persona en la firma
	// electrónica
	if (GenericUtilsCommons.assertStringValue(claimedRoles)) {
	    // Instanciamos el elemento SignerRole
	    SignerRole signerRole = new SignerRoleImpl();

	    // Recorremos los valores indicados para los elementos ClaimedRole
	    // contenidos dentro de SignerRole, separados por coma
	    String[ ] claimedRolValues = claimedRoles.split(",");
	    for (int i = 0; i < claimedRolValues.length; i++) {
		// Añadimos el elemento ClaimedRole
		String claimedRole = claimedRolValues[i].trim();
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG019, new Object[ ] { claimedRole }));
		signerRole.addClaimedRole(claimedRole);
	    }
	    xades.setSignerRole(signerRole);
	}

	ArrayList<DataObjectFormat> dofList = new ArrayList<DataObjectFormat>();
	// recuperamos la lista de pares referencias/dataObjectFormat.
	List<ReferenceDataBaseline> dataObjectList = (List<ReferenceDataBaseline>) extraParams.get(SignatureConstants.MF_REFERENCES_PROPERTYNAME);

	// Si es una XAdES externally detached...
	if (dataObjectList != null) {
	    // Por cada par, creamos el correspondiente elemento
	    // dataObjectFormat.
	    for (ReferenceDataBaseline ref: dataObjectList) {
		// Accedemos a la propiedad con la descripción del
		// documento original
		String dataFormDesc = ref.getDataFormatDescription();

		// Accedemos a la propiedad con la codificación para el
		// documento original
		String dataFormEnc = ref.getDataFormatEncoding();

		// Accedemos a la propiedad con el tipo de datos del
		// documento original
		String dataFormMime = ref.getDataFormatMimeType();

		// Establecemos el elemento DataObjectFormat
		dataObjectFormat = new DataObjectFormatImpl(dataFormDesc, null, dataFormMime, dataFormEnc, "#" + ref.getId());

		dofList.add(dataObjectFormat);
	    }
	    // Si es otro de otro tipo...
	} else {
	    // Accedemos a la propiedad con la descripción del
	    // documento original
	    String dataFormDesc = extraParams.getProperty(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP);

	    // Accedemos a la propiedad con la codificación para el
	    // documento original
	    String dataFormEnc = extraParams.getProperty(SignatureProperties.XADES_DATA_FORMAT_ENCODING_PROP);

	    // Accedemos a la propiedad con el tipo de datos del
	    // documento original
	    String dataFormMime = extraParams.getProperty(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP);

	    // Establecemos el elemento DataObjectFormat
	    dataObjectFormat = new DataObjectFormatImpl(dataFormDesc, null, dataFormMime, dataFormEnc, null);
	    dofList.add(dataObjectFormat);
	}
	xades.setDataObjectFormats(dofList);
	
	return xades;
    }

    /**
     * Method that checks if the set of extra parameters contains the property {@link SignatureProperties#XADES_DATA_FORMAT_DESCRIPTION_PROP} to assign a default value.
     * @param extraParams Parameter that represents the set of extra parameters to check.
     */
    @SuppressWarnings("unchecked")
    private void checkDataObjectFormatDescriptionInputParameter(Properties extraParams) {
	// Si no se ha indicado la propiedad
	// SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP
	if (!extraParams.containsKey(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP) || extraParams.getProperty(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP).isEmpty()) {
	    // Comprobamos si se trata de una firma con manifest y verificamos
	    // si tiene valores válidos para la propiedad.
	    if (extraParams.get(SignatureConstants.MF_REFERENCES_PROPERTYNAME) != null) {
		List<ReferenceDataBaseline> list = (List<ReferenceDataBaseline>) extraParams.get(SignatureConstants.MF_REFERENCES_PROPERTYNAME);
		List<ReferenceDataBaseline> manifestRef = list;
		for (ReferenceDataBaseline ref: manifestRef) {
		    String description = ref.getDataFormatDescription();
		    if (description == null || description.isEmpty()) {
			// Añadimos un valor constante
			ref.setDataFormatDescription(SignatureConstants.XADES_DATA_FORMAT_DESCRIPTION_PROP_DEFAULT);
		    }
		}
	    } else {
		// Añadimos un valor constante
		extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, SignatureConstants.XADES_DATA_FORMAT_DESCRIPTION_PROP_DEFAULT);
	    }
	}
    }

    /**
     * Method that checks if the set of extra parameters contains the property {@link SignatureProperties#XADES_DATA_FORMAT_MIME_PROP} to assign a default value by the mime-type of the input data.
     * @param extraParams Parameter that represents the set of extra parameters to check.
     * @param data Parameter that represents the input data to sign.
     */
    @SuppressWarnings("unchecked")
    private void checkDataObjectFormatMimeType(Properties extraParams, byte[ ] data) {
	// Si no se ha indicado la propiedad
	// SignatureProperties.XADES_DATA_FORMAT_MIME_PROP
	if (!extraParams.containsKey(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP) || extraParams.getProperty(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP).isEmpty()) {
	    // Comprobamos si se trata de una firma con manifest y verificamos
	    // si tiene valores válidos para la propiedad.
	    if (extraParams.get(SignatureConstants.MF_REFERENCES_PROPERTYNAME) != null) {
		List<ReferenceDataBaseline> list = (List<ReferenceDataBaseline>) extraParams.get(SignatureConstants.MF_REFERENCES_PROPERTYNAME);
		List<ReferenceDataBaseline> manifestRef = list;
		for (ReferenceDataBaseline ref: manifestRef) {
		    String mime = ref.getDataFormatMimeType();
		    if (mime == null || mime.isEmpty()) {
			// Añadimos un valor constante
			ref.setDataFormatMimeType(UtilsResourcesSignOperations.getMimeType(data));
		    }
		}
	    } else {
		// Indicamos el Mime-Type de los datos a firmar mediante la
		// librería Tika
		extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, UtilsResourcesSignOperations.getMimeType(data));
	    }
	}
    }

    /**
     * Method that checks if the set of extra parameters is <code>null</code>. In that case, the method initializates it.
     * @param extraParams Parameter that represents the set of extra parameters to check.
     * @return the set of extra parameters, at least, intializated.
     */
    private Properties checkInputExtraParams(Properties extraParams) {
	// Si los parámetros externos son nulos
	if (extraParams == null) {
	    // Los inicializamos
	    return new Properties();
	}
	return extraParams;
    }

    /**
     * Method that generates the XML document where to locate the signature.
     * @param signatureFormat Parameter that represents the signing mode.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * @return an object that represents the XML document.
     * @throws SigningException If the method fails.
     */
    private Document createXMLDocument(String signatureFormat) throws SigningException {
	try {
	    // Crea el nuevo documento org.w3c.dom.Document xml que contendrá la
	    // firma
	    Document docSignature = dBFactory.newDocumentBuilder().newDocument();
	    // inserta en el nuevo documento de firma el documento a firmar
	    if (signatureFormat.equals(SIGN_FORMAT_XADES_ENVELOPED)) {
		docSignature.appendChild(docSignature.adoptNode(dataElement));
	    } else {
		docSignature.appendChild(docSignature.createElement(IXMLConstants.AFIRMA_TAG));
		if (signatureFormat.equals(SIGN_FORMAT_XADES_DETACHED)) {
		    // inserta en el nuevo documento de firma el documento a
		    // firmar (en un nodo <CONTENT>)
		    docSignature.getDocumentElement().appendChild(docSignature.adoptNode(dataElement));
		}
	    }
	    return docSignature;
	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG014);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that updates the {@link #dataElement} with certain data.
     * @param data Parameter that represents the data.
     * @param signatureFormat Parameter that represents the signing mode.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private void createDataNode(byte[ ] data, String signatureFormat) throws SigningException {
	if (!SIGN_FORMAT_XADES_EXTERNALLY_DETACHED.equals(signatureFormat)) {
	    contentId = IXMLConstants.CONTENT_TAG + "-" + UUID.randomUUID().toString();
	    // Detección del tipo de datos a firmar. Diferenciamos entre
	    // documentos XML y resto de formatos
	    Document docum = null;
	    // se comprueba si es un documento xml
	    try {
		docum = dBFactory.newDocumentBuilder().parse(new ByteArrayInputStream(data));
		if (signatureFormat.equals(SIGN_FORMAT_XADES_DETACHED)) {
		    dataElement = docum.createElement(IXMLConstants.CONTENT_TAG);
		    dataElement.setAttribute(IXMLConstants.ATTRIBUTE_ID, contentId);
		    dataElement.setAttribute(IXMLConstants.ATTRIBUTE_MIME_TYPE, "text/xml");
		    // Obtenemos el encoding del documento original
		    dataElement.setAttribute(IXMLConstants.ATTRIBUTE_ENCODING, docum.getXmlEncoding());
		    dataElement.appendChild(docum.getDocumentElement());

		} else {
		    dataElement = docum.getDocumentElement();
		}
		dataType = IXMLConstants.DATA_TYPE_XML;

	    } catch (SAXException e) {
		// captura de error en caso de no ser un documento xml y
		// conversión a base64.
		createNodeBase64(data, signatureFormat);
	    } catch (Exception e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG012);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	}
    }

    /**
     * Method that updates the {@link #dataElement} with data encoded on Base64.
     * @param data Parameter that represents the data encoded on Base64.
     * @param signatureFormat Parameter that represents the signing mode.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private void createNodeBase64(byte[ ] data, String signatureFormat) throws SigningException {
	if (signatureFormat.equals(SIGN_FORMAT_XADES_ENVELOPED)) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG013);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
	// para los formatos de firma internally detached y enveloping se trata
	// de convertir el documento a base64

	try {
	    // crea un nuevo nodo xml para contener los datos en base 64
	    Document docFile = dBFactory.newDocumentBuilder().newDocument();
	    dataElement = docFile.createElement(IXMLConstants.CONTENT_TAG);
	    dataElement.setAttribute(IXMLConstants.ATTRIBUTE_ID, contentId);
	    dataElement.setAttribute(IXMLConstants.ATTRIBUTE_ENCODING, IXMLConstants.ENCODING_BASE64);

	    if (Base64CoderCommons.isBase64Encoded(data)) {
		dataElement.setTextContent(new String(data));
		dataType = IXMLConstants.DATA_TYPE_BINARY;
	    } else {
		dataElement.setTextContent(new String(Base64CoderCommons.encodeBase64(data)));
		dataType = IXMLConstants.DATA_TYPE_BINARY_BASE64;
	    }
	} catch (Exception e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG012);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}

    }

    /**
     * Method that checks if the input signature format is <code>null</code>, it's allowed to use, and the input data to sign is <code>null</code>, if the signature
     * format hasn't the value {@link SignatureConstants#SUPPORTED_XADES_SIGN_FORMAT}.
     * @param signatureFormat Parameter that represents the signature format to check.
     * @param data Parameter that represents the data to check.
     */
    private void checkInputSignatureFormat(String signatureFormat, byte[ ] data) {
	// Comprobamos que el tipo de firma no es nulo
	if (signatureFormat == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG010);
	    LOGGER.error(errorMsg);
	    throw new IllegalArgumentException(errorMsg);
	}

	// Comprobamos que el tipo de firma a generar está soportado
	if (!SignatureConstants.SUPPORTED_XADES_SIGN_FORMAT.contains(signatureFormat)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG011, new Object[ ] { signatureFormat });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}

	// Comprobamos que los datos a firmar no sean nulos, sólo si el tipo de
	// firma a generar no es Externally Detached
	if (!signatureFormat.equals(SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED) && data == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG004);
	    LOGGER.error(errorMsg);
	    throw new IllegalArgumentException(errorMsg);
	}
    }

    /**
     * Method that checks if the input signature format is <code>null</code>, it's allowed to use, and the input data to sign is <code>null</code>, if the signature
     * format hasn't the value {@link SignatureConstants#SUPPORTED_COUNTER_XADES_SIGN_FORMAT} for counter signatures.
     * @param signatureFormat Parameter that represents the signature format to check.
     */
    private void checkInputSignatureFormatCounter(String signatureFormat) {

	// Comprobamos que el tipo de firma a generar está soportado
	if (!SignatureConstants.SUPPORTED_COUNTER_XADES_SIGN_FORMAT.contains(signatureFormat)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG011, new Object[ ] { signatureFormat });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}

    }

    /**
     * Method that checks if the input private key is <code>null</code>.
     * @param privateKey Parameter that represents the private key to check.
     */
    private void checkInputPrivateKey(PrivateKeyEntry privateKey) {
	// Comprobamos que la clave privada no es nula
	if (privateKey == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG009);
	    LOGGER.error(errorMsg);
	    throw new IllegalArgumentException(errorMsg);
	}
    }

    /**
     * Method that checks if the input signature format is <code>null</code> and is allowed to use.
     * @param signatureForm Parameter that represents the signature format.
     */
    private void checkInputSignatureForm(String signatureForm) {
	// Comprobamos que el formato de la firma a generar no es nulo
	if (signatureForm == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG007);
	    LOGGER.error(errorMsg);
	    throw new IllegalArgumentException(errorMsg);
	}

	// Comprobamos que el formato de la firma a generar está
	// soportado.
	if (!signatureForm.equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG008, new Object[ ] { signatureForm });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}
    }

    /**
     * Method that checks if the input signature algorithm is <code>null</code> and is allowed to use.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     */
    private void checkInputSignatureAlgorithm(String signatureAlgorithm) {
	// Comprobamos que el algoritmo de firma no es nulo
	if (signatureAlgorithm == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG005);
	    LOGGER.error(errorMsg);
	    throw new IllegalArgumentException(errorMsg);
	}

	// Comprobamos que el algoritmo de firma está soportado
	if (!SignatureConstants.SIGN_ALGORITHMS_SUPPORT_CADES.containsKey(signatureAlgorithm)) {
	    String msg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG006, new Object[ ] { signatureAlgorithm });
	    LOGGER.error(msg);
	    throw new IllegalArgumentException(msg);
	}
    }

    /**
     * Method that checks if the input signature is <code>null</code>.
     * @param signature Parameter that represents the signature to check.
     */
    private void checkInputSignature(byte[ ] signature) {
	// Comprobamos que la firma no es nula
	if (signature == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG039);
	    LOGGER.error(errorMsg);
	    throw new IllegalArgumentException(errorMsg);
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#coSign(byte[], byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] coSign(byte[ ] signature, byte[ ] document, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG037));
	try {
	    // Comprobamos que se han indicado la firma a actualizar
	    checkInputSignature(signature);

	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkInputSignatureAlgorithm(algorithm);

	    // Comprobamos que se ha indicado la clave privada
	    checkInputPrivateKey(privateKey);

	    // / Inicializamos los parámetros extra en caso de no haberse
	    // indicado
	    Properties optionalParams = checkInputExtraParams(extraParams);

	    // Comprobamos si en los parámetros extra se ha indicado la
	    // propiedad SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP
	    checkDataObjectFormatDescriptionInputParameter(optionalParams);

	    // Comprobamos si en los parámetros extra se ha indicado la
	    // propiedad SignatureProperties.XADES_DATA_FORMAT_MIME_PROP
	    checkDataObjectFormatMimeType(optionalParams, document);

	    // Obtenemos la URI del algoritmo de firma
	    String uriSignAlgorithm = SIGN_ALGORITHM_URI.get(algorithm);

	    // Obtenemos el algoritmo de hash a partir del algoritmo de firma
	    digestAlgorithmRef = SignatureConstants.DIGEST_METHOD_ALGORITHMS_XADES.get(algorithm);

	    // Obtenemos el objeto Document a partir del array de bytes de la
	    // firma XAdES previa
	    Document eSignDoc = UtilsSignatureCommons.getDocumentFromXML(signature);

	    // Obtenemos del modo de firma (Enveloping, Enveloped o Detached) de
	    // la firma XAdES previa
	    String signType = UtilsSignatureOp.getTypeOfXMLSignature(eSignDoc);
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG040, new Object[ ] { signType }));

	    // En función del modo de firma creamos la co-firma
	    Document newCoSignDoc = null;

	    // Si el modo de firma es Enveloping
	    if (signType.equals(SIGN_FORMAT_XADES_ENVELOPING)) {
		// obtención del documento original a partir de la firma.
		byte[ ] originalDoc = UtilsSignatureOp.getOriginalDataFromSignedXMLDocument(eSignDoc);
		// creación de una firma nueva
		byte[ ] tmpSign = sign(originalDoc, algorithm, SIGN_FORMAT_XADES_ENVELOPING, privateKey, optionalParams, includeTimestamp, signatureForm, signaturePolicyID);
		// Creación de un nodo que contenga ambas firmas (antigua y
		// nueva)
		Element newCoSign = dBFactory.newDocumentBuilder().parse(new ByteArrayInputStream(tmpSign)).getDocumentElement();
		newCoSignDoc = UtilsSignatureOp.composeCoSignaturesDocument(eSignDoc, dBFactory);
		UtilsSignatureOp.appendXMLDocument(newCoSignDoc, newCoSign.getOwnerDocument());
	    }
	    // Si el modo de firma es Enveloped
	    else if (signType.equals(SIGN_FORMAT_XADES_ENVELOPED)) {
		newCoSignDoc = eSignDoc;
		generateXAdESCoSignature(newCoSignDoc, uriSignAlgorithm, privateKey, signType, optionalParams, signaturePolicyID, includeTimestamp, idClient);

	    }
	    // Si el modo de firma es Externally Detached
	    else if (signType.equals(SIGN_FORMAT_XADES_EXTERNALLY_DETACHED)) {
		// No se verifica el documento a firmar pues se firmará el
		// objeto Manifest incluido en la firma xml.
		// generación de la cofirma
		newCoSignDoc = eSignDoc;
		// Búsqueda de los datos a firmar externos(objeto Manifest)
		NodeList manifestObjects = newCoSignDoc.getElementsByTagName(IXMLConstants.MANIFEST_TAG_NAME);

		// Parseamos el elemento manifest y dataObjectFormat al tipo ReferenceDataBaseline.
		NodeList dataObjectFormatObjects = newCoSignDoc.getElementsByTagName(IXMLConstants.XADES_PREFIX + ":" + IXMLConstants.ELEMENT_SIGNED_DATA_OBJECT_PROPERTIES);
		if (manifestObjects != null && manifestObjects.getLength() > 0 && dataObjectFormatObjects != null && dataObjectFormatObjects.getLength() > 0) {
		    List<ReferenceDataBaseline> refs = UtilsSignatureOp.fromNodeListToReferenceDataBaselineList(manifestObjects.item(0), dataObjectFormatObjects.item(0));
		    optionalParams.put(SignatureConstants.MF_REFERENCES_PROPERTYNAME, refs);
		} else {
		    String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG258);
		    LOGGER.error(errorMsg);
		    throw new SigningException(errorMsg);
		}
		generateXAdESCoSignature(newCoSignDoc, uriSignAlgorithm, privateKey, signType, optionalParams, signaturePolicyID, includeTimestamp, idClient);

	    }
	    // Si el modo de firma es Detached
	    else {
		newCoSignDoc = eSignDoc;
		// Obtención del ID del nodo que contiene el documento a
		// cofirmar (<CONTENT Id="XX">)
		contentId = UtilsSignatureOp.getSignedElementIdValue(newCoSignDoc);
		generateXAdESCoSignature(newCoSignDoc, uriSignAlgorithm, privateKey, signType, optionalParams, signaturePolicyID, includeTimestamp, idClient);

	    }

	    // Informamos de que hemos generado la firma XAdES Baseline
	    String xmlResult = UtilsXML.transformDOMtoString(newCoSignDoc);
	    byte[ ] result = xmlResult.getBytes(SignatureConstants.UTF8_ENCODING);
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG041));

	    // Escribimos la firma en el Log
	    GenericUtilsCommons.printResult(result, LOGGER);

	    // Devolvemos la co-firma XAdES generada
	    return result;
	} catch (SAXException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (TransformersException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (InvalidCanonicalizerException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG038));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#coSign(byte[], byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] coSign(byte[ ] signature, byte[ ] document, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException {
	return coSign(signature, document, algorithm, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, null);
    }

    /**
     * Method that generates a XAdES B-Level co-signature.
     * @param eSign Parameter that represents the previous signature.
     * @param uriSignAlgorithm Parameter that represents the URI of the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param signType Parameter that represents the signing mode.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * @param optionalParams Set of extra configuration parameters.
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     * @throws InvalidCanonicalizerException If the method fails.
     */
    private void generateXAdESCoSignature(Document eSign, String uriSignAlgorithm, PrivateKeyEntry privateKey, String signType, Properties optionalParams, String signaturePolicyID, boolean includeTimestamp, String idClient) throws SigningException, InvalidCanonicalizerException {
	try {
	    // Instanciamos el objeto encargado de generar la firma XAdES
	    XAdES_EPES xades = generateXAdESElement(privateKey, optionalParams, eSign.getDocumentElement());

	    // Obtenemos el objeto que permite la generación de la firma XAdES
	    XadesExt signBuilder = XadesExt.newInstance(xades, true);

	    // Asociamos el algoritmo de hash a la firma
	    signBuilder.setDigestMethod(digestAlgorithmRef);

	    // Asociamos el algoritmo de canonicalización a la firma
	    signBuilder.setCanonicalizationMethod(defineCanonicalizationMethod(optionalParams));

	    // Creamos el conjunto de referencias
	    List<Reference> references = buildReferences(signBuilder, signType, optionalParams, null, null);

	    // Comprobamos si la firma a realizar debe contener política de
	    // firma
	    boolean includeSignaturePolicy = signaturePolicyID != null;

	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Instanciamos el identificador de la política de firma a usar
	    String policyID = null;
	    if (includeSignaturePolicy) {
		// Buscamos en el archivo con las propiedades asociadas a
		// las
		// políticas de firma si existe la política de firma para el
		// identificador indicado
		if (policyProperties.get(signaturePolicyID + ISignPolicyConstants.KEY_IDENTIFIER_XML) != null) {
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG025, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE, signaturePolicyID }));
		    policyID = signaturePolicyID;
		} else {
		    // Rescatamos del archivo con las propiedades asociadas
		    // a
		    // las políticas de firma el identificador de la
		    // política de
		    // firma
		    // asociada a las firmas XML
		    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

		    // Comprobamos que el identificador de la política de
		    // firma
		    // para
		    // XAdES no sea nulo ni vacío
		    if (!GenericUtilsCommons.assertStringValue(policyID)) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG026, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
			LOGGER.warn(errorMsg);
			includeSignaturePolicy = false;
		    } else {
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG042, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE, policyID }));
		    }
		}
	    }
	    // En caso de que la firma a generar sea XAdES-EPES, comprobamos si
	    // el
	    // algoritmo de firma está soportado por la política de firma,
	    // si el algoritmo de hash está soportado por la política de firma,
	    // si el modo de firma está soportado por la política de firma, y
	    // añadimos a la firma los valores asociados a la política de firma
	    addSignPolicy(includeSignaturePolicy, uriSignAlgorithm, policyID, policyProperties, optionalParams, xades, signType, idClient);

	    // Definimos el Id del nuevo elemento Signature
	    String signatureId = "Signature-" + UUID.randomUUID().toString();

	    X509Certificate signerCertificate = (X509Certificate) privateKey.getCertificate();
	    // Generamos la firma como tal
	    signBuilder.sign(signerCertificate, privateKey.getPrivateKey(), uriSignAlgorithm, references, signatureId, null);

	    // Accedemos al elemento ds:Signature que acabamos de crear
	    Element dsSignature = UtilsSignatureOp.getXMLSignatureById(eSign, signatureId + "-Signature");
	    if (dsSignature == null) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	    // Añadimos el sello de tiempo, en caso de ser necesario
	    addTimestampAndValidateSigningCertificate(includeTimestamp, dsSignature, signerCertificate, idClient);

	    // Comprobamos que la firma generada cumple con las características
	    // de
	    // la política de firma, en caso de incluirla
	    if (includeSignaturePolicy) {
		try {
		    SignaturePolicyManager.validateGeneratedXAdESEPESSignature(dsSignature, policyID, policyProperties, idClient);
		} catch (SignaturePolicyException e) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG034, new Object[ ] { e.getMessage() });
		    LOGGER.error(errorMsg, e);
		    throw new SigningException(errorMsg, e);
		}
	    }

	} catch (org.apache.xml.crypto.MarshalException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (org.apache.xml.crypto.dsig.XMLSignatureException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (GeneralSecurityException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#counterSign(byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] counterSign(byte[ ] signature, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG043));
	try {
	    // Comprobamos que se han indicado la firma a actualizar
	    checkInputSignature(signature);

	    // Comprobamos que se ha indicado el algoritmo de firma y tiene un
	    // valor admitido
	    checkInputSignatureAlgorithm(algorithm);

	    // Comprobamos que se ha indicado la clave privada
	    checkInputPrivateKey(privateKey);

	    // Comprobamos que se han indicado los parámetros adicionales, y al
	    // menos, los que son necesarios para construir el elemento
	    // xades:DataObjectFormat
	    checkInputExtraParams(extraParams);

	    // Comprobamos que se ha indicado el tipo de firma a generar
	    checkInputSignatureForm(signatureForm);

	    // Obtenemos la URI del algoritmo de firma
	    String uriSignAlgorithm = SIGN_ALGORITHM_URI.get(algorithm);

	    // Obtenemos el algoritmo de hash a partir del algoritmo de firma
	    digestAlgorithmRef = SignatureConstants.DIGEST_METHOD_ALGORITHMS_XADES.get(algorithm);

	    // Obtenemos el objeto Document a partir del array de bytes de la
	    // firma XAdES previa
	    Document signDocument = UtilsSignatureCommons.getDocumentFromXML(signature);

	    // Obtenemos del modo de firma (Enveloping, Enveloped o Detached) de
	    // la firma XAdES previa
	    String signType = UtilsSignatureOp.getTypeOfXMLSignature(signDocument);

	    checkInputSignatureFormatCounter(signType);

	    // Definimos una variable para determinar si la firma es enveloping
	    // o no
	    boolean isEnvelopingSign = false;

	    // Accedemos al elemento raíz de la firma
	    Element rootElement = signDocument.getDocumentElement();

	    // Si el elemento raíz es ds:Signature entonces la firma es
	    // enveloping
	    if (IXMLConstants.DS_SIGNATURE_NODE_NAME.equals(rootElement.getNodeName())) {
		isEnvelopingSign = true;
		// Insertamos el noto con el documento firmado
		signDocument = UtilsSignatureOp.insertAfirmaRootNode(signDocument, dBFactory);

		// Actualizamos el valor del elemento raíz de la firma
		rootElement = signDocument.getDocumentElement();
	    }
	    // Generamos las contrafirmas
	    generateXAdESCounterSignature(rootElement, privateKey, extraParams, signatureForm, signaturePolicyID, uriSignAlgorithm, includeTimestamp, idClient);

	    // Si el documento recibido no estaba cofirmado se elimina el nodo
	    // raiz temporal AFIRMA
	    // y se vuelve a dejar como raiz el nodo Signature original
	    if (isEnvelopingSign) {
		Document newdoc = dBFactory.newDocumentBuilder().newDocument();
		newdoc.appendChild(newdoc.adoptNode(signDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE).item(0)));
		signDocument = newdoc;
	    }

	    // Informamos de que hemos generado la firma XAdES Baseline
	    String xmlResult = UtilsXML.transformDOMtoString(signDocument);
	    byte[ ] result = xmlResult.getBytes(SignatureConstants.UTF8_ENCODING);
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG045));

	    // Escribimos la firma en el Log
	    GenericUtilsCommons.printResult(result, LOGGER);

	    // Devolvemos la co-firma XAdES generada
	    return result;

	} catch (GeneralSecurityException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (MarshalException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (XMLSignatureException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (TransformersException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (UnsupportedEncodingException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} catch (InvalidCanonicalizerException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG044));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#counterSign(byte[], java.lang.String, java.security.KeyStore.PrivateKeyEntry, java.util.Properties, boolean, java.lang.String, java.lang.String)
     */
    @Override
    public byte[ ] counterSign(byte[ ] signature, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException {
	return counterSign(signature, algorithm, privateKey, extraParams, includeTimestamp, signatureForm, signaturePolicyID, null);
    }

    /**
     * Method that generates a XAdES Baseline counter-signature for each leaf signature.
     * @param rootElement Parameter that represents the root element of the XML document.
     * @param privateKey  Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters.
     * @param signType Parameter that represents the signing mode.
     * The allowed values are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param uriSignAlgorithm Parameter that represents the URI of the signature algorithm.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     * @throws GeneralSecurityException If the method fails.
     * @throws MarshalException If the method fails.
     * @throws XMLSignatureException If the method fails.
     * @throws InvalidCanonicalizerException If the method fails.
     */
    private void generateXAdESCounterSignature(Element rootElement, PrivateKeyEntry privateKey, Properties extraParams, String signType, String signaturePolicyID, String uriSignAlgorithm, boolean includeTimestamp, String idClient) throws SigningException, GeneralSecurityException, MarshalException, XMLSignatureException, InvalidCanonicalizerException {
	// Comprobamos si la firma a realizar debe incluir política de firma
	boolean mustIncludeSignaturePolicy = signaturePolicyID != null;

	// Accedemos al archivo con las propiedades asociadas a las
	// políticas de firma
	Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	// Instanciamos el identificador de la política de firma a usar
	String policyID = null;
	if (mustIncludeSignaturePolicy) {
	    // Buscamos en el archivo con las propiedades asociadas a las
	    // políticas de firma si existe la política de firma para el
	    // identificador indicado
	    if (policyProperties.get(signaturePolicyID + ISignPolicyConstants.KEY_IDENTIFIER_XML) != null) {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG025, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE, signaturePolicyID }));
		policyID = signaturePolicyID;
	    } else {
		// Rescatamos del archivo con las propiedades asociadas a
		// las políticas de firma el identificador de la política de
		// firma
		// asociada a las firmas XML
		policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

		// Comprobamos que el identificador de la política de firma
		// para
		// XAdES no sea nulo ni vacío
		if (!GenericUtilsCommons.assertStringValue(policyID)) {
		    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG026, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		    LOGGER.warn(errorMsg);
		    mustIncludeSignaturePolicy = false;
		} else {
		    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG042, new Object[ ] { signaturePolicyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE, policyID }));
		}
	    }
	}

	// Instanciamos una lista donde ubicar los elementos que no contengan
	// contrafirmas o subnodos de firma y que además no sean sellos de
	// tiempo
	List<Element> listSignaturesToCounterSign = UtilsSignatureOp.getListSignaturesToCounterSign(rootElement);

	// Recorremos la lista de elementos que contrafirmar
	for (Element signElement: listSignaturesToCounterSign) {
	    // Accedemos al elemento xades:QualifyingProperties
	    Element qualifyingProperties = UtilsSignatureOp.retrieveNode(signElement, IXMLConstants.ELEMENT_QUALIFIYING_PROPERTIES, IXMLConstants.XADES_1_3_2_NAMESPACE, true);

	    // Accedemos al elemento xades:UnsignedProperties
	    Element unsignedProperties = UtilsSignatureOp.retrieveNode(qualifyingProperties, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES, IXMLConstants.XADES_1_3_2_NAMESPACE, false);
	    // Si no exixste el elemento xades:UnsignedProperties lo creamos
	    if (unsignedProperties == null) {
		unsignedProperties = qualifyingProperties.getOwnerDocument().createElementNS(DSSConstants.SignTypesURIs.XADES_V_1_3_2, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
		unsignedProperties.setPrefix(IXMLConstants.XADES_PREFIX);
		qualifyingProperties.appendChild(unsignedProperties);
	    }

	    // Accedemos al elemento xades:UnsignedSignatureProperties
	    Element unsignedSignatureProperties = UtilsSignatureOp.retrieveNode(unsignedProperties, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES, IXMLConstants.XADES_1_3_2_NAMESPACE, false);
	    // Si no exixste el elemento xades:UnsignedSignatureProperties lo
	    // creamos
	    if (unsignedSignatureProperties == null) {
		unsignedSignatureProperties = unsignedProperties.getOwnerDocument().createElementNS(DSSConstants.SignTypesURIs.XADES_V_1_3_2, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
		unsignedSignatureProperties.setPrefix(IXMLConstants.XADES_PREFIX);
		unsignedProperties.appendChild(unsignedSignatureProperties);
	    }

	    // Obtenemos el elemento SignatureValue (para calcular el hash y
	    // referenciarlo)
	    Element signatureValue = UtilsSignatureOp.retrieveNode(signElement, IXMLConstants.ELEMENT_SIGNATURE_VALUE, XMLSignature.XMLNS, true);

	    // Registramos el atributo Id del nodo referenciado
	    IdRegister.registerAttrId(signatureValue);
	    String idSignValue = signatureValue.getAttribute(IXMLConstants.ATTRIBUTE_ID);

	    // Creamos la referencia
	    List<Transform> transformList = Collections.singletonList(xmlSignatureFactory.newTransform(CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec) null));
	    String referenceId = "Reference-" + UUID.randomUUID().toString();
	    Reference reference = xmlSignatureFactory.newReference("#" + idSignValue, getDigestMethod(), transformList, IXMLConstants.COUNTER_SIGN_URI, referenceId);

	    // Creamos el elemento xades:CounterSignature
	    Element counterSignature = signElement.getOwnerDocument().createElementNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COUNTER_SIGNATURE);
	    counterSignature.setPrefix(IXMLConstants.XADES_PREFIX);

	    // Añadimos el elemento xades:CounterSignature como hijo de
	    // xades:UnsignedSignatureProperties
	    unsignedSignatureProperties.appendChild(counterSignature);

	    // Inicializamos los parámetros extra en caso de no haberse indicado
	    Properties optionalParams = checkInputExtraParams(extraParams);

	    // Generamos el objeto que representará la contra-firma
	    XAdES_EPES xades = generateXAdESElement(privateKey, optionalParams, counterSignature);

	    // Añadimos la referencia al objeto a firmar en el elemento
	    // xades:DataObjectFormat del nuevo elemento xades:CounterSignature
	    ((DataObjectFormatImpl) dataObjectFormat).setObjectReference("#" + referenceId);
	    ((DataObjectFormatImpl) dataObjectFormat).setDescription(SignatureConstants.XADES_DATA_FORMAT_DESCRIPTION_PROP_DEFAULT);
	    ((DataObjectFormatImpl) dataObjectFormat).setMimeType(SignatureConstants.XADES_DATA_FORMAT_MIME_PROP_DEFAULT);

	    // Obtenemos el objeto que permite la generación de la firma
	    // XAdES
	    final XadesExt signBuilder = XadesExt.newInstance(xades, true);

	    // Asociamos el algoritmo de hash a la firma
	    signBuilder.setDigestMethod(digestAlgorithmRef);

	    // Asociamos el algoritmo de canonicalización a la firma
	    signBuilder.setCanonicalizationMethod(defineCanonicalizationMethod(optionalParams));

	    // En caso de que la firma a generar deba contener política de
	    // firma, comprobamos si
	    // el
	    // algoritmo de firma está soportado por la política de firma,
	    // si el algoritmo de hash está soportado por la política de firma,
	    // si el modo de firma está soportado por la política de firma, y
	    // añadimos a la firma los valores asociados a la política de firma
	    addSignPolicy(mustIncludeSignaturePolicy, uriSignAlgorithm, policyID, policyProperties, optionalParams, xades, signType, idClient);

	    // Definimos el Id de la firma
	    String signatureId = "Signature-" + UUID.randomUUID().toString();

	    X509Certificate signerCertificate = (X509Certificate) privateKey.getCertificate();
	    // Generamos la firma como tal
	    signBuilder.sign(signerCertificate, privateKey.getPrivateKey(), uriSignAlgorithm, Collections.singletonList(reference), signatureId, null);

	    // Accedemos al elemento ds:Signature que acabamos de crear,
	    // añadimos el sello de tiempo, en caso de ser necesario y
	    // comprobamos que la firma generada cumple con las
	    // características de
	    // la política de firma, en el caso de incluirla
	    addTimestampAndValidatePolicyOfCreatedCounterSignature(rootElement, signatureId, includeTimestamp, mustIncludeSignaturePolicy, policyID, policyProperties, signerCertificate, idClient);
	}
    }

    /**
     * Method that adds a timestamp to a counter-signature if is required, and validates the signature against the associated signature policy, if is
     * required.
     * @param rootElement Parameter that represents the root element of the XML signature.
     * @param signatureId Parameter that represents the Id of the counter-signature.
     * @param includeTimestamp Parameter that indicates if the signature will have a timestamp (true) or not (false).
     * @param includeSignaturePolicy Parameter that indicates if the counter-signature contains signature policy (true) or not (false).
     * @param policyID Parameter that represents the identifier of the associated signature policy.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param signerCertificate Parameter that represents the signing certificate.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     */
    private void addTimestampAndValidatePolicyOfCreatedCounterSignature(Element rootElement, String signatureId, boolean includeTimestamp, boolean includeSignaturePolicy, String policyID, Properties policyProperties, X509Certificate signerCertificate, String idClient) throws SigningException {
	// Accedemos al elemento ds:Signature que acabamos de crear
	Element dsSignature = UtilsSignatureOp.getXMLSignatureById(rootElement.getOwnerDocument(), signatureId + "-Signature");
	if (dsSignature == null) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG031);
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}

	// Añadimos el sello de tiempo, en caso de ser necesario
	addTimestampAndValidateSigningCertificate(includeTimestamp, dsSignature, signerCertificate, idClient);

	// Comprobamos que la firma generada cumple con las características
	// de
	// la política de firma, en caso de incluirla
	if (includeSignaturePolicy) {
	    try {
		SignaturePolicyManager.validateGeneratedXAdESEPESSignature(dsSignature, policyID, policyProperties, idClient);
	    } catch (SignaturePolicyException e) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.XBS_LOG034, new Object[ ] { e.getMessage() });
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#upgrade(byte[], java.util.List, java.lang.String)
     */
    @Override
    public byte[ ] upgrade(byte[ ] signature, List<X509Certificate> listSignersToUpdate, String idClient) throws SigningException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG046));
	try {
	    // Comprobamos que se han indicado la firma a actualizar
	    checkInputSignature(signature);

	    // Obtenemos el documento XML firmado
	    Document doc = UtilsSignatureCommons.getDocumentFromXML(signature);

	    // Registramos los atributos de tipo ID
	    IdRegister.registerElements(doc.getDocumentElement());

	    // Obtenemos la lista de firmantes
	    List<XAdESSignerInfo> listSigners = UtilsSignatureOp.getXAdESListSigners(doc);

	    // Actualizamos los firmantes
	    processListSignersToUpdate(listSigners, listSignersToUpdate, idClient);
	    try {
		// Informamos de que hemos generado la firma XAdES Baseline
		String xmlResult = UtilsXML.transformDOMtoString(doc);
		byte[ ] result = xmlResult.getBytes(SignatureConstants.UTF8_ENCODING);

		// Escribimos la firma en el Log
		GenericUtilsCommons.printResult(result, LOGGER);

		// Devolvemos la firma XAdES generada
		return result;
	    } catch (Exception e) {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG017);
		LOGGER.error(errorMsg, e);
		throw new SigningException(errorMsg, e);
	    }

	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG047));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#upgrade(byte[], java.util.List)
     */
    @Override
    public byte[ ] upgrade(byte[ ] signature, List<X509Certificate> listSignersToUpdate) throws SigningException {
	return upgrade(signature, listSignersToUpdate, null);
    }

    /**
     * Method that validates the signers of a XAdES signature.
     * @param xmlDocument Parameter that represents the XAdES signature.
     * @return an object that contains the information about the validation result.
     */
    public ValidationResult verifySignature(byte[ ] xmlDocument) {
	return verifySignature(xmlDocument, null);
    }

    /**
     * Method that updates the signers of a XML signature adding a timestamp to the signature.
     * @param listSigners Parameter that represents the signers list of the XML signature.
     * @param listSignersToUpdate Parameter that represents the list of certificates of the signers to update.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     */
    private void processListSignersToUpdate(List<XAdESSignerInfo> listSigners, List<X509Certificate> listSignersToUpdate, String idClient) throws SigningException {
	// Comprobamos si es necesario actualizar todos los firmantes o sólo los
	// indicados
	boolean updateAllSigners = listSignersToUpdate == null || listSignersToUpdate.size() == 0;

	// Recorremos la lista de firmantes
	for (XAdESSignerInfo signerInfo: listSigners) {
	    // Comprobamos que no se ha producido ningún error recuperando el
	    // firmante
	    if (signerInfo.getErrorMsg() != null) {
		throw new SigningException(signerInfo.getErrorMsg());
	    }

	    // En caso de que no se haya indicado firmante que actualizar se
	    // actualizarán todos
	    boolean updateThisSigner = updateAllSigners;

	    // Determinamos si tenemos que actualizar este firmante
	    if (!updateThisSigner) {
		// Tratamos de acceder al certificado firmante
		X509Certificate signingCertificate = signerInfo.getSigningCertificate();
		if (signingCertificate != null) {
		    // Determinamos si tenemos que actualizar este firmante
		    boolean enc = false;
		    int i = 0;
		    while (!enc && i < listSignersToUpdate.size()) {
			if (UtilsCertificateCommons.equals(signingCertificate, listSignersToUpdate.get(i))) {
			    enc = true;
			}
			i++;
		    }
		    if (enc) {
			updateThisSigner = true;
		    }
		}
	    }
	    // Actualizaremos el firmante sólo si no posee un sello de
	    // tiempo previo
	    updateSigner(updateThisSigner, signerInfo, idClient);

	    // Procesamos los contra-firmantes que tuviera
	    if (signerInfo.getListCounterSigners() != null) {
		processListSignersToUpdate(signerInfo.getListCounterSigners(), listSignersToUpdate, idClient);
	    }
	}
    }

    /**
     * Method that updates a signature with a timestamp if the signature hasn't already a timestamp.
     * @param updateThisSigner Parameter that indicates whether to update the signer (true) or not (false).
     * @param signerInfo Parameter that represents the principal information related to the signer of the XAdES signature.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails.
     */
    private void updateSigner(boolean updateThisSigner, XAdESSignerInfo signerInfo, String idClient) throws SigningException {
	// Actualizaremos el firmante sólo si no posee un sello de
	// tiempo previo
	// CHECKSTYLE:OFF Boolean complexity needed
	if (updateThisSigner && signerInfo.getListTimeStamps() == null && !signerInfo.isHasArchiveTimeStampElement() && signerInfo.getSigningCertificate() != null) {
	    // CHECKSTYLE:ON
	    // Añadimos el sello de tiempo
	    addTimestampAndValidateSigningCertificate(true, signerInfo.getElementSignature(), signerInfo.getSigningCertificate(), idClient);
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.signature.Signer#getSignedData(byte[])
     */
    @Override
    public OriginalSignedData getSignedData(byte[ ] data) throws SigningException {
	throw new SigningException(Language.getResIntegra(ILogConstantKeys.XBS_LOG051));
    }

    /**
     * Method that generates the XML document where to locate the ASIC-S signature.
     * @return an object that represents the XML document.
     * @throws SigningException If the method fails.
     */
    private Document createXMLDocument() throws SigningException {
	try {
	    // Crea el nuevo documento org.w3c.dom.Document xml que contendrá la
	    // firma
	    Document docSignature = dBFactory.newDocumentBuilder().newDocument();

	    docSignature.appendChild(docSignature.createElementNS(IXMLConstants.ASIC_NS, IXMLConstants.ASIC_NS_PREFIX + ":" + IXMLConstants.ELEMENT_XADES_SIGNATURE));

	    return docSignature;
	} catch (ParserConfigurationException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG014);
	    LOGGER.error(errorMsg, e);
	    throw new SigningException(errorMsg, e);
	}
    }

    /**
     * Method that indicates if a signer has Baseline form.
     * @param signerFormat Parameter that represents the format associated to the signer.
     * @return a boolean that indicates if a signer has Baseline form.
     */
    private boolean signerIsBaseline(String signerFormat) {
	return signerFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL) || signerFormat.equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL) || signerFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LT_LEVEL) || signerFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LTA_LEVEL);
    }

    /**
     * Method that validates a signed XML document.
     * @param xmlDocument Parameter that represents the signed XML document.
     * @param idClient Parameter that represents the client application identifier.
     * @return an object that contains information about the validation of the signed XML document, including all the signers and counter-signers contained inside it.
     */
    public ValidationResult verifySignature(byte[ ] xmlDocument, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG016));

	// Instanciamos el objeto a devolver
	ValidationResult validationResult = new ValidationResult();

	// Por defecto indicamos que la validación de la firma ha sido correcta
	validationResult.setCorrect(true);
	try {
	    // Comprobamos que se ha indicado el documento XML firmado a validar
	    GenericUtilsCommons.checkInputParameterIsNotNull(xmlDocument, Language.getResIntegra(ILogConstantKeys.XBS_LOG053));

	    // Definimos un objeto donde ubicar la lista de firmantes y
	    // contra-firmantes contenidos en la firma
	    List<XAdESSignerInfo> listSigners = new ArrayList<XAdESSignerInfo>();

	    /*
	     * Validación de la Integridad: Se comprobará que el documento XML posee al menos una firma, y que los datos firmados incluídos
	     * en la misma son acordes respecto al modo en que se ha realizado la firma (detached, enveloped, o enveloping).
	     */
	    String signingMode = checkSigantureIntegrity(xmlDocument, validationResult, listSigners);

	    // Instanciamos una lista donde ubicar la información de validación
	    // de cada firmante y la asociamos al resultado final
	    List<SignerValidationResult> listSignersValidationResults = new ArrayList<SignerValidationResult>();
	    validationResult.setListSignersValidationResults(listSignersValidationResults);

	    // inicializamos la fecha que determinará la caducidad de la firma.
	    Date currentDate = null;

	    // Recorremos la lista de firmantes
	    for (XAdESSignerInfo signerInfo: listSigners) {
		// Primero, determinamos el formato del firmante
		String signerFormat = SignatureFormatDetectorXades.resolveSignerXAdESFormat(signerInfo.getElementSignature());

		// Si el firmante tiene formato Baseline, nos mantenemos en
		// este clase. En otro caso, derivamos la validación del
		// firmante a la clase asociada a firmas no Baseline
		SignerValidationResult signerValidationResult = null;
		if (!signerIsBaseline(signerFormat)) {
		    XadesSigner xadesSigner = new XadesSigner();

		    // Obtenemos la información de validación asociada al
		    // contra-firmante
		    signerValidationResult = xadesSigner.validateSigner(signingMode, signerInfo, validationResult, idClient, signerFormat, false);
		} else {
		    // Obtenemos la información de validación asociada al
		    // contra-firmante
		    signerValidationResult = validateSigner(signingMode, signerInfo, validationResult, idClient, signerFormat, false, null, null);
		}

		// Añadimos los datos de validación del firmante a la lista
		// asociada.
		listSignersValidationResults.add(signerValidationResult);

		// Validamos los contra-firmantes asociados al firmante
		validateCounterSigners(signingMode, signerInfo, signerValidationResult, validationResult, idClient, null, null);

		// Recuperamos la fecha de expiración de los archiveTimestamp.
		X509Certificate archiveTstClosestCert = UtilsSignatureOp.obtainCertificateArchiveTimestampsXAdES(signerInfo);
		signerValidationResult.setLastArchiveTst(archiveTstClosestCert);

		// Obtenemos la fecha de caducidad de la firma.
		currentDate = UtilsSignatureOp.calculateExpirationDateForValidations(signerValidationResult, currentDate);
	    }
	    validationResult.setExpirationDate(currentDate);

	    // Indicamos en el log que la firma es correcta
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG055));
	} catch (SigningException e) {
	    // Establecemos en la información asociada a la validación de la
	    // firma que ésta no es correcta
	    validationResult.setCorrect(false);

	    // Indicamos en el log que la firma no es correcta
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG054));
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.XBS_LOG032));
	}
	// Devolvemos el objeto con la información de validación
	return validationResult;
    }

    /**
     * Method that checks:
     * <ul>
     * <li>If the signed data is included according to the signing mode.</li>
     * <li>The signature contains at least one signer.</li>
     * </ul>
     * @param xmlDocument Parameter that represents the signed XML document.
     * @param validationResult Parameter that contains the information related to the validation of the signed XML document.
     * @param listSigners Parameter that represents the list to update with the signers and counter-signers contained inside of the XML document.
     * @return the signing mode of the signed XML document. The possible values are:
     * <ul>
     * <li>{@link IUtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @throws SigningException If the validation fails.
     */
    private String checkSigantureIntegrity(byte[ ] xmlDocument, ValidationResult validationResult, List<XAdESSignerInfo> listSigners) throws SigningException {
	// Establecemos, por defecto, que la firma es estructuralmente correcta
	validationResult.setIntegrallyCorrect(true);

	// Instanciamos un objeto que representará el documento XML firmado
	Document doc = null;

	// Por defecto indicamos que el modo de firma es detached
	String signingMode = IUtilsSignature.DETACHED_SIGNATURE_MODE;
	try {
	    // Accedemos al documento XML firmado
	    doc = UtilsSignatureCommons.getDocumentFromXML(xmlDocument);

	    // Registramos los atributos de tipo ID del documento XML
	    IdRegister.registerElements(doc.getDocumentElement());

	    // Obtenemos el modo de firma
	    String signType = UtilsSignatureOp.getTypeOfXMLSignature(doc);
	    if (signType.equals(SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED)) {
		signingMode = IUtilsSignature.ENVELOPED_SIGNATURE_MODE;
	    } else if (signType.equals(SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING)) {
		signingMode = IUtilsSignature.ENVELOPING_SIGNATURE_MODE;
	    }
	} catch (SigningException e) {
	    LOGGER.error(e.getMessage());
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(e.getMessage());
	    throw new SigningException(e);
	}

	// Obtenemos la lista de firmantes
	List<XAdESSignerInfo> listSignersFound = UtilsSignatureOp.getXAdESListSigners(doc);

	// Comprobamos que exista al menos un firmante
	if (listSignersFound.isEmpty()) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.XBS_LOG018);
	    LOGGER.error(errorMsg);
	    validationResult.setIntegrallyCorrect(false);
	    validationResult.setErrorMsg(errorMsg);
	    throw new SigningException(errorMsg);
	}
	listSigners.addAll(listSignersFound);

	// Devolvemos el modo de firma
	return signingMode;
    }

    /**
     * Method that validates a signer/counter-signer of a XML signature.
     * @param signingMode Parameter that represents the signing mode of the signed XML document. The possible values are:
     * <ul>
     * <li>{@link IUtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @param signerInfo Parameter that represents the information about the signer.
     * @param validationResult Parameter that represents the information about the validation of the signed XML document.
     * @param idClient Parameter that represents the client application identifier.
     * @param signerFormat Parameter that represents the format associated to the signer/counter-signer.
     * @param isCounterSignature Parameter that indicates if the element to validate is a signer (false) or a counter-signer (true).
     * @param signedFile Parameter that represents the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signedFileName Parameter that represents the name of the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @return an object that represents the validation information about the signer/counter-signer.
     */
    public SignerValidationResult validateSigner(String signingMode, XAdESSignerInfo signerInfo, ValidationResult validationResult, String idClient, String signerFormat, boolean isCounterSignature, byte[ ] signedFile, String signedFileName) {
	// Instanciamos el objeto que representa la información de
	// validación del firmante y lo añadimos a la lista asociada
	SignerValidationResult signerValidationResult = new SignerValidationResult();

	// Por defecto indicamos que la validación del firmante ha sido correcta
	signerValidationResult.setCorrect(true);

	// Instanciamos una lista donde ubicar la información asociada
	// de las validaciones aplicadas sobre el firmante
	signerValidationResult.setListValidations(new ArrayList<ValidationInfo>());

	// Añadimos en la información de validación del firmante su formato
	signerValidationResult.setFormat(signerFormat);

	// Determinamos a partir del formato si el firmante es Baseline
	boolean isBaseline = SignatureFormatDetectorXades.isXAdESBaseline(signerFormat);

	try {
	    // Recuperamos el elemento obligatorio xades:SignedProperties
	    Element signedPropertiesElement = retrieveSignedPropertiesElement(signerValidationResult, signerInfo, validationResult);

	    // Recuperamos el elemento obligatorio
	    // xades:SignedSignatureProperties
	    Element signedSignaturePropertiesElement = retrieveSignedSignaturePropertiesElement(signedPropertiesElement, signerValidationResult, signerInfo, validationResult);

	    // Recuperamos el certificado firmante y lo asociamos a la
	    // información del firmante
	    signerInfo.setSigningCertificate(UtilsSignatureOp.retrieveSigningCertificateOfXMLSigner(signedSignaturePropertiesElement, signerInfo.getId(), signerInfo.getElementSignature()));

	    // Validación de la Información de Clave Pública: Se comprobará que
	    // el elemento firmado xades:SigningCertificate se corresponde con
	    // el certificado firmante. Además, se comprobará que existe una
	    // referencia al elemento ds:KeyInfo, si el firmante no tiene
	    // formato Baseline
	    validateKeyInfo(signerValidationResult, signerInfo, validationResult, isBaseline, isCounterSignature);

	    // Añadimos a la información de validación del firmante los
	    // datos de su
	    // certificado
	    addSigningCertificateInfo(signerValidationResult, signerInfo, validationResult);

	    // Obtenemos la fecha de validación que será la fecha de
	    // generación del primer sello de tiempo contenido en un
	    // elemento xades:SignatureTimeStamp. En caso de no
	    // haber ninguno se tomará la fecha actual
	    Date validationDate = getValidationDate(signerInfo);

	    /*
	     * Validación del Núcleo de Firma: Se realizarán las siguientes verificaciones (en el caso de que la firma no sea Baseline):
	     * > Se comprobará que la versión de XAdES es 1.3.2 o superior.
	     * > Se comprobará que el elemento xades:QualifyingProperties está presente y se encuentra correctamente formado.
	     * > Se comprobará que el elemento xades:SignedSignatureProperties tiene una estructura correcta.
	     * > Se comprobará que existe una referencia que apunta al elemento xades:SignedProperties.
	     * > Se comprobará que el firmante verifica la firma.
	     *
	     * Mientras que en el caso de que la firma sea Baseline:
	     * > Se comprobará que la versión de XAdES es 1.3.2 o superior.
	     * > Se comprobará que el firmante verifica la firma.
	     * > Se verificará que el elemento xades:QualifyingProperties está presente y se encuentra correctamente formado.
	     * > Se comprobará que el elemento xades:SignedSignatureProperties tiene una estructura correcta.
	     * > Se verificará que se incluye, al menos, un elemento xades:DataObjectFormat, y por cada uno de ellos, que está correctamente formado y que tiene asociada una
	     *   referencia que no apunta hacia el elemento xades:SignedProperties.
	     * > Se comprobará que existe una referencia que apunta al elemento xades:SignedProperties.
	     */
	    validateSignatureCore(signerValidationResult, signerInfo, validationResult, signedSignaturePropertiesElement, signedPropertiesElement, isBaseline, signedFile, signedFileName, isCounterSignature);

	    // Validación del Instante de Firma: Si se incluye el elemento
	    // firmado xades:SigningTime se comprobará que está correctamente
	    // formado y que contiene una fecha anterior a la fecha de
	    // validación.
	    validateSigningTime(signerValidationResult, signerInfo, validationResult, validationDate, signedSignaturePropertiesElement, isBaseline);

	    // Validación de la Política de Firma: Si se incluye el elemento
	    // firmado xades:SignaturePolicyIdentifier se comprobará si el
	    // identificador (URN o URI) de la política de firma definida en
	    // dicho elemento coincide con el identificador de la política de
	    // firma definida para firmas XML en el fichero policy.properties,
	    // en cuyo caso, se comprobará que los datos de la firma y del
	    // firmante concreto son válidos respecto a las propiedades
	    // definidas en dicho fichero.
	    validateSignaturePolicy(signerValidationResult, signerInfo, validationResult, signingMode, idClient);

	    // Validación del Certificado Firmante: Se comprobará el estado del
	    // certificado firmante respecto al método de validación definido
	    // para el mismo, ya sea en el fichero integraFacade.properties (si
	    // la validación se realiza desde la fachada de firma), o bien en el
	    // fichero signer.properties (si la validación se realiza desde la
	    // interfaz Signer).
	    validateSigningCertificate(signerValidationResult, signerInfo, validationResult, idClient, validationDate);

	    /*
	     * Validación de los Elementos xades:SignatureTimeStamp: Si el firmante posee elementos xades:SignatureTimeStamp se comprobará que todos ellos poseen una
	     * estructura correcta y que los sellos de tiempo que contienen están bien formados. Respecto a cada sello de tiempo se definen las siguientes tareas de validación:
	     * 		> Validación de la Firma del Sello de Tiempo: Se comprobará que la firma del sello de tiempo es correcta.
	     * 		> Validación de la Integridad del Sello de Tiempo: Se comprobará que los datos sellados son correctos.
	     * 		> Validación del Certificado Firmante del Sello de Tiempo: Se comprobará el estado del certificado firmante del sello de tiempo respecto a la fecha de
	     * 		generación del siguiente sello de tiempo, utilizando el método de validación definido para los certificados firmantes, ya sea en el fichero
	     * 		integraFacade.properties (si la validación se realiza desde la fachada de firma), o bien en el fichero signer.properties (si la validación
	     * 		se realiza desde la interfaz Signer). Cuando se esté procesando el certificado firmante del sello de tiempo más reciente (y por lo tanto el último)
	     * 		se utilizará como fecha de validación la fecha actual. Además, se verificará que el certificado posee la extensión id-kp-timestamp.
	     */
	    validateSignatureTimeStampElements(signerValidationResult, signerInfo, validationResult, idClient);
	} catch (Exception e) {
	    // Establecemos en la información asociada a la validación
	    // del firmante que éste no es correcto
	    signerValidationResult.setCorrect(false);

	    // Establecemos en la información asociada a la validación
	    // de la firma que ésta no es correcta
	    validationResult.setCorrect(false);
	}
	return signerValidationResult;
    }

    /**
     * Method that validates the signing certificate of a signer/counter-signer.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException If the validation fails.
     */
    private void validateSigningCertificate(SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult, String idClient, Date validationDate) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNING_CERTIFICATE_VALIDATION);

	// Añadimos a la lista de validaciones del firmante/contra-firmante la
	// información asociada a esta validación
	signerValidationResult.getListValidations().add(validationInfo);
	try {
	    // Validamos el certificado del firmante
	    UtilsSignatureOp.validateCertificate(signerInfo.getSigningCertificate(), validationDate, false, idClient, false);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la
	    // validación
	    // de la
	    // firma XAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a
	    // cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates a XAdES signature by the signature policy defined on the properties file where to configure the validation and generation of signatures
     * with signature policies.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param signingMode Parameter that represents the signing mode of the signed XML document. The possible values are:
     * <ul>
     * <li>{@link IUtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateSignaturePolicy(SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult, String signingMode, String idClient) throws SigningException {
	// Comprobamos si el firmante incluye política de firma
	if (SignatureFormatDetectorXades.hasSignaturePolicyIdentifier(signerInfo.getElementSignature())) {
	    // Instanciamos el objeto que ofrece información sobre la validación
	    // llevada a cabo
	    ValidationInfo validationInfo = new ValidationInfo();
	    validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_POLICY_VALIDATION);

	    // Añadimos a la lista de validaciones del firmante/contra-firmante
	    // la
	    // información asociada a esta validación
	    signerValidationResult.getListValidations().add(validationInfo);

	    try {
		// Validamos la política de firma asociada al firmante
		SignaturePolicyManager.validateXAdESEPESSignature(signerInfo.getElementSignature(), null, signingMode, idClient);

		// Indicamos que la validación ha sido correcta
		validationInfo.setSucess(true);
	    } catch (SignaturePolicyException e) {
		// Establecemos, a nivel general, el error asociado a la
		// validación
		// de la
		// firma XAdES como el error producido, si es que no se indicó
		// previamente
		if (validationResult.getErrorMsg() == null) {
		    validationResult.setErrorMsg(e.getMessage());
		}

		// Establecemos, a nivel de firmante, el error asociado a la
		// validación como el error producido, si es que no se indicó
		// previamente
		if (signerValidationResult.getErrorMsg() == null) {
		    signerValidationResult.setErrorMsg(e.getMessage());
		}

		// Indicamos en la información sobre la validación llevada a
		// cabo
		// que no ha sido correcta
		validationInfo.setSucess(false);
		validationInfo.setErrorMsg(e.getMessage());

		throw new SigningException(e);
	    }
	}
    }

    /**
     * Method that validates if the signing time of a XML signature is previous than certain date.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param validationDate Parameter that represents the validation date.
     * @param signedSignaturePropertiesElement Parameter that represents the <code>xades:SignedSignatureProperties</code> element.
     * @param isBaseline Parameter that indicates if the XML signature has Baseline form (true) or not (false).
     * @throws SigningException If the validation fails.
     */
    private void validateSigningTime(SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult, Date validationDate, Element signedSignaturePropertiesElement, boolean isBaseline) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNING_TIME_VALIDATION);

	// Añadimos a la lista de validaciones del firmante/contra-firmante la
	// información asociada a esta validación
	signerValidationResult.getListValidations().add(validationInfo);

	// El atributo signing-time no es obligatorio
	// en la firma, salvo que ésta tenga formato Baseline
	boolean signingTimeIsRequired = isBaseline;
	try {
	    // Comprobamos que el atributo signing-time, en caso de estar
	    // presente, es correcto
	    UtilsSignatureOp.validateXAdESSigningTime(signedSignaturePropertiesElement, signingTimeIsRequired, signerInfo.getId(), validationDate);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la validación
	    // de la
	    // firma XAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that checks if a signer/counter-signer verifies the signature.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param signedSignaturePropertiesElement Parameter that represents <code>xades:SignedSignatureProperties</code> element.
     * @param signedPropertiesElement Parameter that represents <code>xades:SignedProperties</code> element.
     * @param isBaseline Parameter that indicates if the XML signature has Baseline form (true) or not (false).
     * @param signedFile Parameter that represents the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signedFileName Parameter that represents the name of the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param isCounterSignature Parameter that indicates if the signature to validate is a counterSignature.
     * @throws SigningException If the validation fails.
     */
    private void validateSignatureCore(SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult, Element signedSignaturePropertiesElement, Element signedPropertiesElement, boolean isBaseline, byte[ ] signedFile, String signedFileName, boolean isCounterSignature) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_CORE_VALIDATION);

	// Añadimos a la lista de validaciones del firmante/contra-firmante la
	// información asociada a esta validación
	signerValidationResult.getListValidations().add(validationInfo);
	try {
	    // Comprobamos que el firmante verifica la firma
	    UtilsSignatureOp.validateXAdESSignatureCore(signerInfo.getQualifyingPropertiesElement(), signerInfo.getId(), signerInfo.getElementSignature(), signerInfo.getSignature(), signedFile, signedFileName, signerInfo.getSigningCertificate(), signedSignaturePropertiesElement, signedPropertiesElement, isBaseline, isCounterSignature);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la validación
	    // de la
	    // firma XAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that obtains the date to use for validating the information about a signer/counter-signer. This date will be the generation time of the first time-stamp contained inside
     * of a <code>xades:SignatureTimeStamp</code> element. If the signer/counter-signer doesn't contain any <code>xades:SignatureTimeStamp</code> element, the date will be the current
     * date.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @return the validation date.
     * @throws SigningException If there is some problem trying to retrieve the validation date.
     */
    private Date getValidationDate(XAdESSignerInfo signerInfo) throws SigningException {
	// Por defecto definimos la fecha de validación como la fecha actual
	Date validationDate = Calendar.getInstance().getTime();

	// Si el firmante incluye algún sello de tiempo contenido en elementos
	// xades:SignatureTimeStamp
	List<XAdESTimeStampType> listTimeStamps = signerInfo.getListTimeStamps();
	if (listTimeStamps != null && listTimeStamps.size() > 0) {
	    // Establecemos como fecha de validación la fecha de generación del
	    // sello de
	    // tiempo menos reciente, esto es, el primero de la lista
	    validationDate = listTimeStamps.get(0).getTimestampGenerationDate();
	}
	return validationDate;
    }

    /**
     * Method that includes into the object with the information about the validation of a signer/counter-signer the information about the signing certificate.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @throws SigningException If the signing certificate cannot be retrieved.
     */
    private void addSigningCertificateInfo(SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult) throws SigningException {
	// Añadimos a la información de validación del firmante su certificado
	signerValidationResult.setSigningCertificate(signerInfo.getSigningCertificate());

	// Verificamos que no se haya producido ningún error durante el proceso
	// de obtener el certificado del firmante
	if (signerInfo.getErrorMsg() != null) {
	    // Establecemos, a nivel general, el error asociado a la validación
	    // de la
	    // firma XAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(signerInfo.getErrorMsg());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido
	    signerValidationResult.setErrorMsg(signerInfo.getErrorMsg());

	    throw new SigningException(signerInfo.getErrorMsg());
	}
    }

    /**
     * Method that validates if the public key information contained inside of a XML signature is valid by XAdES TS 101 903 v1.3.2. This method checks:
     * <ul>
     * <li>The signature contains a <code>SigningCertificate</code> element and this element matches to the signing certificate.</li>
     * <li>If the signature doesn't contain a <code>SigningCertificate</code> element the method checks if the <code>KeyInfo</code> element contains
     * the signing certificate, and checks if the signature has a reference to the information of the <code>KeyInfo</code> element.</li>
     * </ul>
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param isBaseline Parameter that indicates if the XML signature has Baseline form (true) or not (false).
     * @param isCounterSignature Parameter that indicates if the element to validate is a signer (false) or a counter-signer (true).
     * @throws SigningException If the validation fails.
     */
    private void validateKeyInfo(SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult, boolean isBaseline, boolean isCounterSignature) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	ValidationInfo validationInfo = new ValidationInfo();
	validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_PUBLIC_KEY_INFO_VALIDATION);

	// Añadimos a la lista de validaciones del firmante/contra-firmante la
	// información asociada a esta validación
	signerValidationResult.getListValidations().add(validationInfo);
	try {
	    // Comprobamos que la información de clave pública del firmante es
	    // correcta
	    UtilsSignatureOp.validateXAdESPublicKeyInfo(signerInfo.getId(), signerInfo.getElementSignature(), signerInfo.getSignature(), isBaseline, isCounterSignature);

	    // Indicamos que la validación ha sido correcta
	    validationInfo.setSucess(true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la validación
	    // de la
	    // firma XAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    validationInfo.setSucess(false);
	    validationInfo.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that obtains the <code>xades:SignedSignatureProperties</code> element from a XML signature.
     * @param signedPropertiesElement Parameter that represents <code>xades:SignedProperties</code> element.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the error message when the XML signature
     * doesn't contain the element.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signed XML document.
     * @return an object that represents the <code>xades:SignedSignatureProperties</code> element.
     * @throws SigningException If the XML signature doesn't contain the element.
     */
    private Element retrieveSignedSignaturePropertiesElement(Element signedPropertiesElement, SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult) throws SigningException {
	try {
	    // Recorremos la lista de elementos hijos del elemento
	    // xades:SignedProperties buscando el elemento
	    // xades:SignedSignatureProperties
	    return UtilsXML.getChildElement(signedPropertiesElement, IXMLConstants.ELEMENT_SIGNED_SIGNATURE_PROPERTIES, signerInfo.getId(), true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la validación
	    // de la
	    // firma XAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }
	    throw new SigningException(e);
	}
    }

    /**
     * Method that obtains the <code>xades:SignedProperties</code> element from a XML signature.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the error message when the XML signature
     * doesn't contain the element.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signed XML document.
     * @return an object that represents the <code>xades:SignedProperties</code> element.
     * @throws SigningException If the XML signature doesn't contain the element.
     */
    private Element retrieveSignedPropertiesElement(SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult) throws SigningException {
	try {
	    // Recorremos la lista de elementos hijos del elemento
	    // xades:QualifyingProperties buscando el elemento
	    // xades:SignedProperties
	    return UtilsXML.getChildElement(signerInfo.getQualifyingPropertiesElement(), IXMLConstants.ELEMENT_SIGNED_PROPERTIES, signerInfo.getId(), true);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado a la validación
	    // de la
	    // firma XAdES como el error producido, si es que no se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error asociado a la
	    // validación como el error producido, si es que no se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }
	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the <code>xades:SignatureTimeStamp</code> elements associated to certain signer/counter-signer.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateSignatureTimeStampElements(SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult, String idClient) throws SigningException {
	// Si el firmante contiene al menos un elemento xades:SignatureTimeStamp
	if (signerInfo.getListTimeStamps() != null && !signerInfo.getListTimeStamps().isEmpty()) {
	    // Instanciamos el objeto que ofrece información sobre la
	    // validación
	    // llevada a cabo
	    ValidationInfo validationInfo = new ValidationInfo();
	    validationInfo.setIdValidationTask(ISignatureValidationTaskID.ID_SIGNATURE_TIME_STAMP_ELEMENTS_VALIDATION);

	    // Por defecto establecemos que la validación ha sido correcta
	    validationInfo.setSucess(true);

	    // Añadimos a la lista de validaciones del
	    // firmante/contra-firmante la
	    // información asociada a esta validación
	    signerValidationResult.getListValidations().add(validationInfo);

	    // Añadmos a la información de validación del
	    // firmante/contra-firmante una lista donde ubicar la
	    // información de validación de cada sello de tiempo asociado
	    signerValidationResult.setListTimestampsValidations(new ArrayList<TimestampValidationResult>());

	    try {
		// Obtenemos una lista con los sellos de tiempo contenidos
		// en los
		// elementos xades:SignatureTimeStamp ordenados ascendentemente
		// por fecha
		// de generación
		List<XAdESTimeStampType> listTimestampsIntoSignature = signerInfo.getListTimeStamps();

		// Definimos la fecha actual como fecha de validación para
		// el certificado firmante del sello de tiempo más reciente
		Date validationDateLatestSignatureTimeStamp = Calendar.getInstance().getTime();

		// Recorremos la lista con los sellos de tiempo contenidos
		// en los
		// elementos xades:SignatureTimeStamp ordenados ascendentemente
		// por fecha
		// de generación
		for (int i = 0; i < listTimestampsIntoSignature.size(); i++) {
		    // Definimos una variable para establecer la fecha de
		    // validación del
		    // certificado firmante del sello de tiempo. Por
		    // defecto, dicha fecha será la fecha actual
		    Date validationDate = validationDateLatestSignatureTimeStamp;

		    // Si no estamos procesando el sello de tiempo más
		    // reciente
		    if (i < listTimestampsIntoSignature.size() - 1) {
			// Establecemos como fecha de validación la fecha de
			// generación
			// del siguiente sello de tiempo
			validationDate = listTimestampsIntoSignature.get(i + 1).getTimestampGenerationDate();
		    }

		    // Accedemos al sello de tiempo
		    XAdESTimeStampType currentTimestampType = listTimestampsIntoSignature.get(i);

		    // Instanciamos el objeto donde ubicar la información de
		    // validación asociada al sello de tiempo y añadimos esa
		    // información al objeto que contiene la información
		    // de validación del firmante
		    TimestampValidationResult timestampValidationResult = new TimestampValidationResult();
		    signerValidationResult.getListTimestampsValidations().add(timestampValidationResult);

		    // Por defecto establecemos que el sello de tiempo es
		    // correcto
		    timestampValidationResult.setCorrect(true);

		    // Instanciamos en el objeto donde ubicar la información
		    // de validación asociada al sello de tiempo una lista
		    // donde ubicar la información asociada a las
		    // validaciones
		    // levadas a cabo sobre el sello de tiempo
		    timestampValidationResult.setListValidations(new ArrayList<TimeStampValidationInfo>());

		    // Establecemos en la información de validación asociada de
		    // qué tipo es el sello de tiempo
		    // al sello de tiempo que éste es de tipo ASN.1
		    timestampValidationResult.setXML(currentTimestampType.getXmlTimestamp() != null);

		    // Validamos el sello de tiempo
		    validateTimeStamp(currentTimestampType, timestampValidationResult, signerValidationResult, signerInfo, validationResult, idClient, validationDate, validationInfo);
		}
	    } catch (Exception e) {
		// Establecemos, a nivel general, el error asociado a la
		// validación
		// de la
		// firma XAdES como el error producido, si es que no se
		// indicó
		// previamente
		if (validationResult.getErrorMsg() == null) {
		    validationResult.setErrorMsg(e.getMessage());
		}

		// Establecemos, a nivel de firmante, el error asociado a la
		// validación como el error producido, si es que no se
		// indicó
		// previamente
		if (signerValidationResult.getErrorMsg() == null) {
		    signerValidationResult.setErrorMsg(e.getMessage());
		}

		// Indicamos en la información sobre la validación llevada a
		// cabo
		// que no ha sido correcta
		validationInfo.setSucess(false);
		validationInfo.setErrorMsg(e.getMessage());

		throw new SigningException(e);
	    }
	}
    }

    /**
     * Method that validates a time-stamp and updates the information about the result of the validation.
     * @param tst Parameter that represents the information related to the time-stamp to validate.
     * @param timestampValidationResult Parameter that represents the information to update with the result of the validation of the time-stamp.
     * @param signerValidationResult Parameter that represents the information about the validation of the signer/counter-signer to update with the result of the validation.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     * @param validationDate Parameter that represents the validation date.
     * @param validationInfo Parameter that represents the information about the result of the valdation of the <code>xades:SignatureTimeStamp</code> elements associated
     * to the current signer/counter-signer.
     * @throws SigningException If the validation fails.
     */
    private void validateTimeStamp(XAdESTimeStampType tst, TimestampValidationResult timestampValidationResult, SignerValidationResult signerValidationResult, XAdESSignerInfo signerInfo, ValidationResult validationResult, String idClient, Date validationDate, ValidationInfo validationInfo) throws SigningException {
	try {
	    // Obtenemos el certificado firmante del sello de
	    // tiempo
	    X509Certificate timestampCertificate = tst.getTstCertificate();

	    // Añadimos a la información de validación asociada
	    // al sello de tiempo los datos del certificado
	    // firmante del sello de tiempo
	    timestampValidationResult.setSigningCertificate(timestampCertificate);

	    // Validamos la firma del sello de tiempo
	    validateTimestampSignature(timestampValidationResult, tst);

	    // Validamos los datos firmados por el sello de tiempo (sello de
	    // tiempo ASN.1), o bien, las referencias contenidas en el sello de
	    // tiempo, incluyendo la referencia a los datos sellados (sello de
	    // tiempo XML)
	    validateTimeStampStampedData(timestampValidationResult, tst, signerInfo);

	    // Validamos el certificado firmante del sello de
	    // tiempo
	    validateTimeStampCertificate(timestampValidationResult, timestampCertificate, validationDate, idClient);
	} catch (Exception e) {
	    // Establecemos, a nivel general, el error asociado
	    // a la
	    // validación
	    // de la
	    // firma CAdES como el error producido, si es que no
	    // se indicó
	    // previamente
	    if (validationResult.getErrorMsg() == null) {
		validationResult.setErrorMsg(e.getMessage());
	    }

	    // Establecemos, a nivel de firmante, el error
	    // asociado a la
	    // validación como el error producido, si es que no
	    // se indicó
	    // previamente
	    if (signerValidationResult.getErrorMsg() == null) {
		signerValidationResult.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación
	    // llevada a
	    // cabo sobre los atributos signature-time-stamp
	    // que no ha sido correcta, si es que no se indicó
	    // previamente
	    validationInfo.setSucess(false);
	    if (validationInfo.getErrorMsg() == null) {
		validationInfo.setErrorMsg(e.getMessage());
	    }

	    // Indicamos en la información sobre la validación
	    // llevada a
	    // cabo en el sello de tiempo
	    // que no ha sido correcta
	    timestampValidationResult.setCorrect(false);

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the signing certificate of a time-stamp contained inside a <code>xades:SignatureTimeStamp</code> element associated to a signer/counter-signer.
     * @param timestampValidationResult Parameter that represents the information about the validation of the time-stamp to update with the result of the validation.
     * @param timestampCertificate Parameter that represents the signing certificate of the time-stamp.
     * @param validationDate Parameter that represents the validation date.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the validation fails.
     */
    private void validateTimeStampCertificate(TimestampValidationResult timestampValidationResult, X509Certificate timestampCertificate, Date validationDate, String idClient) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo timestampValidationInto = new TimeStampValidationInfo();
	timestampValidationInto.setIdValidationTask(ITimestampValidationTaskID.ID_SIGNING_CERTIFICATE_VALIDATION);

	// Añadimos a la lista de validaciones del sello de tiempo la
	// información asociada a esta validación
	timestampValidationResult.getListValidations().add(timestampValidationInto);
	try {
	    // Validamos el certificado firmante
	    UtilsSignatureOp.validateCertificate(timestampCertificate, validationDate, false, idClient, true);

	    // Indicamos que la validación ha sido correcta
	    timestampValidationInto.setSucess(true);
	} catch (Exception e) {
	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    timestampValidationInto.setSucess(false);
	    timestampValidationInto.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that checks if the value of the messageImprint field within time-stamp token is a hash of the value indicated (when the time-stamp is an ASN.1 object), or validates
     * the references included into the time-stamp (when the time-stamp is an XML object).
     * @param timestampValidationResult Parameter that represents the information about the validation of the time-stamp to update with the result of the validation.
     * @param tst Parameter that represents the information related to the time-stamp to validate.
     * @param signerInfo Parameter that represents the information about the signer/counter-signer.
     * @throws SigningException If the validation fails.
     */
    private void validateTimeStampStampedData(TimestampValidationResult timestampValidationResult, XAdESTimeStampType tst, XAdESSignerInfo signerInfo) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo timestampValidationInto = new TimeStampValidationInfo();

	// Si el sello de tiempo es XML
	if (tst.getXmlTimestamp() != null) {
	    // Indicamos que la tarea de validación es sobre las 2 referencias
	    // contenidas en el sello de tiempo, una, sobre el elemento TSTInfo,
	    // y otra sobre los datos sellados
	    timestampValidationInto.setIdValidationTask(ITimestampValidationTaskID.ID_REFERENCES_VALIDATION);
	}
	// Si el sello de tiempo es ASN.1
	else {
	    // Indicamos que la tarea de validación es únicamente hacia los
	    // datos sellados
	    timestampValidationInto.setIdValidationTask(ITimestampValidationTaskID.ID_STAMPED_DATA_VALIDATION);
	}

	// Añadimos a la lista de validaciones del sello de tiempo la
	// información asociada a esta validación
	timestampValidationResult.getListValidations().add(timestampValidationInto);
	try {
	    // Obtenemos los datos que deberían haber sido ser sellados
	    byte[ ] stampedData = UtilsTimestampXML.getSignatureTimeStampDataToStamp(signerInfo.getElementSignature(), tst.getCanonicalizationAlgorithm());

	    // Si el sello de tiempo es XML
	    if (tst.getXmlTimestamp() != null) {
		// Validamos las referencias del sello de tiempo
		UtilsTimestampXML.validateTimeStampReferences(tst.getXmlTimestamp().getFirstChild(), stampedData, tst.getId());
	    }
	    // Si el sello de tiempo es ASN.1
	    else {
		// Validamos los datos sellados
		UtilsTimestampPdfBc.validateTimestampMessageImprint(tst.getAsn1Timestamp(), stampedData);
	    }
	    // Indicamos que la validación ha sido correcta
	    timestampValidationInto.setSucess(true);
	} catch (Exception e) {
	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    timestampValidationInto.setSucess(false);
	    timestampValidationInto.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates the signature of a time-stamp contained inside of a <code>xades:SignatureTimeStamp</code> element associated to a signer/counter-signer.
     * @param timestampValidationResult Parameter that represents the information about the validation of the time-stamp to update with the result of the validation.
     * @param tst Parameter that represents the information about the time-stamp to validate.
     * @throws SigningException If the validation fails.
     */
    private void validateTimestampSignature(TimestampValidationResult timestampValidationResult, XAdESTimeStampType tst) throws SigningException {
	// Instanciamos el objeto que ofrece información sobre la validación
	// llevada a cabo
	TimeStampValidationInfo timestampValidationInto = new TimeStampValidationInfo();
	timestampValidationInto.setIdValidationTask(ITimestampValidationTaskID.ID_TIMESTAMP_SIGNATURE_VALIDATION);

	// Añadimos a la lista de validaciones del sello de tiempo la
	// información asociada a esta validación
	timestampValidationResult.getListValidations().add(timestampValidationInto);

	try {
	    // Validamos la firma del sello de tiempo, distinguiendo si el sello
	    // de tiempo es ASN.1 o XML
	    if (tst.getXmlTimestamp() != null) {
		UtilsTimestampXML.validateXMLTimestamp(tst.getXmlTimestamp());
	    } else {
		UtilsTimestampPdfBc.validateASN1Timestamp(tst.getAsn1Timestamp());
	    }

	    // Indicamos que la validación ha sido correcta
	    timestampValidationInto.setSucess(true);
	} catch (Exception e) {
	    // Indicamos en la información sobre la validación llevada a cabo
	    // que no ha sido correcta
	    timestampValidationInto.setSucess(false);
	    timestampValidationInto.setErrorMsg(e.getMessage());

	    throw new SigningException(e);
	}
    }

    /**
     * Method that validates all the counter-signers associated to a signer.
     * @param signingMode Parameter that represents the signing mode of the signed XML document. The possible values are:
     * <ul>
     * <li>{@link IUtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @param signerInfo Parameter that represents the information about the parent signer.
     * @param signerValidationResult Parameter that represents the information about the validation of the parent signer.
     * @param validationResult Parameter that represents the information about the validation of the signature.
     * @param idClient Parameter that represents the client application identifier.
     * @param signedFile Parameter that represents the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signedFileName Parameter that represents the name of the file signed by the XML signature when the signed data isn't included into the signed XML document.
     */
    public void validateCounterSigners(String signingMode, XAdESSignerInfo signerInfo, SignerValidationResult signerValidationResult, ValidationResult validationResult, String idClient, byte[ ] signedFile, String signedFileName) {
	// Accedemos a la lista de contra-firmantes, en caso de haber
	List<XAdESSignerInfo> listCounterSignerInfo = signerInfo.getListCounterSigners();
	if (listCounterSignerInfo != null && !listCounterSignerInfo.isEmpty()) {
	    // Si el firmante posee contra-firmantes instanciamos una lista
	    // donde ubicar la información de validación
	    // de cada contra-firmante y la asociamos al resultado final de
	    // validar el firmante padre
	    List<SignerValidationResult> listCounterSignersValidationResults = new ArrayList<SignerValidationResult>();
	    signerValidationResult.setListCounterSignersValidationsResults(listCounterSignersValidationResults);

	    // Recorremos la lista de contra-firmantes
	    for (XAdESSignerInfo counterSignerInfo: listCounterSignerInfo) {
		// Primero, determinamos el formato del contra-firmante
		String signerFormat = SignatureFormatDetectorXades.resolveSignerXAdESFormat(counterSignerInfo.getElementSignature());

		// Si el contra-firmante tiene formato no Baseline, nos
		// mantenemos en este clase. En otro caso, derivamos la
		// validación del contra-firmante a la clase asociada a firmas
		// no Baseline
		SignerValidationResult counterSignerValidationResult = null;
		if (!signerIsBaseline(signerFormat)) {
		    XadesSigner xadesSigner = new XadesSigner();

		    // Obtenemos la información de validación asociada al
		    // contra-firmante
		    counterSignerValidationResult = xadesSigner.validateSigner(signingMode, counterSignerInfo, validationResult, idClient, signerFormat, true);
		} else {
		    // Obtenemos la información de validación asociada al
		    // contra-firmante
		    counterSignerValidationResult = validateSigner(signingMode, counterSignerInfo, validationResult, idClient, signerFormat, true, signedFile, signedFileName);
		}

		// Añadimos a la lista donde ubicar la información de validación
		// de cada contra-firmante la información asociada a la
		// validación del contra-firmante actual
		listCounterSignersValidationResults.add(counterSignerValidationResult);

		// Validamos los contra-firmantes asociados al contra-firmante
		validateCounterSigners(signingMode, counterSignerInfo, signerValidationResult, validationResult, idClient, signedFile, signedFileName);
	    }

	}
    }
}
