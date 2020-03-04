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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/**
 * <b>File:</b><p>es.gob.afirma.signature.policy.SignaturePolicyManager.java.</p>
 * <b>Description:</b><p>Class that manages all the operations related to signature policies.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.3, 04/03/2020.
 */
package es.gob.afirma.signature.policy;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.xml.crypto.dsig.XMLSignature;

import net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier;
import net.java.xades.security.xml.XAdES.XAdES_EPES;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfObject;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.utils.CryptoUtilPdfBc;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.ICryptoUtil;
import es.gob.afirma.utils.IUtilsSignature;

/**
 * <p>Class that manages all the operations related to signature policies.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 04/03/2020.
 */
public final class SignaturePolicyManager {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(SignaturePolicyManager.class);

    /**
     * Constructor method for the class SignaturePolicyManager.java.
     */
    private SignaturePolicyManager() {
    }

    /**
    * Method that checks whether a hash algorithm is allowed by the values defined on the properties file where to configure the
    * validation and generation of signatures with signature policies. The allowed values are:
    * <ul>
    * <li>{@link CryptoUtil#HASH_ALGORITHM_SHA1}</li>
    * <li>{@link CryptoUtil#HASH_ALGORITHM_SHA256}</li>
    * <li>{@link CryptoUtil#HASH_ALGORITHM_SHA512}</li>
    * </ul>
    * @param hashAlgorithm Parameter that represents the hash algorithm.
    * @return a boolean that indicates if the hash algorithm is allowed (true) or not (false).
    */
    private static boolean isValidHashAlgoritmForPolicyDocumentDigest(String hashAlgorithm) {
	// Los valores admitidos son:
	// SHA-1
	// SHA-256
	// SHA-512
	if (hashAlgorithm.equals(ICryptoUtil.HASH_ALGORITHM_SHA1) || hashAlgorithm.equals(ICryptoUtil.HASH_ALGORITHM_SHA256) || hashAlgorithm.equals(ICryptoUtil.HASH_ALGORITHM_SHA512)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether a value is <code>null</code>. Will thrown a {@link IllegalArgumentException} if the value is <code>null</code>.
     * @param value Parameter that represents the value to check.
     * @param errorMsg Parameter that represents the error message to include inside of the exception where the value is <code>null</code>.
     */
    private static void checkInputParameter(Object value, String errorMsg) {
	if (value == null) {
	    LOGGER.error(errorMsg);
	    throw new IllegalArgumentException(errorMsg);
	}
    }

    /**
     * Method that adds the <code>SignaturePolicyIdentifier</code> element to an ASN.1 object.
     * @param contexExpecific Parameter that represents the set of values of the signer info.
     * @param qualifier  Parameter that represents the signature policy qualifier.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param isPAdES Parameter that indicates if the <code>SignaturePolicyIdentifier</code> will be added to a PAdES signature (true) or to a CAdES
     * @param idClient Parameter that represents the client application identifier.
     * signature (false).
     * @throws SignaturePolicyException If the method fails.
     */
    public static void addASN1SignPolicy(ASN1EncodableVector contexExpecific, String qualifier, String policyID, Properties properties, boolean isPAdES, String idClient) throws SignaturePolicyException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG038));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(contexExpecific, Language.getResIntegra(ILogConstantKeys.SPM_LOG041));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }

	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG004, new Object[ ] { policyID }));

	    // Obtenemos el identificador (OID) para la política de firma
	    String sigPolicyId = null;
	    if (isPAdES) {
		sigPolicyId = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_IDENTIFIER_PDF);
	    } else {
		sigPolicyId = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_IDENTIFIER_ASN1);
	    }

	    // Comprobamos que el identificador para la política de firma no sea
	    // nulo ni vacío
	    checkIsNotNullAndNotEmpty(sigPolicyId, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG005, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Obtenemos el algoritmo de hash a usar para calcular el resumen
	    // del documento legible de la política de firma
	    String hashAlgorithm = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_HASH_ALGORITHM);

	    // Comprobamos que el algoritmo de hash a usar para calcular el
	    // resumen del documento legible de la política de firma no sea nulo
	    // ni vacío
	    checkIsNotNullAndNotEmpty(hashAlgorithm, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG026, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Comprobamos que el algoritmo de hash indicado es un valor
	    // admitido, esto es, SHA-1, SHA-256 o SHA-512
	    if (!isValidHashAlgoritmForPolicyDocumentDigest(hashAlgorithm)) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG037, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }

	    // Obtenemos el resumen de la política de firma codificada en Base64
	    String policyHashValue = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_HASH_VALUE);

	    // Comprobamos que el resumen de la política de firma no sea nula ni
	    // vacía.
	    checkIsNotNullAndNotEmpty(policyHashValue, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG029, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    byte[ ] policyDigest = Base64.decode(policyHashValue);

	    // Obtenemos el identificador asociado al algoritmo de hash definido
	    // para la política de firma
	    AlgorithmIdentifier policyAlgorithm = CryptoUtilPdfBc.getAlgorithmIdentifierByName(hashAlgorithm);

	    SigPolicyQualifierInfo sigPolicyQualifierInfo[] = new SigPolicyQualifierInfo[1];
	    SigPolicyQualifiers sigPolicyQualifiers = null;

	    if (GenericUtilsCommons.assertStringValue(qualifier)) {
		sigPolicyQualifierInfo[0] = new SigPolicyQualifierInfo(PKCSObjectIdentifiers.id_spq_ets_uri, new DERIA5String(qualifier));
		sigPolicyQualifiers = new SigPolicyQualifiers(sigPolicyQualifierInfo);
	    }

	    contexExpecific.add(new Attribute(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, new DERSet(new org.bouncycastle.asn1.esf.SignaturePolicyIdentifier(new SignaturePolicyId(new DERObjectIdentifier(sigPolicyId), new OtherHashAlgAndValue(policyAlgorithm, new DEROctetString(policyDigest)), sigPolicyQualifiers)))));
	}
	// catch (TransformersException e) {
	// throw new
	// SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG027,
	// new Object[ ] { policyID }), e);
	// }
	finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG039));
	}
    }

    /**
     * Method that adds the <code>SignaturePolicyIdentifier</code> element to an ASN.1 object.
     * @param contexExpecific Parameter that represents the set of values of the signer info.
     * @param qualifier  Parameter that represents the signature policy qualifier.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param isPAdES Parameter that indicates if the <code>SignaturePolicyIdentifier</code> will be added to a PAdES signature (true) or to a CAdES
     * signature (false).
     * @throws SignaturePolicyException If the method fails.
     */
    public static void addASN1SignPolicy(ASN1EncodableVector contexExpecific, String qualifier, String policyID, Properties properties, boolean isPAdES) throws SignaturePolicyException {
	addASN1SignPolicy(contexExpecific, qualifier, policyID, properties, isPAdES, null);
    }

    /**
     * Method that adds the <code>xades:SignaturePolicyIdentifier</code> element to a XAdES object.
     * @param xades Parameter that represents the XAdES object.
     * @param qualifier Parameter that represents the signature policy qualifier.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SignaturePolicyException If the method fails.
     */
    public static void addXMLSignPolicy(XAdES_EPES xades, String qualifier, String policyID, Properties properties, String idClient) throws SignaturePolicyException {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG001));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(xades, Language.getResIntegra(ILogConstantKeys.SPM_LOG002));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG004, new Object[ ] { policyID }));

	    // Obtenemos la descripción de la política de firma
	    String policyDescription = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_DESCRIPTION);

	    // Obtenemos el identificador (URL o URN) para la política de firma
	    String sigPolicyId = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_IDENTIFIER_XML);

	    // Comprobamos que el identificador para la política de firma no sea
	    // nulo ni vacío
	    checkIsNotNullAndNotEmpty(sigPolicyId, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG005, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Obtenemos el algoritmo de hash a usar para calcular el resumen
	    // del documento legible de la política de firma
	    String hashAlgorithm = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_HASH_ALGORITHM);

	    // Comprobamos que el algoritmo de hash a usar para calcular el
	    // resumen del documento legible de la política de firma no sea nulo
	    // ni vacío
	    checkIsNotNullAndNotEmpty(hashAlgorithm, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG026, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Comprobamos que el algoritmo de hash indicado es un valor
	    // admitido, esto es, SHA-1, SHA-256 o SHA-512
	    if (!isValidHashAlgoritmForPolicyDocumentDigest(hashAlgorithm)) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG037, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }

	    // Obtenemos el resumen de la política de firma codificada en Base64
	    String policyDigest = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_HASH_VALUE);

	    // Comprobamos que hash value de la política de firma no sea nula ni
	    // vacía.
	    checkIsNotNullAndNotEmpty(policyDigest, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG029, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Obtenemos el elemento con la política de firma y lo asociamos
	    // a
	    // la firma XAdES
	    SignaturePolicyIdentifier spi = new es.gob.afirma.signature.xades.SignaturePolicyIdentifierImpl(false, sigPolicyId, policyDescription, qualifier, policyDigest);
	    xades.setSignaturePolicyIdentifier(spi);

	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG007));
	}
    }

    /**
     * Method that adds the <code>xades:SignaturePolicyIdentifier</code> element to a XAdES object.
     * @param xades Parameter that represents the XAdES object.
     * @param qualifier Parameter that represents the signature policy qualifier.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    public static void addXMLSignPolicy(XAdES_EPES xades, String qualifier, String policyID, Properties properties) throws SignaturePolicyException {
	addXMLSignPolicy(xades, qualifier, policyID, properties, null);
    }

    /**
     * Method that validates the entries of a PDf signature dictionary by the signature policy defined on the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void validatePAdESEPESEntries(PdfDictionary pdfSignatureDictionary, String policyID, Properties policyProperties) throws SignaturePolicyException {
	// Obtenemos una cadena con la lista de entradas obligatorias,
	// delimitadas con ',' como operador AND y con '|' como operador OR
	String requiredEntriesStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_REQUIRED_ENTRIES);

	// Instanciamos una lista con la entradas obligatorias en base al
	// operador AND.
	List<String> listANDRequiredEntries = new ArrayList<String>();

	// Instanciamos una lista con las listas de entradas obligatorias
	// agrupadas en base al operador OR
	List<List<String>> listORRequiredEntries = new ArrayList<List<String>>();

	// Rellenamos las 2 listas anteriores
	retrieveListElementsFromString(requiredEntriesStr, listANDRequiredEntries, listORRequiredEntries, true);

	// Si hay entradas obligatorias
	if (!listANDRequiredEntries.isEmpty() || !listORRequiredEntries.isEmpty()) {
	    // Procesamos el conjunto de entradas obligatorias
	    processPDFANDElements(pdfSignatureDictionary, listANDRequiredEntries, policyProperties, policyID, true);
	    processPDFORElements(pdfSignatureDictionary, listORRequiredEntries, policyProperties, policyID, true);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG057, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de entradas opcionales, delimitadas
	// con ',' como operador AND y con '|' como operador OR
	String optionalEntriesStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_OPTIONAL_ENTRIES);

	// Instanciamos una lista con la entradas opcionales en base al operador
	// AND.
	List<String> listANDOptionalEntries = new ArrayList<String>();

	// Instanciamos una lista con las listas de entradas opcionales
	// agrupadas en base al operador OR
	List<List<String>> listOROptionalEntries = new ArrayList<List<String>>();

	// Rellenamos la lista anterior
	retrieveListElementsFromString(optionalEntriesStr, listANDOptionalEntries, listOROptionalEntries, true);

	// Si hay entradas opcionales
	if (!listANDOptionalEntries.isEmpty()) {
	    // Procesamos el conjunto de entradas opcionales
	    processPDFANDElements(pdfSignatureDictionary, listANDOptionalEntries, policyProperties, policyID, false);
	    processPDFORElements(pdfSignatureDictionary, listOROptionalEntries, policyProperties, policyID, false);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG058, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de entradas no permitidas,
	// delimitadas con ',' como operador AND
	String notAllowedEntriesStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_NOT_ALLOWED_ENTRIES);

	// Instanciamos una lista con la entradas no permitidas en base al
	// operador AND.
	List<String> listANDNotAllowedEntries = new ArrayList<String>();

	// Rellenamos las lista anterior
	retrieveListElementsFromString(notAllowedEntriesStr, listANDNotAllowedEntries, null, false);

	// Si hay entradas no permitidas
	if (!listANDNotAllowedEntries.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados no permitidos
	    processNotAllowedPAdESEPESElements(pdfSignatureDictionary, listANDNotAllowedEntries, policyID);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG061, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that checks if the signature mode is valid for a signature type.
     * @param isASN1 Parameter that indicates if the signature is ASN.1 (true) or XML (false).
     * @param signatureMode Parameter that represents the signature mode. If the signature is ASN.1 the signature mode must have one of the next values:
     * <ul>
     * <li>{@link IUtilsSignature#IMPLICIT_SIGNATURE_MODE}.</li>
     * <li>{@link IUtilsSignature#EXPLICIT_SIGNATURE_MODE}.</li>
     * </ul>
     * If the signature is XML the signature mode must have one of the next values:
     * <ul>
     * <li>{@link IUtilsSignature#ENVELOPED_SIGNATURE_MODE}.</li>
     * <li>{@link IUtilsSignature#ENVELOPING_SIGNATURE_MODE}.</li>
     * <li>{@link IUtilsSignature#DETACHED_SIGNATURE_MODE}.</li>
     * </ul>
     * @return a boolean that indicates if the signature mode is valid for the signature type (true) or not (false).
     */
    private static boolean checkSignatureMode(boolean isASN1, String signatureMode) {
	if (isASN1) {
	    if (!signatureMode.equals(IUtilsSignature.IMPLICIT_SIGNATURE_MODE) && !signatureMode.equals(IUtilsSignature.EXPLICIT_SIGNATURE_MODE)) {
		return false;
	    }
	} else {
	    if (!signatureMode.equals(IUtilsSignature.DETACHED_SIGNATURE_MODE) && !signatureMode.equals(IUtilsSignature.ENVELOPED_SIGNATURE_MODE) && !signatureMode.equals(IUtilsSignature.ENVELOPING_SIGNATURE_MODE)) {
		return false;
	    }
	}
	return true;
    }

    /**
     * Method that processes a string composed by different elements differentiated by AND (,) tokens and obtains a list with those elements. Each element
     * is the signing mode allowed for ASN.1 or XML signatures by the signature policy defined on the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param listElementsStr Parameter that represents the string composed by different elements differentiated by AND (,) tokens.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param isASN1 Parameter that indicates whether the values will be processed for an ASN.1 signature (true) or for a XML signature (false).
     * @return a list with each signing mode allowed for ASN.1 or XML signatures by the signature policy defined on the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    private static List<String> retrieveListAllowedSigningModesFromString(String listElementsStr, String policyID, boolean isASN1) throws SignaturePolicyException {
	List<String> listAllowedSignatureModes = new ArrayList<String>();
	// Si se han indicado los modos de firma permitidos
	if (listElementsStr != null) {
	    // Dividimos la cadena en modos de firma en base al operador AND
	    StringTokenizer stAND = new StringTokenizer(listElementsStr, ISignPolicyConstants.OPERATOR_AND);
	    // Recorremos los modos de firma en base al operador AND
	    while (stAND.hasMoreTokens()) {
		// Accedemos al modo de firma
		String signatureMode = stAND.nextToken();
		// Comprobamos que el modo de firma indicado es válido para
		// firmas ASN.1
		if (!checkSignatureMode(isASN1, signatureMode)) {
		    // Lanzamos una excepción
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG064, new Object[ ] { signatureMode, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}
		// Añadimos el elemento a la cadena que devolver
		listAllowedSignatureModes.add(signatureMode);
	    }
	}
	// Si no se han indicado los modos de firma permitidos
	else {
	    // Lanzamos una excepción
	    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG063, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
	return listAllowedSignatureModes;
    }

    /**
     * Method that validates if the signing mode of the CAdES-EPES signature is allowed by the signature policy defined on the properties file where to
     * configure the validation and generation of signatures with signature policies.
     * @param signingMode Parameter that represents the signing mode of the XAdES-EPES signature. The possible values are:
     * <ul>
     * <li>{@link IUtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void validateXAdESEPESSigningMode(String signingMode, String policyID, Properties policyProperties) throws SignaturePolicyException {
	// Obtenemos una cadena con la lista de modos de firma permitidos,
	// delimitados con ','
	String allowedSignatureModesStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_ALLOWED_SIGNING_MODES);

	// Obtenemos una lista con los modos de firma permitidos. Como mucho,
	// tendrá 3 elementos
	List<String> listAllowedSignatureModes = retrieveListAllowedSigningModesFromString(allowedSignatureModesStr, policyID, false);

	// Si la lista de modos de firma permitidos no contiene el modo de firma
	// de la firma XAdES-EPES
	if (!listAllowedSignatureModes.contains(signingMode)) {
	    // Lanzamos una excepción
	    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG065, new Object[ ] { signingMode, policyID }));
	}
    }

    /**
     * Method that validates if the signing mode of the XAdES-EPES signature is allowed by the signature policy defined on the properties file where to
     * configure the validation and generation of signatures with signature policies.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void validateCAdESEPESSigningMode(boolean includeContent, String policyID, Properties policyProperties) throws SignaturePolicyException {
	// Obtenemos una cadena con la lista de modos de firma permitidos,
	// delimitados con ','
	String allowedSignatureModesStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_ALLOWED_SIGNING_MODES);

	// Obtenemos una lista con los modos de firma permitidos. Como mucho,
	// tendrá 2 elementos
	List<String> listAllowedSignatureModes = retrieveListAllowedSigningModesFromString(allowedSignatureModesStr, policyID, true);

	// Si la firma debe incluir el contenido
	if (includeContent) {
	    // Comprobamos si el modo de firma Implícito está permitido
	    if (!listAllowedSignatureModes.contains(IUtilsSignature.IMPLICIT_SIGNATURE_MODE)) {
		// Lanzamos una excepción
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG065, new Object[ ] { IUtilsSignature.IMPLICIT_SIGNATURE_MODE, policyID }));
	    }
	}
	// Si la firma no debe incluir el contenido
	else {
	    // Comprobamos si el modo de firma Explícito está permitido
	    if (!listAllowedSignatureModes.contains(IUtilsSignature.EXPLICIT_SIGNATURE_MODE)) {
		// Lanzamos una excepción
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG065, new Object[ ] { IUtilsSignature.EXPLICIT_SIGNATURE_MODE, policyID }));
	    }
	}
    }

    /**
     * Method that validates the signed elements of a CAdES-EPES signature by the signature policy defined on the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param signerInfo Parameter that represents the information related to the signer.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param isCounterSigner Parameter that indicates if the signer a counter-signer (true) or not (false).
     * @throws SignaturePolicyException If the method fails.
     */
    private static void validateCAdESEPESSignedElements(SignerInfo signerInfo, String policyID, Properties policyProperties, boolean isCounterSigner) throws SignaturePolicyException {
	AttributeTable signedAttributes = new AttributeTable(signerInfo.getAuthenticatedAttributes());

	// Obtenemos una cadena con la lista de elementos firmados
	// obligatorios, delimitados con ',' como operador AND y con '|'
	// como operador OR
	String mandatorySignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_MANDATORY_SIGNED_ELEMENTS);

	// Instanciamos un mapa con los elementos firmados obligatorios. La
	// clave es el nombre del elemento
	Map<String, ASN1ObjectIdentifier> mapANDMandatorySignedElements = new HashMap<String, ASN1ObjectIdentifier>();

	// Instanciamos un lista de mapas de elementos firmados
	// obligatorios en base al operador OR
	List<Map<String, ASN1ObjectIdentifier>> listORMandatorySignedElements = new ArrayList<Map<String, ASN1ObjectIdentifier>>();

	// Rellenamos los 2 mapas anteriores
	retrieveASN1MapsElementsFromString(mandatorySignedElementsStr, mapANDMandatorySignedElements, listORMandatorySignedElements, true, policyProperties);

	// Si hay elementos firmados obligatorios
	if (!mapANDMandatorySignedElements.isEmpty() || !listORMandatorySignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados obligatorios
	    processASN1ANDElements(signedAttributes, mapANDMandatorySignedElements, policyProperties, policyID, true, isCounterSigner);
	    processASN1ORElements(signedAttributes, listORMandatorySignedElements, policyProperties, policyID, true);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG009, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de elementos firmados
	// opcionales, delimitados con ',' como operador AND y con '|' como
	// operador OR
	String optionalSignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_OPTIONAL_SIGNED_ELEMENTS);

	// Instanciamos un mapa con los elementos firmados opcionales. La clave
	// es el nombre del elemento
	Map<String, ASN1ObjectIdentifier> mapANDOptionalSignedElements = new HashMap<String, ASN1ObjectIdentifier>();

	// Instanciamos una lista de mapas de elementos firmados opcionales
	// en base al operador OR
	List<Map<String, ASN1ObjectIdentifier>> listOROptionalSignedElements = new ArrayList<Map<String, ASN1ObjectIdentifier>>();

	// Rellenamos las 2 listas anteriores
	retrieveASN1MapsElementsFromString(optionalSignedElementsStr, mapANDOptionalSignedElements, listOROptionalSignedElements, true, policyProperties);

	// Si hay elementos firmados opcionales
	if (!mapANDOptionalSignedElements.isEmpty() || !listOROptionalSignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados opcionales
	    processASN1ANDElements(signedAttributes, mapANDOptionalSignedElements, policyProperties, policyID, false, isCounterSigner);
	    processASN1ORElements(signedAttributes, listOROptionalSignedElements, policyProperties, policyID, false);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG010, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de elementos firmados no
	// permitidos, delimitados con ',' como operador AND
	String notValidSignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_NOT_ALLOWED_SIGNED_ELEMENT);

	// Instanciamos un mapa con los elementos firmados no permitidos
	Map<String, ASN1ObjectIdentifier> mapNotAllowedSignedElements = new HashMap<String, ASN1ObjectIdentifier>();

	// Rellenamos las lista anterior
	retrieveASN1MapsElementsFromString(notValidSignedElementsStr, mapNotAllowedSignedElements, null, false, policyProperties);

	// Si hay elementos firmados no permitidos
	if (!mapNotAllowedSignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados no permitidos
	    processNotAllowedCAdESEPESElements(signedAttributes, mapNotAllowedSignedElements, policyID);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG059, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates the signed elements of a XAdES-EPES signature by the signature policy defined on the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param signedProperties Parameter that represents the xades:SignedProperties element of the XAdES-EPES signature.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void validateXAdESEPESSignedElements(Properties policyProperties, String policyID, Element signedProperties) throws SignaturePolicyException {
	// Obtenemos una cadena con la lista de elementos firmados
	// obligatorios, delimitados con ',' como operador AND y con '|'
	// como operador OR
	String mandatorySignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_MANDATORY_SIGNED_ELEMENTS);

	// Instanciamos una lista con los elementos firmados obligatorios
	List<String> listANDMandatorySignedElements = new ArrayList<String>();

	// Instanciamos una lista de listas de elementos firmados
	// obligatorios en base al operador OR
	List<List<String>> listORMandatorySignedElements = new ArrayList<List<String>>();

	// Rellenamos las 2 listas anteriores
	retrieveListElementsFromString(mandatorySignedElementsStr, listANDMandatorySignedElements, listORMandatorySignedElements, true);

	// Si hay elementos firmados obligatorios
	if (!listANDMandatorySignedElements.isEmpty() || !listORMandatorySignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados obligatorios
	    processXMLANDElements(signedProperties, listANDMandatorySignedElements, policyProperties, policyID, true);
	    processXMLORElements(signedProperties, listORMandatorySignedElements, policyProperties, policyID, true);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG009, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de elementos firmados
	// opcionales, delimitados con ',' como operador AND y con '|' como
	// operador OR
	String optionalSignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_OPTIONAL_SIGNED_ELEMENTS);

	// Instanciamos una lista con los elementos firmados opcionales
	List<String> listANDOptionalSignedElements = new ArrayList<String>();

	// Instanciamos una lista de listas de elementos firmados opcionales
	// en base al operador OR
	List<List<String>> listOROptionalSignedElements = new ArrayList<List<String>>();

	// Rellenamos las 2 listas anteriores
	retrieveListElementsFromString(optionalSignedElementsStr, listANDOptionalSignedElements, listOROptionalSignedElements, true);

	// Si hay elementos firmados opcionales
	if (!listANDOptionalSignedElements.isEmpty() || !listOROptionalSignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados opcionales
	    processXMLANDElements(signedProperties, listANDOptionalSignedElements, policyProperties, policyID, false);
	    processXMLORElements(signedProperties, listOROptionalSignedElements, policyProperties, policyID, false);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG010, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de elementos firmados no
	// permitidos, delimitados con ',' como operador AND
	String notValidSignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_NOT_ALLOWED_SIGNED_ELEMENT);

	// Instanciamos una lista con los elementos firmados no permitidos
	List<String> listNotAllowedSignedElements = new ArrayList<String>();

	// Rellenamos las lista anterior
	retrieveListElementsFromString(notValidSignedElementsStr, listNotAllowedSignedElements, null, false);

	// Si hay elementos firmados no permitidos
	if (!listNotAllowedSignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados no permitidos
	    processNotAllowedXAdESEPESElements(signedProperties, listNotAllowedSignedElements, policyID);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG059, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates the unsigned elements of a CAdES-EPES signature by the signature policy defined on the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param signerInfo Parameter that represents the information related to the signer.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void validateCAdESEPESUnsignedElements(SignerInfo signerInfo, String policyID, Properties policyProperties) throws SignaturePolicyException {
	AttributeTable unsignedAttributes = null;
	if (signerInfo.getUnauthenticatedAttributes() != null) {
	    unsignedAttributes = new AttributeTable(signerInfo.getUnauthenticatedAttributes());
	}

	// Obtenemos una cadena con la lista de elementos no firmados
	// obligatorios, delimitados con ',' como operador AND y con '|'
	// como operador OR
	String mandatoryUnsignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_MANDATORY_UNSIGNED_ELEMENTS);

	// Instanciamos un mapa con los elementos no firmados obligatorios
	Map<String, ASN1ObjectIdentifier> mapANDMandatoryUnsignedElements = new HashMap<String, ASN1ObjectIdentifier>();

	// Instanciamos una lista de mapas de elementos no firmados
	// obligatorios en base al operador OR
	List<Map<String, ASN1ObjectIdentifier>> listORMandatoryUnsignedElements = new ArrayList<Map<String, ASN1ObjectIdentifier>>();

	// Rellenamos los 2 mapas anteriores
	retrieveASN1MapsElementsFromString(mandatoryUnsignedElementsStr, mapANDMandatoryUnsignedElements, listORMandatoryUnsignedElements, true, policyProperties);

	// Si hay elementos no firmados obligatorios
	if (!mapANDMandatoryUnsignedElements.isEmpty() || !listORMandatoryUnsignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos no firmados obligatorios
	    processASN1ANDElements(unsignedAttributes, mapANDMandatoryUnsignedElements, policyProperties, policyID, true, false);
	    processASN1ORElements(unsignedAttributes, listORMandatoryUnsignedElements, policyProperties, policyID, true);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG011, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de elementos no firmados
	// opcionales, delimitados con ',' como operador AND y con '|' como
	// operador OR
	String optionalUnsignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_OPTIONAL_UNSIGNED_ELEMENTS);

	// Instanciamos un mapa con los elementos no firmados opcionales
	Map<String, ASN1ObjectIdentifier> mapANDOptionalUnsignedElements = new HashMap<String, ASN1ObjectIdentifier>();

	// Instanciamos una lista de mapas de elementos no firmados
	// opcionales en base al operador OR
	List<Map<String, ASN1ObjectIdentifier>> listOROptionalUnsignedElements = new ArrayList<Map<String, ASN1ObjectIdentifier>>();

	// Rellenamos las 2 listas anteriores
	retrieveASN1MapsElementsFromString(optionalUnsignedElementsStr, mapANDOptionalUnsignedElements, listOROptionalUnsignedElements, true, policyProperties);

	// Si hay elementos no firmados opcionales
	if (!mapANDOptionalUnsignedElements.isEmpty() || !listOROptionalUnsignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados opcionales
	    processASN1ANDElements(unsignedAttributes, mapANDOptionalUnsignedElements, policyProperties, policyID, false, false);
	    processASN1ORElements(unsignedAttributes, listOROptionalUnsignedElements, policyProperties, policyID, false);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG012, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de elementos no firmados que no
	// deben estar, delimitados con ',' como operador AND
	String notValidUnsignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_NOT_ALLOWED_UNSIGNED_ELEMENTS);

	// Instanciamos un mapa con los elementos no firmados que no deben
	// estar
	Map<String, ASN1ObjectIdentifier> mapNotAllowedUnsignedElements = new HashMap<String, ASN1ObjectIdentifier>();

	// Rellenamos el mapa anterior
	retrieveASN1MapsElementsFromString(notValidUnsignedElementsStr, mapNotAllowedUnsignedElements, null, false, policyProperties);

	// Si hay elementos no firmados no permitidos
	if (!mapNotAllowedUnsignedElements.isEmpty()) {
	    // Procesamos el conjunto de elementos firmados no permitidos
	    processNotAllowedCAdESEPESElements(unsignedAttributes, mapNotAllowedUnsignedElements, policyID);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG060, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates the unsigned elements of a XAdES-EPES signature by the signature policy defined on the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param qualifyingPropertiesParam Parameter that represents the xades:QualifyingProperties element of the XAdES-EPES signature.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void validateXAdESEPESUnsignedElements(Properties policyProperties, String policyID, Element qualifyingPropertiesParam) throws SignaturePolicyException {
	Element qualifyingProperties = qualifyingPropertiesParam;

	// Obtenemos una cadena con la lista de elementos no firmados
	// obligatorios, delimitados con ',' como operador AND y con '|'
	// como operador OR
	String mandatoryUnsignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_MANDATORY_UNSIGNED_ELEMENTS);

	// Instanciamos una lista con los elementos no firmados obligatorios
	List<String> listANDMandatoryUnsignedElements = new ArrayList<String>();

	// Instanciamos una lista de listas de elementos no firmados
	// obligatorios en base al operador OR
	List<List<String>> listORMandatoryUnsignedElements = new ArrayList<List<String>>();

	// Rellenamos las 2 listas anteriores
	retrieveListElementsFromString(mandatoryUnsignedElementsStr, listANDMandatoryUnsignedElements, listORMandatoryUnsignedElements, true);

	Element unsignedProperties = null;

	// Si hay elementos no firmados obligatorios
	if (!listANDMandatoryUnsignedElements.isEmpty() || !listORMandatoryUnsignedElements.isEmpty()) {
	    // Accedemos al elemento xades:UnsignedProperties
	    unsignedProperties = getXMLElementFromXAdESSignature(qualifyingProperties, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES, true);

	    // Procesamos el conjunto de elementos no firmados obligatorios
	    processXMLANDElements(unsignedProperties, listANDMandatoryUnsignedElements, policyProperties, policyID, true);
	    processXMLORElements(unsignedProperties, listORMandatoryUnsignedElements, policyProperties, policyID, true);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG011, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de elementos no firmados
	// opcionales, delimitados con ',' como operador AND y con '|' como
	// operador OR
	String optionalUnsignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_OPTIONAL_UNSIGNED_ELEMENTS);

	// Instanciamos una lista con los elementos no firmados opcionales
	List<String> listANDOptionalUnsignedElements = new ArrayList<String>();

	// Instanciamos una lista de listas de elementos no firmados
	// opcionales en base al operador OR
	List<List<String>> listOROptionalUnsignedElements = new ArrayList<List<String>>();

	// Rellenamos las 2 listas anteriores
	retrieveListElementsFromString(optionalUnsignedElementsStr, listANDOptionalUnsignedElements, listOROptionalUnsignedElements, true);

	// Si hay elementos no firmados opcionales
	if (!listANDOptionalUnsignedElements.isEmpty() || !listOROptionalUnsignedElements.isEmpty()) {
	    if (unsignedProperties == null) {
		// Accedemos al elemento xades:UnsignedProperties
		unsignedProperties = getXMLElementFromXAdESSignature(qualifyingProperties, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES, false);
	    }
	    if (unsignedProperties != null) {
		// Procesamos el conjunto de elementos firmados opcionales
		processXMLANDElements(unsignedProperties, listANDOptionalUnsignedElements, policyProperties, policyID, false);
		processXMLORElements(unsignedProperties, listOROptionalUnsignedElements, policyProperties, policyID, false);
	    }
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG012, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}

	// Obtenemos una cadena con la lista de elementos no firmados que no
	// deben estar, delimitados con ',' como operador AND
	String notValidUnsignedElementsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_NOT_ALLOWED_UNSIGNED_ELEMENTS);

	// Instanciamos una lista con los elementos no firmados que no deben
	// estar
	List<String> listNotAllowedUnsignedElements = new ArrayList<String>();

	// Rellenamos las lista anterior
	retrieveListElementsFromString(notValidUnsignedElementsStr, listNotAllowedUnsignedElements, null, false);

	// Si hay elementos no firmados no permitidos
	if (!listNotAllowedUnsignedElements.isEmpty()) {
	    if (unsignedProperties == null) {
		// Accedemos al elemento xades:UnsignedProperties
		unsignedProperties = getXMLElementFromXAdESSignature(qualifyingProperties, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES, true);
	    }
	    // Procesamos el conjunto de elementos firmados no permitidos
	    processNotAllowedXAdESEPESElements(unsignedProperties, listNotAllowedUnsignedElements, policyID);
	} else {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG060, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates the hash and sign algorithms of a XAdES-EPES signature by the associated signature policy.
     * @param dsSignature Parameter that represents the ds:Signature element of the XAdES-EPES signature.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void validateXAdESAlgorithms(Element dsSignature, Properties policyProperties, String policyID) throws SignaturePolicyException {

	// Obtenemos una cadena con la lista de algoritmos de hash admitidos,
	// delimitados con ',' como operador AND
	String allowedHashAlgorithmsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_ALLOWED_HASH_ALGORITHM);

	// En caso de que haya definidos algoritmos de hash admitidos
	if (allowedHashAlgorithmsStr != null) {
	    // Instanciamos una lista con los algoritmos de hash permitidos
	    List<String> listAllowedHashAlgorithms = new ArrayList<String>();

	    // Rellenamos las lista anterior
	    retrieveListElementsFromString(allowedHashAlgorithmsStr, listAllowedHashAlgorithms, null, false);

	    // Instanciamos una lista donde ubicar las URI de los algoritmos de
	    // hash permitidos
	    List<String> listURIAllowedHashAlgorithms = new ArrayList<String>();

	    // Recorremos la lista con los algoritmos de hash admitidos para
	    // obtener la URI de cada uno
	    for (String allowedHashAlgoritm: listAllowedHashAlgorithms) {
		// Obtenemos la URI asociada al algoritmo de hash
		String uriHashAlgorithm = (String) policyProperties.get(allowedHashAlgoritm);

		// Comprobamos que la URI existe
		checkIsNotNullAndNotEmpty(uriHashAlgorithm, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG021, new Object[ ] { allowedHashAlgoritm, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		// Metemos la URI en la lista donde ubicar las URI de los
		// algoritmos de hash permitidos
		listURIAllowedHashAlgorithms.add(uriHashAlgorithm);
	    }

	    // Obtenemos todos los elementos ds:DigestMethod
	    NodeList nodeListDigestMethod = dsSignature.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD);
	    for (int i = 0; i < nodeListDigestMethod.getLength(); i++) {
		Element digestMethod = (Element) nodeListDigestMethod.item(i);
		String uriAlgorithm = digestMethod.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
		if (!listURIAllowedHashAlgorithms.contains(uriAlgorithm)) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG022, new Object[ ] { uriAlgorithm, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}
	    }
	}

	// Obtenemos una cadena con la lista de algoritmos de firma admitidos,
	// delimitados con ',' como operador AND
	String allowedSignAlgorithmsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_ALLOWED_SIGN_ALGORITHM);

	// En caso de que haya definidos algoritmos de firma admitidos
	if (allowedSignAlgorithmsStr != null) {
	    // Instanciamos una lista con los algoritmos de firma permitidos
	    List<String> listAllowedSignAlgorithms = new ArrayList<String>();

	    // Rellenamos las lista anterior
	    retrieveListElementsFromString(allowedSignAlgorithmsStr, listAllowedSignAlgorithms, null, false);

	    // Instanciamos una lista donde ubicar las URI de los algoritmos de
	    // firma permitidos
	    List<String> listURIAllowedSignAlgorithms = new ArrayList<String>();

	    // Recorremos la lista con los algoritmos de firma admitidos para
	    // obtener la URI de cada uno
	    for (String allowedSignAlgoritm: listAllowedSignAlgorithms) {
		// Obtenemos la URI asociada al algoritmo de firma
		String uriHashAlgorithm = (String) policyProperties.get(allowedSignAlgoritm);

		// Comprobamos que la URI existe
		checkIsNotNullAndNotEmpty(uriHashAlgorithm, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG023, new Object[ ] { allowedSignAlgoritm, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		// Metemos la URI en la lista donde ubicar las URI de los
		// algoritmos de firma permitidos
		listURIAllowedSignAlgorithms.add(uriHashAlgorithm);
	    }

	    // Obtenemos todos los elementos ds:SignatureMethod
	    NodeList nodeListSignatureMethod = dsSignature.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE_METHOD);
	    for (int i = 0; i < nodeListSignatureMethod.getLength(); i++) {
		Element signatureMethod = (Element) nodeListSignatureMethod.item(i);
		String uriAlgorithm = signatureMethod.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM);
		if (!listURIAllowedSignAlgorithms.contains(uriAlgorithm)) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG024, new Object[ ] { uriAlgorithm, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}
	    }
	}
    }

    /**
     * Method that obtains the identifier of a signature policy defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies, by the identifier of the signature policy defined inside of the signature.
     * @param identifierValue Parameter that represents the identifier of the signature policy defined inside of the signature.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param suffix Parameter that represents the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the ID of the
     * signature policy.
     * @return the identifier of the signature policy defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies, or <code>null</code>.
     */
    private static String getPolicyIDFromIdentifier(String identifierValue, Properties policyProperties, String suffix) {
	String policyID = null;
	// Buscamos la clave del elemento que contiene el valor del
	// identificador
	Set<Object> keySet = policyProperties.keySet();
	Iterator<Object> it = keySet.iterator();
	while (policyID == null && it.hasNext()) {
	    String key = (String) it.next();
	    if (key.endsWith(suffix)) {
		String value = policyProperties.getProperty(key);
		if (value.equals(identifierValue)) {
		    int index = key.indexOf(suffix);
		    policyID = key.substring(0, index);
		}
	    }
	}
	return policyID;
    }

    /**
     * Method that valides if the content of <code>SignaturePolicyIdentifier</code> element of a CAdES-EPES or PAdES-EPES signature is correct.
     * @param spi Parameter that represents the <code>SignaturePolicyIdentifier</code> element.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param isPAdES Parameter that indicates if the <code>SignaturePolicyIdentifier</code> element belong to a PAdES signature (true) or to a CAdES
     * signature.
     * @return the identifier of the signature policy defined inside of the properties file where to configure the validation and generation of
     * signatures with signature policies.
     * @throws SignaturePolicyException If the method fails or the content of <code>SignaturePolicyIdentifier</code> element isn't valid.
     */
    private static String validateAdESEPESSignaturePolicyIdentifier(SignaturePolicyId spi, Properties policyProperties, boolean isPAdES) throws SignaturePolicyException {
	// Obtenemos el OID de la política de firma
	String policyOID = spi.getSigPolicyId().getId();

	// Buscamos en el archivo con las propiedades asociadas a las políticas
	// de firma aquella política cuyo identificador coincida con el obtenido
	String policyID = null;
	if (isPAdES) {
	    policyID = getPolicyIDFromIdentifier(policyOID, policyProperties, ISignPolicyConstants.KEY_IDENTIFIER_PDF);
	} else {
	    policyID = getPolicyIDFromIdentifier(policyOID, policyProperties, ISignPolicyConstants.KEY_IDENTIFIER_ASN1);
	}
	if (policyID == null) {
	    // Si no hemos encontrado ninguna política de firma para el
	    // identificador de la firma informamos de que no se llevará a cabo
	    // la validación de los elementos asociados a la política de firma
	    LOGGER.warn(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG048, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE, policyOID }));
	} else {

	    // Obtenemos el resumen de la política de firma codificada en Base64
	    String policyHashValue = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_HASH_VALUE);

	    // Comprobamos que la ruta completa al documento legible de la
	    // política de firma no sea nula ni vacía
	    checkIsNotNullAndNotEmpty(policyHashValue, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG029, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    byte[ ] policyDigest = Base64.decode(policyHashValue);

	    // Comprobamos si los resúmenes coinciden
	    if (!MessageDigest.isEqual(spi.getSigPolicyHash().getHashValue().getOctets(), policyDigest)) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG006, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	}
	return policyID;
    }

    /**
     * Method that valides if the structure and the content of xades:SignaturePolicyIdentifier element of a XAdES-EPES signature is correct.
     * @param signedSignatureProperties Parameter that represents the <code>xades:SignedSignatureProperties</code> element.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @return the identifier of the signature policy defined inside of the properties file where to configure the validation and generation of
     * signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    private static String validateXAdESEPESSignaturePolicyIdentifier(Element signedSignatureProperties, Properties policyProperties) throws SignaturePolicyException {

	// Accedemos al elemento xades:SignaturePolicyIdentifier
	Element signaturePolicyIdentifier = getXMLElementFromXAdESSignature(signedSignatureProperties, IXMLConstants.ELEMENT_SIGNATURE_POLICY_IDENTIFIER, true);

	// Accedemos al elemento xades:SignaturePolicyId
	Element signaturePolicyId = getXMLElementFromXAdESSignature(signaturePolicyIdentifier, IXMLConstants.ELEMENT_SIGNATURE_POLICY_ID, true);

	// Accedemos al elemento xades:SigPolicyId
	Element sigPolicyId = getXMLElementFromXAdESSignature(signaturePolicyId, IXMLConstants.ELEMENT_SIG_POLICY_ID, true);

	// Accedemos al elemento xades:Identifier
	Element identifier = getXMLElementFromXAdESSignature(sigPolicyId, IXMLConstants.ELEMENT_IDENTIFIER, true);

	// Obtenemos el valor del elemento xades:Identifier con el identificador
	// de la política de firma, que puede ser una URN o una URL
	String identifierValue = identifier.getTextContent();

	// Buscamos en el archivo con las propiedades asociadas a las políticas
	// de firma aquella política cuyo identificador coincida con el obtenido
	String policyID = getPolicyIDFromIdentifier(identifierValue, policyProperties, ISignPolicyConstants.KEY_IDENTIFIER_XML);
	if (policyID == null) {
	    // Si no hemos encontrado ninguna política de firma para el
	    // identificador de la firma informamos de que sólo se podrá validar
	    // estructuralmente la política de firma. La validación estructural
	    // consistirá en determinar si el elemento SignaturePolicyIdentifier
	    // contiene el elemento xades:SigPolicyHash y éste, a su vez,
	    // contiene los elementos ds:DigestMethod y ds:DigestValue
	    LOGGER.warn(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG036, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE, identifierValue }));
	}

	// Accedemos al elemento xades:SigPolicyHash
	Element sigPolicyHash = getXMLElementFromXAdESSignature(signaturePolicyId, IXMLConstants.ELEMENT_SIG_POLICY_HASH, true);

	// Accedemos al elemento ds:DigestValue
	Element digestValue = getXMLElementFromXAdESSignature(sigPolicyHash, IXMLConstants.ELEMENT_DIGEST_VALUE, true);

	if (policyID != null) {

	    // Obtenemos el resumen de la política de firma y comprobamos que su
	    // valor coincide con el definido dentro de la firma.
	    String definedPolicyDigest = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_HASH_VALUE);

	    // Obtenemos el valor del resumen de la política de firma contenida
	    // en
	    // la firma
	    String policyDigest = digestValue.getTextContent();

	    if (!policyDigest.equals(definedPolicyDigest)) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG006, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	}
	return policyID;
    }

    /**
     * Method that validates a generated PAdES-EPES signature by the signature policy defined on the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SignaturePolicyException If the method fails.
     */
    public static void validateGeneratedPAdESEPESSignature(PdfDictionary pdfSignatureDictionary, String policyID, Properties properties, String idClient) throws SignaturePolicyException {
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG050, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	try {
	    checkInputParameter(pdfSignatureDictionary, Language.getResIntegra(ILogConstantKeys.SPM_LOG052));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }

	    // Validamos las claves del diccionario de firma
	    validatePAdESEPESEntries(pdfSignatureDictionary, policyID, policyProperties);
	} finally {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG051, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates a generated CAdES-EPES signature by the signature policy defined on the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param signerInfo Parameter that represents the information related to the signer.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param isCounterSigner Parameter that indicates if the signer a counter-signer (true) or not (false).
     * @param idClient Parameter that represents the client application identifier.
     * @throws SignaturePolicyException If the method fails.
     */
    public static void validateGeneratedCAdESEPESSignature(SignerInfo signerInfo, String policyID, Properties properties, boolean isCounterSigner, String idClient) throws SignaturePolicyException {
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG042, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(signerInfo, Language.getResIntegra(ILogConstantKeys.SPM_LOG041));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }
	    // Validamos los elementos firmados
	    validateCAdESEPESSignedElements(signerInfo, policyID, policyProperties, isCounterSigner);

	    // Validamos los elementos no firmados
	    validateCAdESEPESUnsignedElements(signerInfo, policyID, policyProperties);

	} finally {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG043, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates a generated XAdES-EPES signature by the signature policy defined on the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param dsSignature Parameter that represents the ds:Signature element of the XAdES-EPES signature.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SignaturePolicyException If the method fails.
     */
    public static void validateGeneratedXAdESEPESSignature(Element dsSignature, String policyID, Properties properties, String idClient) throws SignaturePolicyException {
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG008, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(dsSignature, Language.getResIntegra(ILogConstantKeys.SPM_LOG002));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }
	    // Accedemos al elemento xades:QualifyingProperties
	    Element qualifyingProperties = getXMLElementFromXAdESSignature(dsSignature, IXMLConstants.ELEMENT_QUALIFIYING_PROPERTIES, true);

	    // Accedemos al elemento xades:SignedProperties
	    Element signedProperties = getXMLElementFromXAdESSignature(qualifyingProperties, IXMLConstants.ELEMENT_SIGNED_PROPERTIES, true);

	    // Validamos los elementos firmados
	    validateXAdESEPESSignedElements(policyProperties, policyID, signedProperties);

	    // Validamos los elementos no firmados
	    validateXAdESEPESUnsignedElements(policyProperties, policyID, qualifyingProperties);
	} finally {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG013, new Object[ ] { policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates a PAdES-EPES signature by the signature policy defined on the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param signerInformation Parameter that represents the information related to the signer.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SignaturePolicyException If the method fails.
     */
    public static void validatePAdESEPESSignature(SignerInformation signerInformation, PdfDictionary pdfSignatureDictionary, Properties properties, String idClient) throws SignaturePolicyException {
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG050, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(signerInformation, Language.getResIntegra(ILogConstantKeys.SPM_LOG041));
	    checkInputParameter(pdfSignatureDictionary, Language.getResIntegra(ILogConstantKeys.SPM_LOG052));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }

	    // Accedemos al conjunto de atributos firmados
	    AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	    // Accedemos al identificador de la firma CAdES-EPES
	    SignaturePolicyId spi = SignaturePolicyId.getInstance(signedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId).getAttrValues().getObjectAt(0));

	    // Validamos el contenido del elemento SignaturePolicyIdentifier
	    String policyID = validateAdESEPESSignaturePolicyIdentifier(spi, policyProperties, true);

	    // Si tenemos en el archivo de propiedades las propiedades asociadas
	    // a la política de firma encontrada
	    if (policyID != null) {
		AlgorithmIdentifier hashOID = signerInformation.getDigestAlgorithmID();
		// Comprobamos si el algoritmo de hash es válido
		if (!isValidASN1HashAlgorithmByPolicy(hashOID, policyID, policyProperties, idClient)) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG022, new Object[ ] { hashOID.getAlgorithm().getId(), policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}

		AlgorithmIdentifier signHashOID = new AlgorithmIdentifier(signerInformation.getEncryptionAlgOID());
		// Comprobamos si el algoritmo de firma es válido
		if (!isValidASN1SignAlgorithmByPolicy(signHashOID, policyID, policyProperties, idClient)) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG024, new Object[ ] { signHashOID.getAlgorithm().getId(), policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}

		// Validamos los elementos firmados
		validateCAdESEPESSignedElements(signerInformation.toASN1Structure(), policyID, policyProperties, false);

		// Validamos los elementos no firmados
		validateCAdESEPESUnsignedElements(signerInformation.toASN1Structure(), policyID, policyProperties);

		// Validamos las claves del diccionario de firma
		validatePAdESEPESEntries(pdfSignatureDictionary, policyID, policyProperties);
	    }
	} finally {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG051, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates a CAdES-EPES signature by the signature policy defined on the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param signerInformation Parameter that represents the information related to the signer.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param isCounterSigner Parameter that indicates if the signer a counter-signer (true) or not (false).
     * @param includeContent Parameter that indicates if the signature includes the signed data (true) or not (false).
     * @param idClient Parameter that represents the client application identifier.
     * @throws SignaturePolicyException If the method fails.
     */
    public static void validateCAdESEPESSignature(SignerInformation signerInformation, Properties properties, boolean isCounterSigner, boolean includeContent, String idClient) throws SignaturePolicyException {
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG046, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(signerInformation, Language.getResIntegra(ILogConstantKeys.SPM_LOG041));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }
	    // Accedemos al conjunto de atributos firmados
	    AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	    // Accedemos al identificador de la firma CAdES-EPES
	    SignaturePolicyId spi = SignaturePolicyId.getInstance(signedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId).getAttrValues().getObjectAt(0));

	    // Validamos el contenido del elemento SignaturePolicyIdentifier
	    String policyID = validateAdESEPESSignaturePolicyIdentifier(spi, policyProperties, false);

	    // Si tenemos en el archivo de propiedades las propiedades asociadas
	    // a la política de firma encontrada
	    if (policyID != null) {
		AlgorithmIdentifier hashOID = signerInformation.getDigestAlgorithmID();
		// Comprobamos si el algoritmo de hash es válido
		if (!isValidASN1HashAlgorithmByPolicy(hashOID, policyID, policyProperties, idClient)) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG022, new Object[ ] { hashOID.getAlgorithm().getId(), policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}

		AlgorithmIdentifier signHashOID = new AlgorithmIdentifier(signerInformation.getEncryptionAlgOID());
		// Comprobamos si el algoritmo de firma es válido
		if (!isValidASN1SignAlgorithmByPolicy(signHashOID, policyID, policyProperties, idClient)) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG024, new Object[ ] { signHashOID.getAlgorithm().getId(), policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}

		// Comprobamos si el modo de firma es válido
		validateCAdESEPESSigningMode(includeContent, policyID, policyProperties);

		// Validamos los elementos firmados
		validateCAdESEPESSignedElements(signerInformation.toASN1Structure(), policyID, policyProperties, isCounterSigner);

		// Validamos los elementos no firmados
		validateCAdESEPESUnsignedElements(signerInformation.toASN1Structure(), policyID, policyProperties);
	    }

	} finally {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG047, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that validates a XAdES-EPES signature by the signature policy defined on the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param dsSignature Parameter that represents the <code>ds:Signature</code> element of the XAdES-EPES signature.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param signingMode Parameter that represents the signing mode of the XAdES-EPES signature. The possible values are:
     * <ul>
     * <li>{@link UtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link UtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link UtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @param idClient Parameter that represents the client application identifier.
     * @throws SignaturePolicyException If the method fails.
     */
    public static void validateXAdESEPESSignature(Element dsSignature, Properties properties, String signingMode, String idClient) throws SignaturePolicyException {
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG014, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(dsSignature, Language.getResIntegra(ILogConstantKeys.SPM_LOG002));
	    checkInputParameter(signingMode, Language.getResIntegra(ILogConstantKeys.SPM_LOG068));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }
	    // Accedemos al identificador de la firma XAdES-EPES
	    String signatureId = dsSignature.getAttribute("Id");
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG035, new Object[ ] { signatureId }));

	    // Accedemos al elemento xades:QualifyingProperties
	    Element qualifyingProperties = getXMLElementFromXAdESSignature(dsSignature, IXMLConstants.ELEMENT_QUALIFIYING_PROPERTIES, true);

	    // Accedemos al elemento xades:SignedProperties
	    Element signedProperties = getXMLElementFromXAdESSignature(qualifyingProperties, IXMLConstants.ELEMENT_SIGNED_PROPERTIES, true);

	    // Validamos el contenido del elemento SignaturePolicyIdentifier
	    String policyID = validateXAdESEPESSignaturePolicyIdentifier(signedProperties, policyProperties);

	    // Si tenemos en el archivo de propiedades las propiedades asociadas
	    // a la política de firma encontrada
	    if (policyID != null) {
		// Validamos el modo de firma
		validateXAdESEPESSigningMode(signingMode, policyID, policyProperties);

		// Validamos los algoritmos de hash y de firma usados
		validateXAdESAlgorithms(dsSignature, policyProperties, policyID);

		// Validamos los elementos firmados
		validateXAdESEPESSignedElements(policyProperties, policyID, signedProperties);

		// Validamos los elementos no firmados
		validateXAdESEPESUnsignedElements(policyProperties, policyID, qualifyingProperties);
	    }
	} finally {
	    LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG015, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	}
    }

    /**
     * Method that checks if a PDF signature dictionary doesn't contain any of the not allowed entries defined inside of an input list.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param listNotAllowedEntries Parameter that represents the list of not allowed entries.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the PDF signature dictionary contains one of the entries defined as not allowed inside of the list.
     */
    private static void processNotAllowedPAdESEPESElements(PdfDictionary pdfSignatureDictionary, List<String> listNotAllowedEntries, String policyID) throws SignaturePolicyException {
	// Recorremos la lista de entradas no permitidas con delimitador AND
	if (!listNotAllowedEntries.isEmpty()) {
	    for (String notAllowedEntryName: listNotAllowedEntries) {
		// Comprobamos si la entrada está presente en el diccionario de
		// firma
		PdfObject pdfName = getPDFElementFromPAdESSignature(notAllowedEntryName, pdfSignatureDictionary, false);

		if (pdfName != null) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG062, new Object[ ] { notAllowedEntryName, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}
	    }
	}
    }

    /**
     * Method that checks if an elements table doesn't contain any of the not allowed elements defined inside of an input list.
     * @param tableAttributes Parameter that represents the elements table.
     * @param mapANDElements Parameter that represents the map with the OIDs of the not allowed elements. The key is the name of the element.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails or the elements table has as an attribute one of the not allowed elements defined inside of
     * the map.
     */
    private static void processNotAllowedCAdESEPESElements(AttributeTable tableAttributes, Map<String, ASN1ObjectIdentifier> mapANDElements, String policyID) throws SignaturePolicyException {
	// Recorremos el mapa de elementos no permitidos con delimitador AND
	if (!mapANDElements.isEmpty()) {
	    Iterator<String> it = mapANDElements.keySet().iterator();

	    while (it.hasNext()) {
		String attributeName = it.next();
		// Comprobamos si el elemento con el OID está presente
		Attribute attr = null;
		if (tableAttributes != null) {
		    attr = tableAttributes.get(mapANDElements.get(attributeName));
		}

		if (attr != null) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG045, new Object[ ] { attributeName, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}
	    }
	}
    }

    /**
     * Method that checks if a parent element hasn't any of the not allowed elements defined inside of an input list.
     * @param parentElement Parameter that represents the parent element.
     * @param listANDElements Parameter that represents the list with the names of the not allowed elements.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails or the parent element has as a child element one of the not allowed elements defined inside of
     * the list.
     */
    private static void processNotAllowedXAdESEPESElements(Element parentElement, List<String> listANDElements, String policyID) throws SignaturePolicyException {
	// Recorremos la lista de elementos no permitidos con delimitador AND
	if (!listANDElements.isEmpty()) {
	    for (String elementWithOutNamespace: listANDElements) {
		// Comprobamos si el elemento está presente
		Element element = getXMLElementFromXAdESSignature(parentElement, elementWithOutNamespace, false);

		if (element != null) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG016, new Object[ ] { parentElement.getNodeName(), elementWithOutNamespace, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
		}
	    }
	}
    }

    /**
     * Method that checks if a PDF dictionary is valid by the associated signature policy.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param listANDElements Parameter that represents the lists with the entries of the PDF dictionary to process.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param isRequired Parameter that indicates if each of the elements contained inside of the list is required (true) or not (false).
     * @throws SignaturePolicyException If the method fails.
     */
    private static void processPDFANDElements(PdfDictionary pdfSignatureDictionary, List<String> listANDElements, Properties policyProperties, String policyID, boolean isRequired) throws SignaturePolicyException {
	// Recorremos la lista de entradas con delimitador AND
	if (!listANDElements.isEmpty()) {
	    for (String entry: listANDElements) {
		// Comprobamos que la entrada exista
		PdfObject pdfName = getPDFElementFromPAdESSignature(entry, pdfSignatureDictionary, isRequired);

		// Comprobamos si la entrada tiene definidos valores
		// obligatorios
		checkPAdESRequiredValues(pdfName, entry, policyProperties, policyID);

		// Comprobamos si la entrada tiene definidos valores no
		// permitidos
		checkPAdESNotAllowedValues(pdfName, entry, policyProperties, policyID);
	    }
	}
    }

    /**
     * Method that checks if a PDF dictionary is valid by the associated signature policy.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param listListORElements Parameter that represents the list with the lists of the entries of the PDF dictionary to process.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param isRequired Parameter that indicates if at least one of the elements contained inside of each list is required (true) or not (false).
     * @throws SignaturePolicyException If the method fails.
     */
    private static void processPDFORElements(PdfDictionary pdfSignatureDictionary, List<List<String>> listListORElements, Properties policyProperties, String policyID, boolean isRequired) throws SignaturePolicyException {
	// Recorremos la lista de listas elementos con delimitador OR
	if (!listListORElements.isEmpty()) {
	    for (List<String> listORElements: listListORElements) {
		PdfObject pdfName = null;
		String entryName = null;
		int i = 0;
		while (pdfName == null && i < listORElements.size()) {
		    // Comprobamos que la entrada exista
		    pdfName = getPDFElementFromPAdESSignature(entryName, pdfSignatureDictionary, false);
		    i++;
		}
		if (pdfName != null) {
		    // Comprobamos si la entrada tiene definidos valores
		    // obligatorios
		    checkPAdESRequiredValues(pdfName, entryName, policyProperties, policyID);

		    // Comprobamos si la entrada tiene definidos valores no
		    // permitidos
		    checkPAdESNotAllowedValues(pdfName, entryName, policyProperties, policyID);
		} else {
		    // Si el elemento es obligatorio y no está presente lanzamos
		    // una excepción
		    if (isRequired) {
			throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG056, new Object[ ] { listORElements }));
		    }
		}
	    }
	}
    }

    /**
     * Method that validates an ASN.1 element by the associated signature policy.
     * @param attr Parameter that represents the ASN.1 element to validate.
     * @param attributeName Parameter that represents the name of the ASN.1 element.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param isRequired Parameter that indicates if the element can be <code>null</code> (false) or not (true).
     * @param isCounterSigner Parameter that represents if the signer which contains the ASN.1 element is a counter-signer (true) or not (false).
     * @param oid Parameter that represents the OID of the ASN.1 element.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void processASN1ANDElement(Attribute attr, String attributeName, Properties policyProperties, String policyID, boolean isRequired, boolean isCounterSigner, ASN1ObjectIdentifier oid) throws SignaturePolicyException {
	if (attr != null) {
	    // Comprobamos si el elemento tiene definidos valores
	    // obligatorios
	    checkCAdESRequiredValues(attr, attributeName, policyProperties, policyID);

	    // Comprobamos si el elemento tiene definidos valores no
	    // permitidos
	    checkCAdESNotAllowedValues(attr, attributeName, policyProperties, policyID);

	} else {
	    // TODO: Si el elemento es obligatorio y no está presente lanzamos
	    // una excepción, salvo que el elemento obligatorio sea ContentType
	    // y la
	    // firma sea una contra-firma, en dicho caso, NO LANZAMOS UNA
	    // EXCEPCIÓN. Esta es una solución tomada por Dirección de
	    // Proyecto.
	    // CHECKSTYLE:OFF Boolean complexity needed
	    if (isRequired && (oid == null || oid != null && (!oid.equals(CMSAttributes.contentType) || oid.equals(CMSAttributes.contentType) && !isCounterSigner))) {
		// CHECKSTYLE:ON
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG019, new Object[ ] { attributeName }));
	    }
	}
    }

    /**
     * Method that checks if an ASN.1 element is valid by the associated signature policy.
     * @param tableAttributes Parameter that represents a table with signed or unsigned attributes of the signature.
     * @param mapANDElements Parameter that represents the map with the OIDs of the ASN.1 elements to process. The key is the name of the element.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param isRequired Parameter that indicates if each of the elements contained inside of the map is required (true) or not (false).
     * @param isCounterSigner Parameter that represents if the signer which contains the ASN.1 elements is a counter-signer (true) or not (false).
     * @throws SignaturePolicyException If the method fails.
     */
    private static void processASN1ANDElements(AttributeTable tableAttributes, Map<String, ASN1ObjectIdentifier> mapANDElements, Properties policyProperties, String policyID, boolean isRequired, boolean isCounterSigner) throws SignaturePolicyException {
	// Recorremos el mapa de OIDs de elementos con delimitador AND
	if (!mapANDElements.isEmpty()) {
	    Iterator<String> it = mapANDElements.keySet().iterator();
	    while (it.hasNext()) {
		String attributeName = it.next();
		Attribute attr = null;
		ASN1ObjectIdentifier oid = null;
		if (tableAttributes != null) {
		    // Comprobamos si el elemento con el OID está presente
		    oid = mapANDElements.get(attributeName);
		    attr = tableAttributes.get(oid);
		}
		processASN1ANDElement(attr, attributeName, policyProperties, policyID, isRequired, isCounterSigner, oid);
	    }
	}
    }

    /**
     * Method that checks if a XML element is valid by the associated signature policy.
     * @param parentElement Parameter that represents the XML element.
     * @param listANDElements Parameter that represents the list of child elements delimited by AND tag.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param isRequired Parameter that indicates if each of the elements are required (true) or not (false).
     * @throws SignaturePolicyException If the method fails.
     */
    private static void processXMLANDElements(Element parentElement, List<String> listANDElements, Properties policyProperties, String policyID, boolean isRequired) throws SignaturePolicyException {
	// Recorremos la lista de elementos con delimitador AND
	if (!listANDElements.isEmpty()) {
	    for (String elementToFind: listANDElements) {
		// Comprobamos si el elemento está presente
		Element element = getXMLElementFromXAdESSignature(parentElement, elementToFind, isRequired);

		// Procesamos el elemento respecto a sus hijos y valores
		if (element != null) {
		    checkXAdESElementChildsAndValues(policyProperties, policyID, elementToFind, element);
		}

	    }
	}
    }

    /**
     * Method that checks if an ASN.1 element is valid by the associated signature policy.
     * @param tableAttributes Parameter that reprsents a table with signer or unsigned ASN.1 attributes.
     * @param listOfMapORElements Parameter that represents a list of maps with the OIDs of the elements delimited by OR tag.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param isRequired Parameter that indicates if each of the elements are required (true) or not (false).
     * @throws SignaturePolicyException If the method fails.
     */
    private static void processASN1ORElements(AttributeTable tableAttributes, List<Map<String, ASN1ObjectIdentifier>> listOfMapORElements, Properties policyProperties, String policyID, boolean isRequired) throws SignaturePolicyException {
	// Recorremos la lista de listas elementos con delimitador OR
	if (!listOfMapORElements.isEmpty()) {
	    for (Map<String, ASN1ObjectIdentifier> mapORElements: listOfMapORElements) {
		Attribute attr = null;
		String attributeName = null;
		Iterator<String> it = mapORElements.keySet().iterator();
		while (it.hasNext() && attr == null) {
		    attributeName = it.next();

		    // Comprobamos si el elemento con el OID está presente
		    if (tableAttributes != null) {
			attr = tableAttributes.get(mapORElements.get(attributeName));
		    }
		}
		// Si no hemos encontrado ninguno de los elementos opcionales
		// lanzamos una excepción
		if (attr == null && isRequired) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG020, new Object[ ] { mapORElements.keySet() }));
		}
		// Comprobamos si el elemento tiene definido valores
		// obligatorios
		checkCAdESRequiredValues(attr, attributeName, policyProperties, policyID);

		// Comprobamos si el elemento tiene definidos valores no
		// permitidos
		checkCAdESNotAllowedValues(attr, attributeName, policyProperties, policyID);
	    }
	}
    }

    /**
     * Method that checks if a XML element is valid by the associated signature policy.
     * @param parentElement Parameter that represents the XML element.
     * @param listOfListORElements Parameter that represents the list of child elements delimited by OR tag.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param isRequired Parameter that indicates if each of the elements are required (true) or not (false).
     * @throws SignaturePolicyException If the method fails.
     */
    private static void processXMLORElements(Element parentElement, List<List<String>> listOfListORElements, Properties policyProperties, String policyID, boolean isRequired) throws SignaturePolicyException {
	// Recorremos la lista de listas elementos con delimitador OR
	if (!listOfListORElements.isEmpty()) {
	    for (List<String> listORElements: listOfListORElements) {
		Element element = null;
		String elementWithOutNamespace = null;
		int i = 0;
		while (i < listORElements.size() && element == null) {
		    elementWithOutNamespace = listORElements.get(i);
		    // Comprobamos si el elemento está presente
		    element = getXMLElementFromXAdESSignature(parentElement, elementWithOutNamespace, false);
		    i++;
		}
		// Si no hemos encontrado ninguno de los elementos opcionales
		// lanzamos una excepción
		if (element == null && isRequired) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG020, new Object[ ] { listORElements }));
		}
		// Procesamos el elemento respecto a sus hijos y valores
		if (element != null) {
		    checkXAdESElementChildsAndValues(policyProperties, policyID, elementWithOutNamespace, element);
		}
	    }
	}
    }

    /**
     * Method that validates the child elements and the values of an element by the associated signature policy.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param elementWithOutNamespace Parameter that represents the name of the element without the namespafe prefix.
     * @param element Parameter that represents the element.
     * @throws SignaturePolicyException If the XML element has a value not allowed by the associated signature policy.
     */
    private static void checkXAdESElementChildsAndValues(Properties policyProperties, String policyID, String elementWithOutNamespace, Element element) throws SignaturePolicyException {
	// Comprobamos si el elemento debe tener algún hijo
	// obligatorio
	String mandatoryElementChildsStr = (String) policyProperties.get(policyID + "-[" + elementWithOutNamespace + "]" + ISignPolicyConstants.KEY_REQUIRED_CHILD);
	if (mandatoryElementChildsStr != null) {
	    // Instanciamos una lista con los elementos hijos
	    // obligatorios
	    List<String> listANDMandatoryChildElements = new ArrayList<String>();

	    // Instanciamos una lista de listas de elementos hijos
	    // obligatorios en base al operador OR
	    List<List<String>> listORMandatoryChildElements = new ArrayList<List<String>>();

	    // Rellenamos las 2 listas anteriores
	    retrieveListElementsFromString(mandatoryElementChildsStr, listANDMandatoryChildElements, listORMandatoryChildElements, true);

	    // Procesamos los elementos hijos obligatorios
	    processXMLANDElements(element, listANDMandatoryChildElements, policyProperties, policyID, true);
	    processXMLORElements(element, listORMandatoryChildElements, policyProperties, policyID, true);
	}

	// Comprobamos si el elemento debe tener algún hijo opcional
	String optionalElementChildsStr = (String) policyProperties.get(policyID + "-[" + elementWithOutNamespace + "]" + ISignPolicyConstants.KEY_OPTIONAL_CHILD);
	if (optionalElementChildsStr != null) {
	    // Instanciamos una lista con los elementos hijos
	    // opcionales
	    List<String> listANDOptionalChildElements = new ArrayList<String>();

	    // Instanciamos una lista de listas de elementos hijos
	    // opcionales en base al operador OR
	    List<List<String>> listOROptionalChildElements = new ArrayList<List<String>>();

	    // Rellenamos las 2 listas anteriores
	    retrieveListElementsFromString(optionalElementChildsStr, listANDOptionalChildElements, listOROptionalChildElements, true);

	    // Procesamos los elementos hijos opcionales
	    processXMLANDElements(element, listANDOptionalChildElements, policyProperties, policyID, false);
	    processXMLORElements(element, listOROptionalChildElements, policyProperties, policyID, false);
	}

	// Comprobamos si el elemento tiene algún hijo no permitido
	String notAllowedElementChildsStr = (String) policyProperties.get(policyID + "-[" + elementWithOutNamespace + "]" + ISignPolicyConstants.KEY_NOT_ALLOWED_CHILD);
	if (notAllowedElementChildsStr != null) {
	    // Instanciamos una lista con los elementos hijos no
	    // permitidos
	    List<String> listNotAllowedChildElements = new ArrayList<String>();

	    // Rellenamos las lista anterior
	    retrieveListElementsFromString(notAllowedElementChildsStr, listNotAllowedChildElements, null, false);

	    // Procesamos el conjunto de elementos hijos no
	    // permitidos
	    processNotAllowedXAdESEPESElements(element, listNotAllowedChildElements, policyID);
	}

	// Comprobamos si el elemento tiene definido valores
	// obligatorios
	checkXAdESRequiredValue(policyProperties, policyID, elementWithOutNamespace, element);

	// Comprobamos si el elemento tiene definidos valores no
	// permitidos
	checkXAdESNotAllowedValues(policyProperties, policyID, elementWithOutNamespace, element);
    }

    /**
     * Method that throws an exception if an ASN.1 element has a value not allowed by the associated signature policy.
     * @param attr Parameter that represents the ASN.1 element.
     * @param attributeName Parameter that represents the name of the ASN.1 element.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the ASN.1 element has a value not allowed by the associated signature policy.
     */
    private static void checkCAdESNotAllowedValues(Attribute attr, String attributeName, Properties policyProperties, String policyID) throws SignaturePolicyException {
	String notAllowedValueStr = (String) policyProperties.get(policyID + "-[" + attributeName + "]" + ISignPolicyConstants.KEY_NOT_ALLOWED_VALUE);
	if (notAllowedValueStr != null) {
	    // Instanciamos una lista con los valores no permitidos
	    List<DERObject> listNotAllowedValues = new ArrayList<DERObject>();
	    // Comprobamos si el elemento es único o tiene varios a
	    // elegir
	    if (notAllowedValueStr.contains(ISignPolicyConstants.OPERATOR_AND)) {
		StringTokenizer stOR = new StringTokenizer(notAllowedValueStr, ISignPolicyConstants.OPERATOR_AND);
		while (stOR.hasMoreTokens()) {
		    // Accedemos al valor
		    String notAllowedValueName = stOR.nextToken();

		    // Tratamos de obtener el OID de dicho elemento
		    String notAllowedValueOID = policyProperties.getProperty(notAllowedValueName);

		    // Comprobamos que dicho OID no es nulo ni vacío
		    checkIsNotNullAndNotEmpty(notAllowedValueOID, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG044, new Object[ ] { notAllowedValueName, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		    try {
			// Añadimos el OID a la lista de valores no permitidos
			listNotAllowedValues.add(new ASN1ObjectIdentifier(notAllowedValueOID));
		    } catch (Exception e) {
			throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG049, new Object[ ] { notAllowedValueName, IIntegraConstants.DEFAULT_PROPERTIES_FILE }), e);
		    }
		}
	    } else {
		// Tratamos de obtener el OID de dicho elemento
		String notAllowedValueOID = policyProperties.getProperty(notAllowedValueStr);

		// Comprobamos que dicho OID no es nulo ni vacío
		checkIsNotNullAndNotEmpty(notAllowedValueOID, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG044, new Object[ ] { notAllowedValueStr, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		try {
		    // Añadimos el OID a la lista de valores no permitidos
		    listNotAllowedValues.add(new ASN1ObjectIdentifier(notAllowedValueOID));
		} catch (Exception e) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG049, new Object[ ] { notAllowedValueStr, IIntegraConstants.DEFAULT_PROPERTIES_FILE }), e);
		}
	    }
	    // Obtenemos el valor que presenta el elemento
	    DERObject attributeValue = attr.getAttrValues().getObjectAt(0).getDERObject();

	    // Buscamos en la lista de valores admitidos si está
	    // presente el valor que presenta el elemento
	    boolean enc = false;
	    int i = 0;
	    while (!enc && i < listNotAllowedValues.size()) {
		DERObject allowedValue = listNotAllowedValues.get(i);
		if (allowedValue.equals(attributeValue)) {
		    enc = true;
		}
		i++;
	    }
	    if (enc) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG018, new Object[ ] { attributeName, attributeValue, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	}
    }

    /**
     * Method that throws an exception if a XML element has a value not allowed by the associated signature policy.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param elementWithNamespace Parameter that represents the name of the element with the namespafe prefix.
     * @param element Parameter that represents the element.
     * @throws SignaturePolicyException If the XML element has a value not allowed by the associated signature policy.
     */
    private static void checkXAdESNotAllowedValues(Properties policyProperties, String policyID, String elementWithNamespace, Element element) throws SignaturePolicyException {
	String notAllowedValueStr = (String) policyProperties.get(policyID + "-[" + elementWithNamespace + "]" + ISignPolicyConstants.KEY_NOT_ALLOWED_VALUE);
	if (notAllowedValueStr != null) {
	    // Instanciamos una lista con los valores no permitidos
	    List<String> listNotAllowedValues = new ArrayList<String>();
	    // Comprobamos si el elemento es único o tiene varios a
	    // elegir
	    if (notAllowedValueStr.contains(ISignPolicyConstants.OPERATOR_AND)) {
		StringTokenizer stOR = new StringTokenizer(notAllowedValueStr, ISignPolicyConstants.OPERATOR_AND);
		while (stOR.hasMoreTokens()) {
		    // Accedemos al valor y lo añadimos a la lista
		    listNotAllowedValues.add(stOR.nextToken());
		}
	    } else {
		listNotAllowedValues.add(notAllowedValueStr);
	    }
	    // Obtenemos el valor que presenta el elemento
	    String elementValue = element.getTextContent();

	    // Buscamos en la lista de valores admitidos si está
	    // presente el valor que presenta el elemento
	    boolean enc = false;
	    int i = 0;
	    while (!enc && i < listNotAllowedValues.size()) {
		String allowedValue = listNotAllowedValues.get(i);
		if (allowedValue.equals(elementValue)) {
		    enc = true;
		}
		i++;
	    }
	    if (enc) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG018, new Object[ ] { elementWithNamespace, elementValue, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	}
    }

    /**
     * Method that throws an exception if an entry of a signature dictionary has a not allowed value defined by the associated signature policy.
     * @param pdfName Parameter that represents the entry.
     * @param entryName Parameter that represents the name of the entry.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the entry has a not allowed value defined by the associated signature policy.
     */
    private static void checkPAdESNotAllowedValues(PdfObject pdfName, String entryName, Properties policyProperties, String policyID) throws SignaturePolicyException {
	String pdfEntry = entryName;
	if (!pdfEntry.startsWith(ISignPolicyConstants.ENTRY_PREFIX)) {
	    pdfEntry = ISignPolicyConstants.ENTRY_PREFIX + pdfEntry;
	}
	String notAllowedValueStr = (String) policyProperties.get(policyID + "-[" + pdfEntry + "]" + ISignPolicyConstants.KEY_NOT_ALLOWED_VALUE);
	if (notAllowedValueStr != null) {
	    // Instanciamos una lista con los valores no permitidos
	    List<PdfObject> listNotAllowedValues = new ArrayList<PdfObject>();

	    // Comprobamos si el valor es único o tiene varios a elegir
	    if (notAllowedValueStr.contains(ISignPolicyConstants.OPERATOR_AND)) {
		StringTokenizer stAND = new StringTokenizer(notAllowedValueStr, ISignPolicyConstants.OPERATOR_AND);
		while (stAND.hasMoreTokens()) {
		    String value = stAND.nextToken();
		    if (value.startsWith(ISignPolicyConstants.ENTRY_PREFIX)) {
			value = value.substring(1);
		    }
		    // Añadimos el valor a la lista de valores no permitidos
		    listNotAllowedValues.add(new PdfName(value));
		}
	    } else {
		// Añadimos el valor a la lista de valores no permitidos
		listNotAllowedValues.add(new PdfName(notAllowedValueStr));
	    }
	    // Buscamos en la lista de valores no permitidos si está presente el
	    // valor que presenta la entrada
	    if (listNotAllowedValues.contains(pdfName)) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG055, new Object[ ] { pdfEntry, pdfName.toString(), policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	}
    }

    /**
     * Method that throws an exception if an entry of a signature dictionary hasn't a required values defined by the associated signature policy.
     * @param pdfName Parameter that represents the entry.
     * @param entryName Parameter that represents the name of the entry.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the entry hasn't the required values defined by the associated signature policy.
     */
    private static void checkPAdESRequiredValues(PdfObject pdfName, String entryName, Properties policyProperties, String policyID) throws SignaturePolicyException {
	String pdfEntry = entryName;
	if (!pdfEntry.startsWith(ISignPolicyConstants.ENTRY_PREFIX)) {
	    pdfEntry = ISignPolicyConstants.ENTRY_PREFIX + pdfEntry;
	}
	String requiredValueStr = (String) policyProperties.get(policyID + "-[" + pdfEntry + "]" + ISignPolicyConstants.KEY_REQUIRED_VALUE);
	if (requiredValueStr != null) {
	    // Instanciamos una lista con los valores obligatorios
	    List<PdfObject> listRequiredValues = new ArrayList<PdfObject>();

	    // Comprobamos si el valor obligatorio es único o son varios
	    if (requiredValueStr.contains(ISignPolicyConstants.OPERATOR_OR)) {
		StringTokenizer stOR = new StringTokenizer(requiredValueStr, ISignPolicyConstants.OPERATOR_OR);

		while (stOR.hasMoreTokens()) {
		    String value = stOR.nextToken();
		    if (value.startsWith(ISignPolicyConstants.ENTRY_PREFIX)) {
			value = value.substring(1);
		    }
		    // Metemos el valor en la lista de valores obligatorios
		    listRequiredValues.add(new PdfName(value));
		}
	    } else {
		// Metemos el valor en la lista de valores obligatorios
		listRequiredValues.add(new PdfName(requiredValueStr));
	    }
	    // Buscamos en la lista de valores admitidos si está
	    // presente el valor que presenta la entrada
	    if (!listRequiredValues.contains(pdfName)) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG054, new Object[ ] { pdfEntry, pdfName.toString(), policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	}
    }

    /**
     * Method that throws an exception if an ASN.1 element hasn't a required value defined by the associated signature policy.
     * @param attr Parameter that represents the ASN.1 element to process.
     * @param attributeName Parameter that represents the name of the ASN.1 element.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @throws SignaturePolicyException If the ASN.1 element hasn't a required value defined by the associated signature policy.
     */
    private static void checkCAdESRequiredValues(Attribute attr, String attributeName, Properties policyProperties, String policyID) throws SignaturePolicyException {
	String requiredValueStr = (String) policyProperties.get(policyID + "-[" + attributeName + "]" + ISignPolicyConstants.KEY_REQUIRED_VALUE);
	if (requiredValueStr != null) {
	    // Instanciamos una lista con los valores obligatorios
	    List<DERObject> listRequiredValues = new ArrayList<DERObject>();
	    // Comprobamos si el elemento es único o tiene varios a
	    // elegir
	    if (requiredValueStr.contains(ISignPolicyConstants.OPERATOR_OR)) {
		StringTokenizer stOR = new StringTokenizer(requiredValueStr, ISignPolicyConstants.OPERATOR_OR);
		while (stOR.hasMoreTokens()) {
		    // Accedemos al nombre del elemento
		    String requiredValueName = stOR.nextToken();

		    // Tratamos de obtener el OID de dicho elemento
		    String requiredValueOID = policyProperties.getProperty(requiredValueName);

		    // Comprobamos que dicho OID no es nulo ni vacío
		    checkIsNotNullAndNotEmpty(requiredValueOID, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG044, new Object[ ] { requiredValueName, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		    try {
			// Añadimos el OID a la lista de valores obligatorios
			listRequiredValues.add(new ASN1ObjectIdentifier(requiredValueOID));
		    } catch (Exception e) {
			throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG049, new Object[ ] { requiredValueName, IIntegraConstants.DEFAULT_PROPERTIES_FILE }), e);
		    }
		}
	    } else {
		// Tratamos de obtener el OID de dicho elemento
		String requiredValueOID = policyProperties.getProperty(requiredValueStr);

		// Comprobamos que dicho OID no es nulo ni vacío
		checkIsNotNullAndNotEmpty(requiredValueOID, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG044, new Object[ ] { requiredValueStr, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		try {
		    // Añadimos el OID a la lista de valores obligatorios
		    listRequiredValues.add(new ASN1ObjectIdentifier(requiredValueOID));
		} catch (Exception e) {
		    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG049, new Object[ ] { requiredValueStr, IIntegraConstants.DEFAULT_PROPERTIES_FILE }), e);
		}
	    }
	    // Obtenemos el valor que presenta el elemento
	    DERObject elementValue = attr.getAttrValues().getObjectAt(0).getDERObject();

	    // Buscamos en la lista de valores admitidos si está
	    // presente el valor que presenta el elemento
	    if (!listRequiredValues.contains(elementValue)) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG017, new Object[ ] { attributeName, elementValue, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	}
    }

    /**
     * Method that throws an exception if a XML element hasn't a required value defined by the associated signature policy.
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param elementWithNamespace Parameter that represents the name of the element with the namespafe prefix.
     * @param element Parameter that represents the element.
     * @throws SignaturePolicyException If the XML element hasn't a required value defined by the associated signature policy.
     */
    private static void checkXAdESRequiredValue(Properties policyProperties, String policyID, String elementWithNamespace, Element element) throws SignaturePolicyException {
	String requiredValueStr = (String) policyProperties.get(policyID + "-[" + elementWithNamespace + "]" + ISignPolicyConstants.KEY_REQUIRED_VALUE);
	if (requiredValueStr != null) {
	    // Instanciamos una lista con los valores admitidos
	    List<String> listAllowedValues = new ArrayList<String>();
	    // Comprobamos si el elemento es único o tiene varios a
	    // elegir
	    if (requiredValueStr.contains(ISignPolicyConstants.OPERATOR_OR)) {
		StringTokenizer stOR = new StringTokenizer(requiredValueStr, ISignPolicyConstants.OPERATOR_OR);
		while (stOR.hasMoreTokens()) {
		    // Accedemos al valor y lo añadimos a la lista
		    listAllowedValues.add(stOR.nextToken());
		}
	    } else {
		listAllowedValues.add(requiredValueStr);
	    }
	    // Obtenemos el valor que presenta el elemento
	    String elementValue = element.getTextContent();

	    // Buscamos en la lista de valores admitidos si está
	    // presente el valor que presenta el elemento
	    if (!listAllowedValues.contains(elementValue)) {
		throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG017, new Object[ ] { elementWithNamespace, elementValue, policyID, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
	    }
	}
    }

    /**
     * Method that processes a string composed by different elements differentiated by AND (,) and OR (|) tokens. The method updates
     * the first list defined as a parameter with the list of elements delimited by AND token, and updates the second list defined as a parameter with the
     * list of lists with elements delimited by OR token. Example:
     * <ul>
     * <li>[param] listElementsStr = "A,B,C|D,E,F|G|H"</li>
     * <li>[param] listANDElements is empty.</li>
     * <li>[param] listORElements is empty.</li>
     * </ul>
     * The method will update listANDElements param as: {A, B, E} and listORElements param as: {{C, D}, {F, G, H}}.
     * @param listElementsStr Parameter that represents the string composed by different elements differentiated by AND (,) and OR (|) tokens.
     * @param listANDElements Parameter that represents the list of elements delimited by AND token.
     * @param listORElements Parameter that represents the list of lists with elements delimited by OR token.
     * @param allowOROperator Parameter that indicates if the string composed by different elements can contains OR tokens (true) or not (false).
     */
    private static void retrieveListElementsFromString(String listElementsStr, List<String> listANDElements, List<List<String>> listORElements, boolean allowOROperator) {
	if (listElementsStr != null) {
	    // Dividimos la cadena en elementos en base al operador AND
	    StringTokenizer stAND = new StringTokenizer(listElementsStr, ISignPolicyConstants.OPERATOR_AND);
	    // Recorremos los elementos en base al operador AND
	    while (stAND.hasMoreTokens()) {
		// Accedemos al elemento
		String element = stAND.nextToken();
		// Comprobamos si el elemento es único o tiene varios a elegir
		if (allowOROperator && element.contains(ISignPolicyConstants.OPERATOR_OR)) {
		    StringTokenizer stOR = new StringTokenizer(element, ISignPolicyConstants.OPERATOR_OR);
		    List<String> listOR = new ArrayList<String>();
		    while (stOR.hasMoreTokens()) {
			// Accedemos al elemento y lo añadimos a la lista
			listOR.add(stOR.nextToken());
		    }
		    listORElements.add(listOR);
		} else {
		    listANDElements.add(element);
		}

	    }
	}
    }

    /**
     * Method that processes a string composed by different ASN.1 elements differentiated by AND (,) and OR (|) tokens. The method updates
     * the first map defined as a parameter with the list of OIDs of the ASN.1 elements delimited by AND token, and updates the second list defined as
     * a parameter with the list of maps with the OIDs of the ASN.1 elements by OR token. Example:
     * <ul>
     * <li>[param] listElementsStr = "ContentType,MessageDigest,SigningCertificate|SigningCertificateV2"</li>
     * <li>[param] mapANDOIDs is empty.</li>
     * <li>[param] listOROIDs is empty.</li>
     * </ul>
     * The method will update mapANDOIDs param as: {[ContentType, 1.2.840.113549.1.9.3], [MessageDigest, 1.2.840.113549.1.9.4]} and listORElements
     * param as: {{[SigningCertificate, 1.2.840.113549.1.9.16.2.12], [SigningCertificateV2, 1.2.840.113549.1.9.16.2.47]}}.
     * @param listElementsStr Parameter that represents the string composed by different ASN.1 elements differentiated by AND (,) and OR (|) tokens.
     * @param mapANDOIDs Parameter that represents the maps of OIDs of the ASN.1 elements delimited by AND token. The key is the ASN.1 element name.
     * @param listOROIDs Parameter that represents the list of maps with OIDs of the ASN.1 elements delimited by OR token.
     * @param allowOROperator Parameter that indicates if the string composed by different elements can contains OR tokens (true) or not (false).
     * @param policyProperties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @throws SignaturePolicyException If the method fails.
     */
    private static void retrieveASN1MapsElementsFromString(String listElementsStr, Map<String, ASN1ObjectIdentifier> mapANDOIDs, List<Map<String, ASN1ObjectIdentifier>> listOROIDs, boolean allowOROperator, Properties policyProperties) throws SignaturePolicyException {
	if (listElementsStr != null) {
	    // Dividimos la cadena en elementos en base al operador AND
	    StringTokenizer stAND = new StringTokenizer(listElementsStr, ISignPolicyConstants.OPERATOR_AND);
	    // Recorremos los elementos en base al operador AND
	    while (stAND.hasMoreTokens()) {
		// Accedemos al elemento
		String elementName = stAND.nextToken();
		// Comprobamos si el elemento es único o tiene varios a elegir
		if (allowOROperator && elementName.contains(ISignPolicyConstants.OPERATOR_OR)) {
		    StringTokenizer stOR = new StringTokenizer(elementName, ISignPolicyConstants.OPERATOR_OR);
		    Map<String, ASN1ObjectIdentifier> mapOR = new HashMap<String, ASN1ObjectIdentifier>();
		    while (stOR.hasMoreTokens()) {
			// Accedemos al elemento
			String asn1ObjectName = stOR.nextToken();

			// Tratamos de obtener del listado de OIDs para
			// elementos ASN.1 del archivo de propiedades asociadas
			// a las políticas de firma el
			// valor del OID para el elemento ASN.1
			String asn1OID = policyProperties.getProperty(asn1ObjectName);

			// Comprobamos que el OID no sea nulo ni vacío
			checkIsNotNullAndNotEmpty(asn1OID, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG044, new Object[ ] { asn1ObjectName, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

			// Añadimos el OID a la lista
			try {
			    mapOR.put(asn1ObjectName, new ASN1ObjectIdentifier(asn1OID));
			} catch (Exception e) {
			    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG049, new Object[ ] { asn1ObjectName, IIntegraConstants.DEFAULT_PROPERTIES_FILE }), e);
			}
		    }
		    listOROIDs.add(mapOR);
		} else {
		    // Tratamos de obtener del listado de OIDs para elementos
		    // ASN.1 del archivo de propiedades asociadas a las
		    // políticas de firma el
		    // valor del OID para el elemento ASN.1
		    String asn1OID = policyProperties.getProperty(elementName);

		    // Comprobamos que el OID no sea nulo ni vacío
		    checkIsNotNullAndNotEmpty(asn1OID, Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG044, new Object[ ] { elementName, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		    // Añadimos el OID a la lista
		    try {
			mapANDOIDs.put(elementName, new ASN1ObjectIdentifier(asn1OID));
		    } catch (Exception e) {
			throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG049, new Object[ ] { elementName, IIntegraConstants.DEFAULT_PROPERTIES_FILE }), e);
		    }
		}

	    }
	}
    }

    /**
     * Method that obtains an entry from a PDF signature dictionary.
     * @param entryName Parameter that represents the name of the entry to obtain.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param isRequired Parameter that indicates if the entry is required (true) or optional (false).
     * @return an object that represents the found entry.
     * @throws SignaturePolicyException If the enstry is required and the PDF signature dictionary doesn't contains that entry.
     */
    private static PdfObject getPDFElementFromPAdESSignature(String entryName, PdfDictionary pdfSignatureDictionary, boolean isRequired) throws SignaturePolicyException {
	PdfObject result = null;
	String entry = entryName;
	// Eliminamos del nombre de la entrada el prefijo '/', en caso de estar
	// presente
	if (entry.startsWith("/")) {
	    entry = entry.substring(1);
	}

	// Accedemos a la entrada
	result = pdfSignatureDictionary.get(new PdfName(entry));
	if (result == null && isRequired) {
	    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG053, new Object[ ] { entry }));
	}

	return result;
    }

    /**
     * Method that obtains an element from a XAdES signature.
     * @param parentElement Parameter that represents the parent element of the element to obtain.
     * @param element Parameter that represents the name of the element to obtain.
     * @param isRequired Parameter that indicates if the element is required (true) or optional (false).
     * @return an object that represents the found element.
     * @throws SignaturePolicyException If the element is required and the XAdES signature doesn't contains that element as the child of the indicated
     * parent element.
     */
    private static Element getXMLElementFromXAdESSignature(Element parentElement, String element, boolean isRequired) throws SignaturePolicyException {
	Element result = null;
	NodeList listElements = null;
	// Instanciamos una lista con los espacios de nombres admitidos
	// (XMLDSig, XAdES 1.3.2 y XAdES 1.4.1)
	List<String> listAllowedNamespaces = new ArrayList<String>();
	listAllowedNamespaces.add(XMLSignature.XMLNS);
	listAllowedNamespaces.add(IXMLConstants.XADES_1_3_2_NAMESPACE);
	listAllowedNamespaces.add(IXMLConstants.XADES_1_4_1_NAMESPACE);
	int i = 0;
	while (result == null && i < listAllowedNamespaces.size()) {
	    // Intentamos obtener primero el elemento para el espacio de nombres
	    // de XMLDSig
	    listElements = parentElement.getElementsByTagNameNS(listAllowedNamespaces.get(i), element);
	    if (listElements.getLength() > 0) {
		result = (Element) listElements.item(0);
	    }
	    i++;
	}
	if (result == null && isRequired) {
	    throw new SignaturePolicyException(Language.getFormatResIntegra(ILogConstantKeys.SPM_LOG019, new Object[ ] { element }));
	}
	return result;
    }

    /**
     * Method that verifies if a value is not empty and not null.
     * @param value Parameter that represents the value to check.
     * @param errorMsg Parameter that represents the error message to include inside of the exception where the value is empty or null.
     * @throws SignaturePolicyException If the value is empty or null.
     */
    private static void checkIsNotNullAndNotEmpty(String value, String errorMsg) throws SignaturePolicyException {
	if (!GenericUtilsCommons.assertStringValue(value)) {
	    LOGGER.error(errorMsg);
	    throw new SignaturePolicyException(errorMsg);
	}
    }

    /**
     * Method that checks if the signing mode of the CAdES-EPES signature is allowed by the signature policy defined on the properties file where
     * to configure the validation and generation of signatures with signature policies.
     * @param includeContent Parameter that indicates whether the document content is included in the signature (true) or is only referenced (false).
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation
     * and generation of signatures with signature policies.
     * * @param idClient Parameter that represents the client application identifier.
     * @return a boolean that indicates if the signing mode of the CAdES-EPES signature is allowed by the signature policy (true) or not (false).
     */
    public static boolean isValidASN1SigningModeByPolicy(boolean includeContent, String policyID, Properties properties, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG066));
	boolean result = true;
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }

	    try {
		// Comprobamos si el modo de firma es correcto
		validateCAdESEPESSigningMode(includeContent, policyID, policyProperties);
	    } catch (SignaturePolicyException e) {
		// En caso de excepción, el modo de firma no es correcto
		result = false;
	    }
	    return result;
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG067));
	}
    }

    /**
     * Method that checks if the signing mode of the XAdES-EPES signature is allowed by the signature policy defined on the properties file where
     * to configure the validation and generation of signatures with signature policies.
     * @param signingMode Parameter that represents the signing mode of the XAdES-EPES signature. The possible values are:
     * <ul>
     * <li>{@link UtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link UtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link UtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation
     * and generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @return a boolean that indicates if the signing mode of the XAdES-EPES signature is allowed by the signature policy (true) or not (false).
     */
    public static boolean isValidXMLSigningModeByPolicy(String signingMode, String policyID, Properties properties, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG066));
	boolean result = true;
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));
	    checkInputParameter(signingMode, Language.getResIntegra(ILogConstantKeys.SPM_LOG068));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }

	    try {
		// Comprobamos si el modo de firma es correcto
		validateXAdESEPESSigningMode(signingMode, policyID, policyProperties);
	    } catch (SignaturePolicyException e) {
		// En caso de excepción, el modo de firma no es correcto
		result = false;
	    }
	    return result;
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG067));
	}
    }

    /**
     * Method that checks if the URI of a hash algorithm is valid for certain signature policy.
     * @param uriAlgorithm Parameter that represents the URI of the hash algorithm.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @return a boolean that indicates if the URI of the hash algorithm is valid for the signature policy (true) or not (false).
     */
    public static boolean isValidXMLHashAlgorithmByPolicy(String uriAlgorithm, String policyID, Properties properties, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG033));
	boolean result = true;
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(uriAlgorithm, Language.getResIntegra(ILogConstantKeys.SPM_LOG032));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }
	    // Obtenemos una cadena con la lista de algoritmos de hash
	    // admitidos,
	    // delimitados con ',' como operador AND
	    String allowedHashAlgorithmsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_ALLOWED_HASH_ALGORITHM);

	    // En caso de que haya definidos algoritmos de hash admitidos
	    if (allowedHashAlgorithmsStr != null) {
		// Instanciamos una lista con los algoritmos de hash permitidos
		List<String> listAllowedHashAlgorithms = new ArrayList<String>();

		// Rellenamos las lista anterior
		retrieveListElementsFromString(allowedHashAlgorithmsStr, listAllowedHashAlgorithms, null, false);

		// Instanciamos una lista donde ubicar las URI de los algoritmos
		// de
		// hash permitidos
		List<String> listURIAllowedHashAlgorithms = new ArrayList<String>();

		// Recorremos la lista con los algoritmos de hash admitidos para
		// obtener la URI de cada uno
		for (String allowedHashAlgoritm: listAllowedHashAlgorithms) {
		    // Obtenemos la URI asociada al algoritmo de hash
		    String uriHashAlgorithm = (String) policyProperties.get(allowedHashAlgoritm);

		    // Comprobamos que la URI existe
		    if (uriHashAlgorithm != null && !uriHashAlgorithm.isEmpty()) {
			// Metemos la URI en la lista donde ubicar las URI de
			// los
			// algoritmos de hash permitidos
			listURIAllowedHashAlgorithms.add(uriHashAlgorithm);
		    }
		}
		// Comprobamos si la URI del algoritmo de hash indicado está
		// permitido o no
		if (!listURIAllowedHashAlgorithms.contains(uriAlgorithm)) {
		    result = false;
		}
	    }
	    return result;
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG034));
	}
    }

    /**
     * Method that checks if the OID of a hash algorithm is valid for certain signature policy.
     * @param digestAlgorithmId Parameter that represents the OID of the hash algorithm.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @return a boolean that indicates if the OID of the hash algorithm is valid for the signature policy (true) or not (false).
     */
    public static boolean isValidASN1HashAlgorithmByPolicy(AlgorithmIdentifier digestAlgorithmId, String policyID, Properties properties, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG033));
	boolean result = true;
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(digestAlgorithmId, Language.getResIntegra(ILogConstantKeys.SPM_LOG040));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }
	    // Obtenemos una cadena con la lista de algoritmos de hash
	    // admitidos,
	    // delimitados con ',' como operador AND
	    String allowedHashAlgorithmsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_ALLOWED_HASH_ALGORITHM);

	    // En caso de que haya definidos algoritmos de hash admitidos
	    if (allowedHashAlgorithmsStr != null) {
		// Instanciamos una lista con los algoritmos de hash permitidos
		List<String> listAllowedHashAlgorithms = new ArrayList<String>();

		// Rellenamos las lista anterior
		retrieveListElementsFromString(allowedHashAlgorithmsStr, listAllowedHashAlgorithms, null, false);

		// Instanciamos una lista donde ubicar los OIDs de los
		// algoritmos
		// de
		// hash permitidos
		List<String> listOIDAllowedHashAlgorithms = new ArrayList<String>();

		// Recorremos la lista con los algoritmos de hash admitidos para
		// obtener el OID de cada uno
		for (String allowedHashAlgoritm: listAllowedHashAlgorithms) {
		    // Obtenemos el OID asociado al algoritmo de hash
		    String oidHashAlgorithm = (String) policyProperties.get(allowedHashAlgoritm);

		    // Comprobamos que el OID existe
		    if (oidHashAlgorithm != null && !oidHashAlgorithm.isEmpty()) {
			// Metemos el OID en la lista donde ubicar los OIDs de
			// los
			// algoritmos de hash permitidos
			listOIDAllowedHashAlgorithms.add(oidHashAlgorithm);
		    }
		}
		// Comprobamos si el OID del algoritmo de hash indicado está
		// permitido o no
		if (!listOIDAllowedHashAlgorithms.contains(digestAlgorithmId.getAlgorithm().getId())) {
		    result = false;
		}
	    }
	    return result;
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG034));
	}
    }

    /**
     * Method that checks if the OID of a signature algorithm is valid for certain signature policy.
     * @param signAlgorithmId Parameter that represents the OID of the signature algorithm.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @return a boolean that indicates if the OID of the signature algorithm is valid for the signature policy (true) or not (false).
     */
    public static boolean isValidASN1SignAlgorithmByPolicy(AlgorithmIdentifier signAlgorithmId, String policyID, Properties properties, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG030));
	boolean result = true;
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(signAlgorithmId, Language.getResIntegra(ILogConstantKeys.SPM_LOG040));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }

	    // Obtenemos una cadena con la lista de algoritmos de firma
	    // admitidos,
	    // delimitados con ',' como operador AND
	    String allowedSignAlgorithmsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_ALLOWED_SIGN_ALGORITHM);

	    // En caso de que haya definidos algoritmos de firma admitidos
	    if (allowedSignAlgorithmsStr != null) {
		// Instanciamos una lista con los algoritmos de firma permitidos
		List<String> listAllowedSignAlgorithms = new ArrayList<String>();

		// Rellenamos las lista anterior
		retrieveListElementsFromString(allowedSignAlgorithmsStr, listAllowedSignAlgorithms, null, false);

		// Instanciamos una lista donde ubicar los OID de los algoritmos
		// de
		// firma permitidos
		List<String> listOIDAllowedSignAlgorithms = new ArrayList<String>();

		// Recorremos la lista con los algoritmos de firma admitidos
		// para
		// obtener el OID de cada uno
		for (String allowedSignAlgoritm: listAllowedSignAlgorithms) {
		    // Obtenemos el OID asociado al algoritmo de firma
		    String oidHashAlgorithm = (String) policyProperties.get(allowedSignAlgoritm);

		    // Comprobamos que el OID existe
		    if (oidHashAlgorithm != null && !oidHashAlgorithm.isEmpty()) {
			// Metemos el OID en la lista donde ubicar los OIDs de
			// los
			// algoritmos de firma permitidos
			listOIDAllowedSignAlgorithms.add(oidHashAlgorithm);
		    }
		}
		// Comprobamos si el OID del algoritmo de firma indicado está
		// permitido o no
		if (!listOIDAllowedSignAlgorithms.contains(signAlgorithmId.getAlgorithm().getId())) {
		    result = false;
		}
	    }
	    return result;
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG031));
	}
    }

    /**
     * Method that checks if the URI of a signature algorithm is valid for certain signature policy.
     * @param uriAlgorithm Parameter that represents the URI of the signature algorithm.
     * @param policyID Parameter that represents the identifier of the signature policy defined inside of the properties file where to configure the
     * validation and generation of signatures with signature policies.
     * @param properties Parameter that represents the set of properties defined inside of the properties file where to configure the validation and
     * generation of signatures with signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @return a boolean that indicates if the URI of the signature algorithm is valid for the signature policy (true) or not (false).
     */
    public static boolean isValidXMLSignAlgorithmByPolicy(String uriAlgorithm, String policyID, Properties properties, String idClient) {
	LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG030));
	boolean result = true;
	try {
	    // Comprobamos que se han indicado parámetros de entrada
	    checkInputParameter(uriAlgorithm, Language.getResIntegra(ILogConstantKeys.SPM_LOG032));
	    checkInputParameter(policyID, Language.getResIntegra(ILogConstantKeys.SPM_LOG003));

	    Properties policyProperties = properties;
	    if (policyProperties == null) {
		policyProperties = new IntegraProperties().getIntegraProperties(idClient);
	    }

	    // Obtenemos una cadena con la lista de algoritmos de firma
	    // admitidos,
	    // delimitados con ',' como operador AND
	    String allowedSignAlgorithmsStr = (String) policyProperties.get(policyID + ISignPolicyConstants.KEY_ALLOWED_SIGN_ALGORITHM);

	    // En caso de que haya definidos algoritmos de firma admitidos
	    if (allowedSignAlgorithmsStr != null) {
		// Instanciamos una lista con los algoritmos de firma permitidos
		List<String> listAllowedSignAlgorithms = new ArrayList<String>();

		// Rellenamos las lista anterior
		retrieveListElementsFromString(allowedSignAlgorithmsStr, listAllowedSignAlgorithms, null, false);

		// Instanciamos una lista donde ubicar las URI de los algoritmos
		// de
		// firma permitidos
		List<String> listURIAllowedSignAlgorithms = new ArrayList<String>();

		// Recorremos la lista con los algoritmos de firma admitidos
		// para
		// obtener la URI de cada uno
		for (String allowedSignAlgoritm: listAllowedSignAlgorithms) {
		    // Obtenemos la URI asociada al algoritmo de firma
		    String uriHashAlgorithm = (String) policyProperties.get(allowedSignAlgoritm);

		    // Comprobamos que la URI existe
		    if (uriHashAlgorithm != null && !uriHashAlgorithm.isEmpty()) {
			// Metemos la URI en la lista donde ubicar las URI de
			// los
			// algoritmos de firma permitidos
			listURIAllowedSignAlgorithms.add(uriHashAlgorithm);
		    }
		}
		// Comprobamos si la URI del algoritmo de firma indicado está
		// permitido o no
		if (!listURIAllowedSignAlgorithms.contains(uriAlgorithm)) {
		    result = false;
		}
	    }
	    return result;
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.SPM_LOG031));
	}

    }
}
