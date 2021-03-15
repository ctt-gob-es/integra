// Copyright (C) 2017 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.SignatureFormatDetector.java.</p>
 * <b>Description:</b><p>Class that contains all the functionality related to recognize the signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.signature;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.utils.UtilsSignatureCommons;
import es.gob.afirma.utils.UtilsSignatureOp;

/**
 * <p>Class that contains all the functionality related to recognize the signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public final class SignatureFormatDetectorXades implements ISignatureFormatDetector {

    /**
     * Constructor method for the class SignatureFormatDetector.java.
     */
    private SignatureFormatDetectorXades() {
    }

    /**
     * Method that obtains the format of the most advanced XML signature format contained inside of a signed XML document.
     * @param signature Parameter that represents the XML document to evaluate.
     * @return the most advanced XML signature format. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    public static String getSignatureFormat(byte[ ] signature) {
	// Comprobamos que se ha indicado el elemento a comprobar
	if (signature == null) {
	    throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.SFD_LOG001));
	}

	// Por defecto definimos que el formato no está reconocido
	String format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	if (SignatureFormatDetectorCommons.isXMLFormat(signature)) {
	    try {
		// Obtenemos el documento XML
		Document doc = UtilsSignatureCommons.getDocumentFromXML(signature);

		// Obtenemos la lista de elementos ds:Signature que no
		// correspondan
		// con un sello de tiempo XML
		List<Element> listSignatureElements = UtilsSignatureOp.getListSignatures(doc);

		// Comprobamos si alguna de las firmas del documento XML tiene
		// el
		// formato XAdES-EPES
		if (isXAdESEPES(listSignatureElements)) {
		    // Comprobamos si alguna de las firmas del documento XML
		    // tiene
		    // un formato Baseline, estableciendo que, al menos, el
		    // formato
		    // es XAdES-EPES
		    format = resolveXAdESBaselineFormat(ISignatureFormatDetector.FORMAT_XADES_EPES, listSignatureElements);

		    // Si ninguna de las firmas del documento XML tiene un
		    // formato
		    // Baseline, es decir, el formato por ahora es XAdES-EPES,
		    // comprobamos si posee un formato más avanzado no Baseline
		    if (format.equals(ISignatureFormatDetector.FORMAT_XADES_EPES)) {
			format = resolveXAdESNoBaselineFormat(ISignatureFormatDetector.FORMAT_XADES_EPES, listSignatureElements);
		    }

		}
		// Comprobamos si alguna de las firmas del documento XML tiene
		// el
		// formato XAdES-BES
		else if (isXAdESBES(listSignatureElements)) {
		    // Comprobamos si alguna de las firmas del documento XML
		    // tiene
		    // un formato Baseline, estableciendo que, al menos, el
		    // formato
		    // es XAdES-BES
		    format = resolveXAdESBaselineFormat(ISignatureFormatDetector.FORMAT_XADES_BES, listSignatureElements);

		    // Si ninguna de las firmas del documento XML tiene un
		    // formato
		    // Baseline, es decir, el formato por ahora es XAdES-BES,
		    // comprobamos si posee un formato más avanzado no Baseline
		    if (format.equals(ISignatureFormatDetector.FORMAT_XADES_BES)) {
			format = resolveXAdESNoBaselineFormat(ISignatureFormatDetector.FORMAT_XADES_BES, listSignatureElements);
		    }
		}

	    } catch (SigningException e) {
		format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	    }
	}
	return format;
    }

    /**
     * Method that obtains the format of the most advanced XML signature format of Baseline form contained inside of a signed XML document.
     * @param temporalFormat Parameter that represents the current most advanced XML signature format contained inside of a signed XML document. This parameter only allows one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures contained inside of the XML document.
     * @return the most advanced XML signature format of Baseline form contained inside of the signed XML document, or the current most advanced XML signature format contained inside of a signed XML document
     * if any of the signatures contained inside of the XML document has a Baseline form. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * </ul>
     */
    private static String resolveXAdESBaselineFormat(String temporalFormat, List<Element> listSignatureElements) {
	String format = temporalFormat;
	// Comprobamos si alguna de las firmas del documento XML tiene
	// el formato XAdES B-Level
	if (isXAdESBLevel(listSignatureElements)) {
	    // Indicamos que el formato por ahora es XAdES B-Level
	    format = ISignatureFormatDetector.FORMAT_XADES_B_LEVEL;

	    // Comprobamos si alguna de las firmas del documento XML
	    // tiene
	    // el formato XAdES T-Level
	    if (isXAdEST(listSignatureElements)) {
		// Indicamos que el formato por ahora es XAdES T-Level
		format = ISignatureFormatDetector.FORMAT_XADES_T_LEVEL;

		// Comprobamos si alguna de las firmas del documento XML
		// tiene
		// el formato XAdES LT-Level
		if (isXAdESLTLevel(listSignatureElements)) {
		    // Indicamos que el formato por ahora es XAdES
		    // LT-Level
		    format = ISignatureFormatDetector.FORMAT_XADES_LT_LEVEL;

		    // Comprobamos si alguna de las firmas del documento XML
		    // tiene
		    // el formato XAdES LTA-Level
		    if (isXAdESLTALevel(listSignatureElements)) {
			// Indicamos que el formato por ahora es XAdES
			// LTA-Level
			format = ISignatureFormatDetector.FORMAT_XADES_LTA_LEVEL;

		    }
		} else {
		    format = resolveXAdESNoBaselineFormat(format, listSignatureElements);
		}

	    }
	}
	else if (isXAdESBBLevel(listSignatureElements)) {
	    // Indicamos que el formato por ahora es XAdES B-B-Level
	    format = ISignatureFormatDetector.FORMAT_XADES_B_B_LEVEL;

	    // Comprobamos si alguna de las firmas del documento XML
	    // tiene
	    // el formato XAdES B-T-Level
	    if (isXAdEST(listSignatureElements)) {
		// Indicamos que el formato por ahora es XAdES B-T-Level
		format = ISignatureFormatDetector.FORMAT_XADES_B_T_LEVEL;

		// Comprobamos si alguna de las firmas del documento XML
		// tiene
		// el formato XAdES B-LT-Level
		if (isXAdESBLTLevel(listSignatureElements)) {
		    // Indicamos que el formato por ahora es XAdES
		    // B-LT-Level
		    format = ISignatureFormatDetector.FORMAT_XADES_B_LT_LEVEL;

		    // Comprobamos si alguna de las firmas del documento XML
		    // tiene
		    // el formato XAdES B-LTA-Level
		    if (isXAdESBLTALevel(listSignatureElements)) {
			// Indicamos que el formato por ahora es XAdES
			// B-LTA-Level
			format = ISignatureFormatDetector.FORMAT_XADES_B_LTA_LEVEL;

		    }
		} else {
		    format = resolveXAdESNoBaselineFormat(format, listSignatureElements);
		}

	    }
	}
	return format;
    }

    /**
     * Method that obtains the format of the most advanced XML signature format without Baseline form contained inside of a signed XML document.
     * @param temporalFormat Parameter that represents the current most advanced XML signature format contained inside of a signed XML document. This parameter only allows one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures contained inside of the XML document.
     * @return the most advanced XML signature format without Baseline form contained inside of the signed XML document. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * </ul>
     */
    private static String resolveXAdESNoBaselineFormat(String temporalFormat, List<Element> listSignatureElements) {
	String format = temporalFormat;

	// Comprobamos si alguna de las firmas del documento XML
	// tiene
	// el formato XAdES-A
	if (isXAdESA(listSignatureElements)) {
	    // Indicamos que el formato es XAdES-A
	    format = ISignatureFormatDetector.FORMAT_XADES_A;
	}
	// Comprobamos si alguna de las firmas del documento XML
	// tiene
	// el formato XAdES-XL1
	else if (isXAdESXL1(listSignatureElements)) {
	    // Indicamos que el formato es XAdES-XL1
	    format = ISignatureFormatDetector.FORMAT_XADES_XL1;
	}
	// Comprobamos si alguna de las firmas del documento XML
	// tiene
	// el formato XAdES-XL2
	else if (isXAdESXL2(listSignatureElements)) {
	    // Indicamos que el formato es XAdES-XL2
	    format = ISignatureFormatDetector.FORMAT_XADES_XL2;
	}
	// Comprobamos si alguna de las firmas del documento XML
	// tiene
	// el formato XAdES-X1
	else if (isXAdESX1(listSignatureElements)) {
	    // Indicamos que el formato es XAdES-X1
	    format = ISignatureFormatDetector.FORMAT_XADES_X1;
	}
	// Comprobamos si alguna de las firmas del documento XML
	// tiene
	// el formato XAdES-X2
	else if (isXAdESX2(listSignatureElements)) {
	    // Indicamos que el formato es XAdES-X2
	    format = ISignatureFormatDetector.FORMAT_XADES_X2;
	}
	// Comprobamos si alguna de las firmas del documento XML
	// tiene
	// el formato XAdES-C
	else if (isXAdESC(listSignatureElements)) {
	    // Indicamos que el formato es XAdES-C
	    format = ISignatureFormatDetector.FORMAT_XADES_C;
	}
	// Comprobamos si alguna de las firmas del documento XML
	// tiene
	// el formato XAdES-T
	else if (isXAdEST(listSignatureElements) && !format.equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
	    // Indicamos que el formato es XAdES-T
	    format = ISignatureFormatDetector.FORMAT_XADES_T;
	}
	return format;
    }

    /**
     * Method that obtains a child element of a parent element, both elements contained inside of a XML document.
     * @param parentElement Parameter that represents the parent element.
     * @param namespace Parameter that represents the namespace of the element to obtain.
     * @param elementName Parameter that represents the name of the element to obtain.
     * @return the found element, or <code>null</code> if the element hasn't been found.
     */
    private static Element getXMLElement(Element parentElement, String namespace, String elementName) {
	Element result = (Element) parentElement.getElementsByTagNameNS(namespace, elementName).item(0);
	if (result == null) {
	    result = (Element) parentElement.getElementsByTagName(elementName).item(0);
	}

	return result;
    }

    /**
     * Method that indicates if a XML signature contains the <code>xades:SignaturePolicyIdentifier</code> element.
     * @param dsSignature Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the XML signature contains the <code>xades:SignaturePolicyIdentifier</code> element (true) or not (false).
     */
    public static boolean hasSignaturePolicyIdentifier(Element dsSignature) {
	// Accedemos al elemento SignedProperties
	Element signedProperties = getXMLElement(dsSignature, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_PROPERTIES);
	if (signedProperties != null) {
	    // Accedemos al elemento SignedSignatureProperties
	    Element signedSignatureProperties = getXMLElement(signedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_SIGNATURE_PROPERTIES);
	    if (signedSignatureProperties != null) {
		// Se considera una firma con formato XAdES-EPES si
		// posee el
		// elemento SignaturePolicyIdentifier
		Element signaturePolicyIdentifier = getXMLElement(signedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNATURE_POLICY_IDENTIFIER);
		if (signaturePolicyIdentifier != null) {
		    return true;
		}
	    }
	}
	return false;
    }
    
    /**
     * Method that indicates if a XML signature contains the <code>xades141:SignaturePolicyStore</code> element.
     * @param dsSignature Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the XML signature contains the <code>xades141:SignaturePolicyStore</code> element (true) or not (false).
     */
    public static boolean hasSignaturePolicyStore(Element dsSignature) {
	// Accedemos al elemento UnsignedProperties
	Element unsignedProperties = getXMLElement(dsSignature, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {
		// Comprobamos la existencia del atributo <code>xades141:SignaturePolicyStore</code>.
		Element signaturePolicyStore = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_4_1_NAMESPACE, IXMLConstants.ELEMENT_SIGNATURE_POLICY_STORE);
		if (signaturePolicyStore != null) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:ArchiveTimeStamp</code> element</li>
     * or
     * <li><code>xadesv141:ArchiveTimeStamp</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of the list of XML signatures contains:
     * <ul>
     * <li>One <code>xades:ArchiveTimeStamp</code> element</li>
     * or
     * <li>One <code>xadesv141:ArchiveTimeStamp</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESLTALevel(List<Element> listSignatureElements) {
	return isXAdESA(listSignatureElements);
    }

    /**
     * Method that indicates if a signer has XAdES LTA-Level format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES LTA-Level format.
     */
    private static boolean isXAdESLTALevel(Element signatureElement) {
	return isXAdESA(signatureElement);
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains:
     * <ul>
     * <li>One <code>xades:CertificateValues</code> element and one <code>xades:RevocationValues</code> element</li>
     * or at least one
     * <li><code>xadesv141:TimeStampValidationData</code> element.</li>
     * </ul>
     * And it doesn't contain:
     * <ul>
     * <li>Any <code>xades:CompleteCertificateRefs</code> element</li>
     * and
     * <li>Any <code>xades:CompleteRevocationRefs</code> element</li>
     * and
     * <li>Any <code>xades:AttributeCertificateRefs</code> element</li>
     * and
     * <li>Any <code>xades:AttributeRevocationRefs</code> element</li>
     * and
     * <li>Any <code>xades:SigAndRefsTimeStamp</code> element</li>
     * and
     * <li>Any <code>xades:RefsOnlyTimeStamp</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of the list of XML signatures contains:
     * <ul>
     * <li>One <code>xades:CertificateValues</code> element and one <code>xades:RevocationValues</code> element</li>
     * or at least one
     * <li><code>xadesv141:TimeStampValidationData</code> element.</li>
     * </ul>
     * And it doesn't contain:
     * <ul>
     * <li>Any <code>xades:CompleteCertificateRefs</code> element</li>
     * and
     * <li>Any <code>xades:CompleteRevocationRefs</code> element</li>
     * and
     * <li>Any <code>xades:AttributeCertificateRefs</code> element</li>
     * and
     * <li>Any <code>xades:AttributeRevocationRefs</code> element</li>
     * and
     * <li>Any <code>xades:SigAndRefsTimeStamp</code> element</li>
     * and
     * <li>Any <code>xades:RefsOnlyTimeStamp</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESLTLevel(List<Element> listSignatureElements) {
	/* Una firma se considerará XAdES LT-Level si posee los elementos:
	 * > xades:CertificateValues y xades:RevocationValues
	 * > o xadesv141:TimeStampValidationData
	 * Y si no posee los elementos:
	 * > xades:CompleteCertificateRefs
	 * > xades:CompleteRevocationRefs
	 * > xades:AttributeCertificateRefs
	 * > xades:AttributeRevocationRefs
	 * > xades:SigAndRefsTimeStamp
	 * > xades:RefsOnlyTimeStamp
	 */
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESLTLevel(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES LT-Level format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES LT-Level format.
     */
    private static boolean isXAdESLTLevel(Element signatureElement) {
	/* Una firma se considerará XAdES LT-Level si posee los elementos:
	 * > xades:CertificateValues y xades:RevocationValues
	 * > o xadesv141:TimeStampValidationData
	 * Y si no posee los elementos:
	 * > xades:CompleteCertificateRefs
	 * > xades:CompleteRevocationRefs
	 * > xades:AttributeCertificateRefs
	 * > xades:AttributeRevocationRefs
	 * > xades:SigAndRefsTimeStamp
	 * > xades:RefsOnlyTimeStamp
	 */
	boolean hasCertificateValues = false;
	boolean hasRevocationValues = false;
	boolean hashTimeStampValidationData = false;
	boolean hasCompleteCertificateRefs = false;
	boolean hasCompleteRevocationRefs = false;
	boolean hasAttributeCertificateRefs = false;
	boolean hasAttributeRevocationRefs = false;
	boolean hasSigAndRefsTimeStamp = false;
	boolean hasRefsOnlyTimeStamp = false;

	// Accedemos al elemento xades:UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento xades:UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {

		// Comprobamos si contiene el elemento
		// xades:CertificateValues
		hasCertificateValues = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_CERTIFICATE_VALUES) != null;

		// Comprobamos si contiene el elemento
		// xades:RevocationValues
		hasCertificateValues = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REVOCATION_VALUES) != null;

		// Comprobamos si contiene el elemento
		// xadesv141:TimeStampValidationData
		hashTimeStampValidationData = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_4_1_NAMESPACE, IXMLConstants.ELEMENT_TIME_STAMP_VALIDATION_DATA) != null;

		// Comprobamos si contiene el elemento
		// xades:CompleteCertificateRefs
		hasCompleteCertificateRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COMPLETE_CERTIFICATE_REFS) != null;

		// Comprobamos si contiene el elemento
		// xades:CompleteRevocationRefs
		hasCompleteRevocationRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COMPLETE_REVOCATION_REFS) != null;

		// Comprobamos si contiene el elemento
		// xades:AttributeCertificateRefs
		hasAttributeCertificateRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ATTRIBUTE_CERTIFICATE_REFS) != null;

		// Comprobamos si contiene el elemento
		// xades:AttributeRevocationRefs
		hasAttributeRevocationRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ATTRIBUTE_REVOCATION_REFS) != null;

		// Comprobamos si contiene el elemento
		// xades:SigAndRefsTimeStamp
		hasSigAndRefsTimeStamp = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIG_AND_REFS_TIMESTAMP) != null;

		// Comprobamos si contiene el elemento
		// xades:RefsOnlyTimeStamp
		hasRefsOnlyTimeStamp = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REFS_ONLY_TIMESTAMP) != null;

		if (checkLTLevel(hasCertificateValues, hasRevocationValues, hashTimeStampValidationData, hasCompleteCertificateRefs, hasCompleteRevocationRefs, hasAttributeCertificateRefs, hasAttributeRevocationRefs, hasSigAndRefsTimeStamp, hasRefsOnlyTimeStamp)) {
		    return true;
		}
	    }
	}
	return false;
    }
    
    /**
     * Method that indicates if at least one of a list of XML signatures has XAdES B-LT-Level format.
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if al leasr one element meets the requirements of the
     * XAdES B-LT-Level profile.
     */
    private static boolean isXAdESBLTLevel(List<Element> listSignatureElements) {
	/* Una firma se considerará XAdES LT-Level si posee los elementos:
	 * > xades:CertificateValues y xades:RevocationValues
	 * > o xadesv141:TimeStampValidationData
	 * Y si no posee los elementos:
	 * > xades:CompleteCertificateRefs
	 * > xades:CompleteCertificateRefsV2
	 * > xades:CompleteRevocationRefs
	 * > xades:AttributeCertificateRefs
	 * > xades:AttributeCertificateRefsV2
	 * > xades:AttributeRevocationRefs
	 * > xades:SigAndRefsTimeStamp
	 * > xades:SigAndRefsTimeStampV2
	 * > xades:RefsOnlyTimeStamp
	 * > xades:RefsOnlyTimeStampV2
	 */
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESBLTLevel(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signature has XAdES B-LT-Level format. The requirements are:
     * <ul>
     * <li>Contain one <code>xades:CertificateValues</code> element and one <code>xades:RevocationValues</code> element</li>
     * or at least one
     * <li><code>xadesv141:TimeStampValidationData</code> element.</li>
     * </ul>
     * And it doesn't contain:
     * <ul>
     * <li>Any <code>xades:CompleteCertificateRefs</code> element</li>
     * and
     * <li>Any <code>xades:CompleteCertificateRefsV2</code> element</li>
     * and
     * <li>Any <code>xades:CompleteRevocationRefs</code> element</li>
     * and
     * <li>Any <code>xades:AttributeCertificateRefs</code> element</li>
     * and
     * <li>Any <code>xades:AttributeCertificateRefsV2</code> element</li>
     * and
     * <li>Any <code>xades:AttributeRevocationRefs</code> element</li>
     * and
     * <li>Any <code>xades:SigAndRefsTimeStamp</code> element</li>
     * and
     * <li>Any <code>xades:SigAndRefsTimeStampV2</code> element</li>
     * and
     * <li>Any <code>xades:RefsOnlyTimeStamp</code> element</li>
     * and
     * <li>Any <code>xades:RefsOnlyTimeStampV2</code> element.</li>
     * </ul>
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES LT-Level format.
     */
    private static boolean isXAdESBLTLevel(Element signatureElement) {
	/* Una firma se considerará XAdES B-LT-Level si posee los elementos:
	 * > xades:CertificateValues y xades:RevocationValues
	 * > o xadesv141:TimeStampValidationData
	 * Y si no posee los elementos:
	 * > xades:CompleteCertificateRefs
	 * > xades:CompleteCertificateRefsV2
	 * > xades:CompleteRevocationRefs
	 * > xades:AttributeCertificateRefs
	 * > xades:AttributeCertificateRefsV2
	 * > xades:AttributeRevocationRefs
	 * > xades:SigAndRefsTimeStamp
	 * > xades:SigAndRefsTimeStampV2
	 * > xades:RefsOnlyTimeStamp
	 * > xades:RefsOnlyTimeStampV2
	 */
	boolean hasCertificateValues = false;
	boolean hasRevocationValues = false;
	boolean hashTimeStampValidationData = false;
	boolean hasCompleteCertificateRefs = false;
	boolean hasCompleteCertificateRefsV2 = false;
	boolean hasCompleteRevocationRefs = false;
	boolean hasAttributeCertificateRefs = false;
	boolean hasAttributeCertificateRefsV2 = false;
	boolean hasAttributeRevocationRefs = false;
	boolean hasSigAndRefsTimeStamp = false;
	boolean hasSigAndRefsTimeStampV2 = false;
	boolean hasRefsOnlyTimeStamp = false;
	boolean hasRefsOnlyTimeStampV2 = false;

	// Accedemos al elemento xades:UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento xades:UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {

		// Comprobamos si contiene el elemento
		// xades:CertificateValues
		hasCertificateValues = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_CERTIFICATE_VALUES) != null;

		// Comprobamos si contiene el elemento
		// xades:RevocationValues
		hasCertificateValues = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REVOCATION_VALUES) != null;

		// Comprobamos si contiene el elemento
		// xadesv141:TimeStampValidationData
		hashTimeStampValidationData = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_4_1_NAMESPACE, IXMLConstants.ELEMENT_TIME_STAMP_VALIDATION_DATA) != null;

		// Comprobamos si contiene el elemento
		// xades:CompleteCertificateRefs
		hasCompleteCertificateRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COMPLETE_CERTIFICATE_REFS) != null;
		
		// Comprobamos si contiene el elemento
		// xades:CompleteCertificateRefsV2
		hasCompleteCertificateRefsV2 = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COMPLETE_CERTIFICATE_REFS_V2) != null;

		// Comprobamos si contiene el elemento
		// xades:CompleteRevocationRefs
		hasCompleteRevocationRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COMPLETE_REVOCATION_REFS) != null;

		// Comprobamos si contiene el elemento
		// xades:AttributeCertificateRefs
		hasAttributeCertificateRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ATTRIBUTE_CERTIFICATE_REFS) != null;

		// Comprobamos si contiene el elemento
		// xades:AttributeCertificateRefsV2
		hasAttributeCertificateRefsV2 = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ATTRIBUTE_CERTIFICATE_REFS_V2) != null;

		// Comprobamos si contiene el elemento
		// xades:AttributeRevocationRefs
		hasAttributeRevocationRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_ATTRIBUTE_REVOCATION_REFS) != null;

		// Comprobamos si contiene el elemento
		// xades:SigAndRefsTimeStamp
		hasSigAndRefsTimeStamp = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIG_AND_REFS_TIMESTAMP) != null;

		// Comprobamos si contiene el elemento
		// xades:SigAndRefsTimeStamp
		hasSigAndRefsTimeStampV2 = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIG_AND_REFS_TIMESTAMP_V2) != null;
		
		// Comprobamos si contiene el elemento
		// xades:RefsOnlyTimeStamp
		hasRefsOnlyTimeStamp = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REFS_ONLY_TIMESTAMP) != null;
		
		// Comprobamos si contiene el elemento
		// xades:RefsOnlyTimeStampV2
		hasRefsOnlyTimeStampV2 = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REFS_ONLY_TIMESTAMP_V2) != null;

		if (checkBLTLevel(hasCertificateValues, hasRevocationValues, hashTimeStampValidationData, hasCompleteCertificateRefs, hasCompleteCertificateRefsV2, hasCompleteRevocationRefs, hasAttributeCertificateRefs, hasAttributeCertificateRefsV2, hasAttributeRevocationRefs, hasSigAndRefsTimeStamp, hasSigAndRefsTimeStampV2, hasRefsOnlyTimeStamp, hasRefsOnlyTimeStampV2)) {
		    return true;
		}
	    }
	}
	return false;
    }
    
    /**
     * Method that indicates if at least one of a list of XML signatures has XAdES B-LTA-Level format.
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if al leasr one element meets the requirements of the
     * XAdES B-LTA-Level profile.
     */
    private static boolean isXAdESBLTALevel(List<Element> listSignatureElements) {
	/* Una firma se considerará XAdES B-LTA-Level si posee el elemento:
	 * > xadesv141:ArchiveTimeStamp
	 * Y si no posee el elemento:
	 * > xades:ArchiveTimeStamp
	 */
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESBLTALevel(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }
    
    /**
     * Method that indicates if a signature has XAdES B-LT-Level format. The requirements are:
     * <ul>
     * <li>Contain one <code>xadesv141:ArchiveTimeStamp</code> element.</li>
     * <li>And it doesn't contain any <code>ArchiveTimeStamp</code> element.</li>
     * </ul>
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES LT-Level format.
     */
    private static boolean isXAdESBLTALevel(Element signatureElement) {
	
	// Accedemos al elemento xades:UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento xades:UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {
		// Obtenemos el conjunto de hijos del elemento
		// xades:UnsignedSignatureProperties
		NodeList nl = unsignedSignatureProperties.getChildNodes();

		// Recorremos el conjunto de elementos hijos comprobando que no haya ningun
		boolean anyXadES141TimeStamp = false;
		for (int i = 0; i < nl.getLength(); i++) {
		    if (nl.item(i).getNodeType() == Node.ELEMENT_NODE && nl.item(i).getLocalName().equals(IXMLConstants.ELEMENT_ARCHIVE_TIMESTAMP)) {
			// Si encontramos al menos un sello de XAdES 1.3.2, la firma no es B-LTA Level
			if (IXMLConstants.XADES_1_3_2_NAMESPACE.equals(nl.item(i).getNamespaceURI())) {
			    return false;
			}
			// Si encontramos al menos un sello de XAdES 1.4.1, la firma podria ser B-LTA Level
			else if (IXMLConstants.XADES_1_4_1_NAMESPACE.equals(nl.item(i).getNamespaceURI())) {
			    anyXadES141TimeStamp = true;
			}
		    }
		}
		return anyXadES141TimeStamp;
	    }
	}
	return false;
    }

    /**
     * Method that indicates if the input parameters has the values associated to a XAdES LT-Level signature.
     * @param hasCertificateValues Parameter that indicates if a XML signature contains at least one <code>xades:CertificateValues</code> element.
     * @param hasRevocationValues Parameter that indicates if a XML signature contains at least one <code>xades:RevocationValues</code> element.
     * @param hashTimeStampValidationData Parameter that indicates if a XML signature contains at least one <code>xades:RevocationValues</code> element.
     * @param hasCompleteCertificateRefs Parameter that indicates if a XML signature contains at least one <code>xades:CompleteCertificateRefs</code> element.
     * @param hasCompleteRevocationRefs Parameter that indicates if a XML signature contains at least one <code>xades:CompleteRevocationRefs</code> element.
     * @param hasAttributeCertificateRefs Parameter that indicates if a XML signature contains at least one <code>xades:AttributeCertificateRefs</code> element.
     * @param hasAttributeRevocationRefs Parameter that indicates if a XML signature contains at least one <code>xades:AttributeRevocationRefs</code> element.
     * @param hasSigAndRefsTimeStamp Parameter that indicates if a XML signature contains at least one <code>xades:SigAndRefsTimeStamp</code> element.
     * @param hasRefsOnlyTimeStamp Parameter that indicates if a XML signature contains at least one <code>xades:RefsOnlyTimeStamp</code> element.
     * @return a boolean that indicates if a XML signature:
     * <ul>
     * <li>Contains the <code>xades:CertificateValues</code> element and the <code>xades:RevocationValues</code> element</li>
     * or
     * <li>contains the <code>xadesv141:TimeStampValidationData</code> element</li>
     * and doesn't contain
     * <li>the <code>xades:CompleteCertificateRefs</code> element</li>
     * and
     * <li>the <code>xades:CompleteRevocationRefs</code> element</li>
     * and
     * <li>the <code>xades:AttributeCertificateRefs</code> element</li>
     * and
     * <li>the <code>xades:AttributeRevocationRefs</code> element</li>
     * and
     * <li>the <code>xades:SigAndRefsTimeStamp</code> element</li>
     * and
     * <li>the <code>xades:RefsOnlyTimeStamp</code> element.</li>
     * </ul>
     */
    private static boolean checkLTLevel(boolean hasCertificateValues, boolean hasRevocationValues, boolean hashTimeStampValidationData, boolean hasCompleteCertificateRefs, boolean hasCompleteRevocationRefs, boolean hasAttributeCertificateRefs, boolean hasAttributeRevocationRefs, boolean hasSigAndRefsTimeStamp, boolean hasRefsOnlyTimeStamp) {
	// CHECKSTYLE:OFF expresion complexity needed
	if ((hasCertificateValues && hasRevocationValues || hashTimeStampValidationData) && !hasCompleteCertificateRefs && !hasCompleteRevocationRefs && !hasAttributeCertificateRefs && !hasAttributeRevocationRefs && !hasSigAndRefsTimeStamp && !hasRefsOnlyTimeStamp) {
	    // CHECKSTYLE:ON
	    return true;
	}
	return false;
    }
    
    /**
     * Method that indicates if the input parameters has the values associated to a XAdES LT-Level signature.
     * @param hasCertificateValues Parameter that indicates if a XML signature contains at least one <code>xades:CertificateValues</code> element.
     * @param hasRevocationValues Parameter that indicates if a XML signature contains at least one <code>xades:RevocationValues</code> element.
     * @param hashTimeStampValidationData Parameter that indicates if a XML signature contains at least one <code>xades:RevocationValues</code> element.
     * @param hasCompleteCertificateRefs Parameter that indicates if a XML signature contains at least one <code>xades:CompleteCertificateRefs</code> element.
     * @param hasCompleteCertificateRefsV2 Parameter that indicates if a XML signature contains at least one <code>xades:CompleteCertificateRefsV2</code> element.
     * @param hasCompleteRevocationRefs Parameter that indicates if a XML signature contains at least one <code>xades:CompleteRevocationRefs</code> element.
     * @param hasAttributeCertificateRefs Parameter that indicates if a XML signature contains at least one <code>xades:AttributeCertificateRefs</code> element.
     * @param hasAttributeCertificateRefsV2 Parameter that indicates if a XML signature contains at least one <code>xades:AttributeCertificateRefsV2</code> element.
     * @param hasAttributeRevocationRefs Parameter that indicates if a XML signature contains at least one <code>xades:AttributeRevocationRefs</code> element.
     * @param hasSigAndRefsTimeStamp Parameter that indicates if a XML signature contains at least one <code>xades:SigAndRefsTimeStamp</code> element.
     * @param hasSigAndRefsTimeStampV2 Parameter that indicates if a XML signature contains at least one <code>xades:SigAndRefsTimeStampV2</code> element.
     * @param hasRefsOnlyTimeStamp Parameter that indicates if a XML signature contains at least one <code>xades:RefsOnlyTimeStamp</code> element.
     * @param hasRefsOnlyTimeStampV2 Parameter that indicates if a XML signature contains at least one <code>xades:RefsOnlyTimeStampV2</code> element.
     * @return a boolean that indicates if a XML signature:
     * <ul>
     * <li>Contains the <code>xades:CertificateValues</code> element and the <code>xades:RevocationValues</code> element</li>
     * or
     * <li>contains the <code>xadesv141:TimeStampValidationData</code> element</li>
     * and doesn't contain
     * <li>Any <code>xades:CompleteCertificateRefs</code> element</li>
     * and
     * <li>Any <code>xades:CompleteCertificateRefsV2</code> element</li>
     * and
     * <li>Any <code>xades:CompleteRevocationRefs</code> element</li>
     * and
     * <li>Any <code>xades:AttributeCertificateRefs</code> element</li>
     * and
     * <li>Any <code>xades:AttributeCertificateRefsV2</code> element</li>
     * and
     * <li>Any <code>xades:AttributeRevocationRefs</code> element</li>
     * and
     * <li>Any <code>xades:SigAndRefsTimeStamp</code> element</li>
     * and
     * <li>Any <code>xades:SigAndRefsTimeStampV2</code> element</li>
     * and
     * <li>Any <code>xades:RefsOnlyTimeStamp</code> element</li>
     * and
     * <li>Any <code>xades:RefsOnlyTimeStampV2</code> element.</li>
     * </ul>
     */
    private static boolean checkBLTLevel(boolean hasCertificateValues, boolean hasRevocationValues, boolean hashTimeStampValidationData, boolean hasCompleteCertificateRefs, boolean hasCompleteCertificateRefsV2, boolean hasCompleteRevocationRefs, boolean hasAttributeCertificateRefs, boolean hasAttributeCertificateRefsV2, boolean hasAttributeRevocationRefs, boolean hasSigAndRefsTimeStamp, boolean hasSigAndRefsTimeStampV2, boolean hasRefsOnlyTimeStamp, boolean hasRefsOnlyTimeStampV2) {
	// CHECKSTYLE:OFF expresion complexity needed
	if ((hasCertificateValues && hasRevocationValues || hashTimeStampValidationData) && !hasCompleteCertificateRefs && !hasCompleteCertificateRefsV2 && !hasCompleteRevocationRefs && !hasAttributeCertificateRefs && !hasAttributeCertificateRefsV2 && !hasAttributeRevocationRefs && !hasSigAndRefsTimeStamp && !hasSigAndRefsTimeStampV2 && !hasRefsOnlyTimeStamp && !hasRefsOnlyTimeStampV2) {
	    // CHECKSTYLE:ON
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li>One <code>xades:SigningCertificate</code> element</li>
     * and
     * <li>One <code>xades:SigningTime</code> element</li>
     * and
     * <li>One <code>xades:DataObjectFormat</code> element</li>
     * and it doesn't contain any:
     * <li>One <code>xades:QualifyingPropertiesReference</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of the list of XML signatures contains:
     * <ul>
     * <li>One <code>xades:SigningCertificate</code> element</li>
     * and
     * <li>One <code>xades:SigningTime</code> element</li>
     * and
     * <li>One <code>xades:DataObjectFormat</code> element</li>
     * and it doesn't contain any:
     * <li>One <code>xades:QualifyingPropertiesReference</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESBLevel(List<Element> listSignatureElements) {
	/* Una firma se considerará XAdES B-Level si posee los elementos:
	 * > xades:SigningCertificate
	 * > xades:SigningTime
	 * > xades:DataObjectFormat
	 * Y si no posee el elemento:
	 * > xades:QualifyingPropertiesReference
	 */
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		return isXAdESBLevel(signatureElement);
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES B-Level format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES B-Level format.
     */
    private static boolean isXAdESBLevel(Element signatureElement) {
	/* Un firmante se considerará XAdES B-Level si posee los elementos:
	 * > xades:SigningCertificate
	 * > xades:SigningTime
	 * > xades:DataObjectFormat (incluyendo el elemento xades:MimeType)
	 * Y si no posee el elemento:
	 * > xades:QualifyingPropertiesReference
	 */
	boolean hasSigningCertificate = false;
	boolean hasSigningTime = false;
	boolean hasDataObjectFormat = false;
	boolean hasMimeType = false;

	// Comprobamos que la firma no contiene el elemento
	// xades:QualifyingPropertiesReference
	if (signatureElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_QUALIFYING_PROPERTIES_REFERENCE).getLength() == 0) {
	    // Accedemos al elemento xades:SignedProperties
	    Element signedPropertiesElement = null;
	    if (signatureElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_PROPERTIES).getLength() > 0) {
		signedPropertiesElement = (Element) signatureElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_PROPERTIES).item(0);

		// Accedemos al elemento xades:SignedSignatureProperties
		Element signedSignaturePropertiesElement = null;
		if (signedPropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_SIGNATURE_PROPERTIES).getLength() > 0) {
		    signedSignaturePropertiesElement = (Element) signatureElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_SIGNATURE_PROPERTIES).item(0);

		    // Comprobamos si el elemento
		    // xades:SignedSignatureProperties tiene
		    // xades:SigningCertificate como uno de sus hijos
		    hasSigningCertificate = signedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNING_CERTIFICATE).getLength() > 0;

		    // Comprobamos si el elemento
		    // xades:SignedSignatureProperties tiene
		    // xades:SigningTime como uno de sus hijos
		    hasSigningTime = signedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNING_TIME).getLength() > 0;
		}
		// Accedemos al elemento
		// xades:SignedDataObjectProperties
		Element signedDataObjectPropertiesElement = null;
		if (signedPropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_DATA_OBJECT_PROPERTIES).getLength() > 0) {
		    signedDataObjectPropertiesElement = (Element) signedPropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_DATA_OBJECT_PROPERTIES).item(0);

		    // Comprobamos si el elemento
		    // xades:SignedDataObjectProperties tiene
		    // xades:DataObjectFormat como uno de sus hijos
		    Element dataObjectFormatElement = getXMLElement(signedDataObjectPropertiesElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_DATA_OBJECT_FORMAT);

		    hasDataObjectFormat = dataObjectFormatElement != null;
		    if (dataObjectFormatElement != null) {
			hasDataObjectFormat = true;

			// Comprobamos si el elemento
			// xades:DataObjectFormat tiene
			// xades:MimeType como uno de sus hijos
			hasMimeType = dataObjectFormatElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_MIME_TYPE).getLength() > 0;
		    }
		}
		if (hasSigningTime && hasSigningCertificate && hasDataObjectFormat && hasMimeType) {
		    return true;
		}
	    }
	}
	return false;
    }
    
    /**
     * Method that indicates if at least one of a list of XML signatures meets the requirements
     * of XAdES B-B-Level profile.
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of the list of XML signatures meets the requirements
     * of XAdES B-B-Level profile.
     */
    private static boolean isXAdESBBLevel(List<Element> listSignatureElements) {
	/* Una firma se considerará XAdES B-Level si posee los elementos:
	 * > xades:SigningCertificateV2
	 * > xades:SigningTime
	 * > xades:DataObjectFormat (incluyendo el elemento xades:MimeType)
	 * Y si no posee:
	 * > xades:QualifyingPropertiesReference
	 * > xades:SigningCertificate
	 * > xades:SignerRole
	 * > xades:SignatureProductionPlace
	 */
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		return isXAdESBBLevel(signatureElement);
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signature contains at least:
     * <ul>
     * <li>One <code>xades:SigningCertificateV2</code> element</li>
     * and
     * <li>One <code>xades:SigningTime</code> element</li>
     * and
     * <li>One <code>xades:DataObjectFormat</code> element</li>
     * and it doesn't contain any:
     * <li><code>xades:QualifyingPropertiesReference</code> element</li>
     * or
     * <li><code>xades:SigningCertificate</code> element</li>
     * or
     * <li><code>xades:SignerRole</code> element</li>
     * or
     * <li><code>xades:SignatureProductionPlace</code> element.</li>
     * </ul>
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES B-Level format.
     */
    private static boolean isXAdESBBLevel(Element signatureElement) {
	/* Un firmante se considerará XAdES B-B-Level si posee los elementos:
	 * > xades:SigningCertificateV2
	 * > xades:SigningTime
	 * > xades:DataObjectFormat (incluyendo el elemento xades:MimeType)
	 * Y si no posee:
	 * > xades:QualifyingPropertiesReference
	 * > xades:SigningCertificate
	 * > xades:SignerRole
	 * > xades:SignatureProductionPlace
	 */
	boolean hasSigningCertificate = false;
	boolean hasSigningCertificateV2 = false;
	boolean hasSignerRole = false;
	boolean hasSignatureProductionPlace = false;
	boolean hasSigningTime = false;
	boolean hasDataObjectFormat = false;
	boolean hasMimeType = false;

	// Comprobamos que la firma no contiene el elemento
	// xades:QualifyingPropertiesReference
	if (signatureElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_QUALIFYING_PROPERTIES_REFERENCE).getLength() == 0) {
	    // Accedemos al elemento xades:SignedProperties
	    Element signedPropertiesElement = null;
	    if (signatureElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_PROPERTIES).getLength() > 0) {
		signedPropertiesElement = (Element) signatureElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_PROPERTIES).item(0);

		// Accedemos al elemento xades:SignedSignatureProperties
		Element signedSignaturePropertiesElement = null;
		if (signedPropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_SIGNATURE_PROPERTIES).getLength() > 0) {
		    signedSignaturePropertiesElement = (Element) signatureElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_SIGNATURE_PROPERTIES).item(0);

		    // Comprobamos si tiene xades:SigningCertificate como uno de sus hijos
		    hasSigningCertificate = signedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNING_CERTIFICATE).getLength() > 0;
		    
		    // Comprobamos si tiene xades:SigningCertificateV2 como uno de sus hijos
		    hasSigningCertificateV2 = signedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNING_CERTIFICATE_V2).getLength() > 0;
		    
		    // Comprobamos si tiene xades:SignerRole como uno de sus hijos
		    hasSignerRole = signedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNER_ROLE).getLength() > 0;
		    
		    // Comprobamos si tiene xades:SignatureProductionPlace como uno de sus hijos
		    hasSignatureProductionPlace = signedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNATURE_PRODUCTION_PLACE).getLength() > 0;

		    // Comprobamos si el elemento
		    // xades:SignedSignatureProperties tiene
		    // xades:SigningTime como uno de sus hijos
		    hasSigningTime = signedSignaturePropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNING_TIME).getLength() > 0;
		}
		// Accedemos al elemento
		// xades:SignedDataObjectProperties
		Element signedDataObjectPropertiesElement = null;
		if (signedPropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_DATA_OBJECT_PROPERTIES).getLength() > 0) {
		    signedDataObjectPropertiesElement = (Element) signedPropertiesElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNED_DATA_OBJECT_PROPERTIES).item(0);

		    // Comprobamos si el elemento
		    // xades:SignedDataObjectProperties tiene
		    // xades:DataObjectFormat como uno de sus hijos
		    Element dataObjectFormatElement = getXMLElement(signedDataObjectPropertiesElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_DATA_OBJECT_FORMAT);

		    hasDataObjectFormat = dataObjectFormatElement != null;
		    if (dataObjectFormatElement != null) {
			hasDataObjectFormat = true;

			// Comprobamos si el elemento
			// xades:DataObjectFormat tiene
			// xades:MimeType como uno de sus hijos
			hasMimeType = dataObjectFormatElement.getElementsByTagNameNS(IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_MIME_TYPE).getLength() > 0;
		    }
		}
		if (hasSigningTime && hasSigningCertificateV2 && hasDataObjectFormat && hasMimeType && !hasSigningCertificate && !hasSignerRole && !hasSignatureProductionPlace) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li>One <code>xades:ArchiveTimeStamp</code> element</li>
     * or
     * <li>One <code>xadesv141:ArchiveTimeStamp</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of the list of XML signatures contains:
     * <ul>
     * <li>One <code>xades:ArchiveTimeStamp</code> element</li>
     * or
     * <li>One <code>xadesv141:ArchiveTimeStamp</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESA(List<Element> listSignatureElements) {
	/* Una firma se considerará XAdES LTA-Level si posee al menos uno de los siguientes elementos:
	 * > xades:ArchiveTimeStamp
	 * > xadesv141:ArchiveTimeStamp
	 */
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESA(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES-A format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES-A format.
     */
    private static boolean isXAdESA(Element signatureElement) {
	/* Una firma se considerará XAdES LTA-Level si posee al menos uno de los siguientes elementos:
	 * > xades:ArchiveTimeStamp
	 * > xadesv141:ArchiveTimeStamp
	 */
	// Accedemos al elemento xades:UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento xades:UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {
		// Obtenemos el conjunto de hijos del elemento
		// xades:UnsignedSignatureProperties
		NodeList nl = unsignedSignatureProperties.getChildNodes();

		// Recorremos el conjunto de elementos hijos
		for (int i = 0; i < nl.getLength(); i++) {
		    if (nl.item(i).getNodeType() == Node.ELEMENT_NODE && nl.item(i).getLocalName().equals(IXMLConstants.ELEMENT_ARCHIVE_TIMESTAMP)) {
			return true;
		    }
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:SigAndRefsTimeStamp</code> element</li>
     * and
     * <li>One <code>xades:CertificateValues</code> element</li>
     * and
     * <li>One <code>xades:RevocationValues</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:SigAndRefsTimeStamp</code> element</li>
     * and
     * <li>One <code>xades:CertificateValues</code> element</li>
     * and
     * <li>One <code>xades:RevocationValues</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESXL1(List<Element> listSignatureElements) {
	// Si el documento XML posee elementos ds:Signature
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESXL1(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES-XL1 format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES-XL1 format.
     */
    private static boolean isXAdESXL1(Element signatureElement) {
	// Accedemos al elemento UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {
		// Se considera una firma con formato XAdES-XL1 si posee
		// los
		// elementos SigAndRefsTimeStamp, CertificateValues y
		// RevocationValues
		Element sigAndRefsTimeStamp = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIG_AND_REFS_TIMESTAMP);
		Element certificateValues = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_CERTIFICATE_VALUES);
		Element revocationValues = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REVOCATION_VALUES);
		if (sigAndRefsTimeStamp != null && certificateValues != null && revocationValues != null) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:RefsOnlyTimeStamp</code> element</li>
     * and
     * <li>One <code>xades:CertificateValues</code> element</li>
     * and
     * <li>One <code>xades:RevocationValues</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:RefsOnlyTimeStamp</code> element</li>
     * and
     * <li>One <code>xades:CertificateValues</code> element</li>
     * and
     * <li>One <code>xades:RevocationValues</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESXL2(List<Element> listSignatureElements) {
	// Si el documento XML posee elementos ds:Signature
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESXL2(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES-XL2 format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES-XL2 format.
     */
    private static boolean isXAdESXL2(Element signatureElement) {
	// Accedemos al elemento UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {
		// Se considera una firma con formato XAdES-XL2 si posee
		// los
		// elementos RefsOnlyTimeStamp, CertificateValues y
		// RevocationValues
		Element refsOnlyTimeStamp = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REFS_ONLY_TIMESTAMP);
		Element certificateValues = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_CERTIFICATE_VALUES);
		Element revocationValues = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REVOCATION_VALUES);
		if (refsOnlyTimeStamp != null && certificateValues != null && revocationValues != null) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:SigAndRefsTimeStamp</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:SigAndRefsTimeStamp</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESX1(List<Element> listSignatureElements) {
	// Si el documento XML posee elementos ds:Signature
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESX1(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES-X1 format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES-X1 format.
     */
    private static boolean isXAdESX1(Element signatureElement) {
	// Accedemos al elemento UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {
		// Se considera una firma con formato XAdES-X1 si posee
		// el
		// elemento SigAndRefsTimeStamp
		Element sigAndRefsTimeStamp = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIG_AND_REFS_TIMESTAMP);
		if (sigAndRefsTimeStamp != null) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:RefsOnlyTimeStamp</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:RefsOnlyTimeStamp</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESX2(List<Element> listSignatureElements) {
	// Si el documento XML posee elementos ds:Signature
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESX2(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES-X2 format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES-X2 format.
     */
    private static boolean isXAdESX2(Element signatureElement) {
	// Accedemos al elemento UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {
		// Se considera una firma con formato XAdES-X2 si posee
		// el
		// elemento RefsOnlyTimeStamp
		Element refsOnlyTimeStamp = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_REFS_ONLY_TIMESTAMP);
		if (refsOnlyTimeStamp != null) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:CompleteCertificateRefs</code> element</li>
     * and
     * <li>One <code>xades:CompleteRevocationRefs</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:CompleteCertificateRefs</code> element</li>
     * and
     * <li>One <code>xades:CompleteRevocationRefs</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESC(List<Element> listSignatureElements) {
	// Si el documento XML posee elementos ds:Signature
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdESC(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES-C format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES-C format.
     */
    private static boolean isXAdESC(Element signatureElement) {
	// Accedemos al elemento UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento UnsignedSignatureProperties
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null) {
		// Se considera una firma con formato XAdES-C si posee
		// los
		// elementos CompleteCertificateRefs y
		// CompleteRevocationRefs
		Element completeCertificateRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COMPLETE_CERTIFICATE_REFS);
		Element completeRevocationRefs = getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_COMPLETE_REVOCATION_REFS);
		if (completeCertificateRefs != null && completeRevocationRefs != null) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:SignaturePolicyIdentifier</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:SignaturePolicyIdentifier</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESEPES(List<Element> listSignatureElements) {
	// Si el documento XML posee elementos ds:Signature
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		// Comprobamos si el firmante posee el elemento
		// xades:SignaturePolicyIdentifier
		if (hasSignaturePolicyIdentifier(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:QualifyingProperties</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:QualifyingProperties</code> element.</li>
     * </ul>
     */
    private static boolean isXAdESBES(List<Element> listSignatureElements) {
	// Si el documento XML posee elementos ds:Signature
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		// Se considera una firma con formato XAdES-BES si posee el
		// elemento QualifyingProperties
		if (getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_QUALIFIYING_PROPERTIES) != null) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES B-Level format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES B-Level format.
     */
    private static boolean isXAdESBES(Element signatureElement) {
	// Se considera una firma con formato XAdES-BES si posee el
	// elemento QualifyingProperties
	if (getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_QUALIFIYING_PROPERTIES) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:SignatureTimeStamp</code> element.</li>
     * </ul>
     * @param listSignatureElements Parameter that represents the list of signatures.
     * @return a boolean that indicates if at least one of a list of XML signatures contains at least one:
     * <ul>
     * <li><code>xades:SignatureTimeStamp</code> element.</li>
     * </ul>
     */
    private static boolean isXAdEST(List<Element> listSignatureElements) {
	// Si el documento XML posee elementos ds:Signature
	if (!listSignatureElements.isEmpty()) {
	    // Recorremos la lista de elementos ds:Signature
	    for (Element signatureElement: listSignatureElements) {
		if (isXAdEST(signatureElement)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signer has XAdES T-Level format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return a boolean that indicates if the signer has XAdES T-Level format.
     */
    private static boolean isXAdEST(Element signatureElement) {
	// Accedemos al elemento UnsignedProperties
	Element unsignedProperties = getXMLElement(signatureElement, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_PROPERTIES);
	if (unsignedProperties != null) {
	    // Accedemos al elemento UnsignedSignatureProperties. Se
	    // considera una firma con formato XAdES-T si posee
	    // el
	    // elemento SignatureTimeStamp
	    Element unsignedSignatureProperties = getXMLElement(unsignedProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES);
	    if (unsignedSignatureProperties != null && getXMLElement(unsignedSignatureProperties, IXMLConstants.XADES_1_3_2_NAMESPACE, IXMLConstants.ELEMENT_SIGNATURE_TIMESTAMP) != null) {
		return true;
	    }
	}
	return false;
    }

    /**
     *  Method that obtains the format associated to a signer of a XML document.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return the signature format. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    public static String resolveSignerXAdESFormat(Element signatureElement) {
	// Inicialmente definidos que el formato no está reconocido
	String format = FORMAT_UNRECOGNIZED;

	// Si se ha indicado firmante
	if (signatureElement != null) {
	    // Comprobamos si el firmante posee formato XAdES-EPES
	    if (isXAdESEPES(signatureElement)) {
		// Comprobamos si el firmante tiene
		// un formato Baseline, estableciendo que, al menos, el
		// formato
		// es XAdES-EPES
		format = resolveXAdESBaselineFormat(ISignatureFormatDetector.FORMAT_XADES_EPES, signatureElement);

		// Si el firmante no tiene un
		// formato
		// Baseline, es decir, el formato por ahora es XAdES-EPES,
		// comprobamos si posee un formato más avanzado no Baseline
		if (format.equals(ISignatureFormatDetector.FORMAT_XADES_EPES)) {
		    format = resolveXAdESNoBaselineFormat(ISignatureFormatDetector.FORMAT_XADES_EPES, signatureElement);
		}
	    }
	    // Comprobamos si el firmante tiene formato XAdES-BES
	    else if (isXAdESBES(signatureElement)) {
		// Comprobamos si el firmante tiene
		// un formato Baseline, estableciendo que, al menos, el
		// formato
		// es XAdES-BES
		format = resolveXAdESBaselineFormat(ISignatureFormatDetector.FORMAT_XADES_BES, signatureElement);

		// Si el firmante no tiene un
		// formato
		// Baseline, es decir, el formato por ahora es XAdES-BES,
		// comprobamos si posee un formato más avanzado no Baseline
		if (format.equals(ISignatureFormatDetector.FORMAT_XADES_BES)) {
		    format = resolveXAdESNoBaselineFormat(ISignatureFormatDetector.FORMAT_XADES_BES, signatureElement);
		}
	    }
	}
	return format;
    }

    /**
     * Method that checks if a signer has XAdES-EPES format.
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element associated to the signer.
     * @return a boolean that indicates if the signer has XAdES-EPES format.
     */
    private static boolean isXAdESEPES(Element signatureElement) {
	// Comprobamos si el firmante posee el elemento
	// xades:SignaturePolicyIdentifier
	if (hasSignaturePolicyIdentifier(signatureElement)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that obtains the format associated to a signer.
     * @param temporalFormat Parameter that represents the current format defined for the signer. This parameter only allows one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * </ul>
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_A}.</li>
     * </ul>
     */
    private static String resolveXAdESBaselineFormat(String temporalFormat, Element signatureElement) {
	String format = temporalFormat;
	// Comprobamos si el firmante tiene
	// el formato XAdES B-Level
	if (isXAdESBLevel(signatureElement)) {
	    // Indicamos que el formato por ahora es XAdES B-Level
	    format = ISignatureFormatDetector.FORMAT_XADES_B_LEVEL;

	    // Comprobamos si el firmante
	    // tiene
	    // el formato XAdES T-Level
	    if (isXAdEST(signatureElement)) {
		// Indicamos que el formato por ahora es XAdES T-Level
		format = ISignatureFormatDetector.FORMAT_XADES_T_LEVEL;

		// Comprobamos si el firmante
		// tiene
		// el formato XAdES LT-Level
		if (isXAdESLTLevel(signatureElement)) {
		    // Indicamos que el formato por ahora es XAdES
		    // LT-Level
		    format = ISignatureFormatDetector.FORMAT_XADES_LT_LEVEL;

		    // Comprobamos si el firmante
		    // tiene
		    // el formato XAdES LTA-Level
		    if (isXAdESLTALevel(signatureElement)) {
			// Indicamos que el formato por ahora es XAdES
			// LTA-Level
			format = ISignatureFormatDetector.FORMAT_XADES_LTA_LEVEL;
		    }
		} else {
		    format = resolveXAdESNoBaselineFormat(format, signatureElement);
		}
	    }
	}
	// Comprobamos si la firma tiene
	// el formato XAdES B-B-Level
	else if (isXAdESBBLevel(signatureElement)) {
	    // Indicamos que el formato por ahora es XAdES B-B-Level
	    format = ISignatureFormatDetector.FORMAT_XADES_B_B_LEVEL;

	    // Comprobamos si el firmante
	    // tiene
	    // el formato XAdES T-Level
	    if (isXAdEST(signatureElement)) {
		// Indicamos que el formato por ahora es XAdES B-T-Level
		format = ISignatureFormatDetector.FORMAT_XADES_B_T_LEVEL;

		// Comprobamos si el firmante
		// tiene
		// el formato XAdES LT-Level
		if (isXAdESBLTLevel(signatureElement)) {
		    // Indicamos que el formato por ahora es XAdES
		    // B-LT-Level
		    format = ISignatureFormatDetector.FORMAT_XADES_B_LT_LEVEL;

		    // Comprobamos si el firmante
		    // tiene
		    // el formato XAdES LTA-Level
		    if (isXAdESBLTALevel(signatureElement)) {
			// Indicamos que el formato por ahora es XAdES
			// B-LTA-Level
			format = ISignatureFormatDetector.FORMAT_XADES_B_LTA_LEVEL;
		    }
		} else {
		    format = resolveXAdESNoBaselineFormat(format, signatureElement);
		}
	    }
	}
	
	return format;
    }

    /**
     * Method that obtains the format no Baseline of a signer.
     * @param temporalFormat Parameter that represents the current format associated to the signer. This parameter only allows one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * </ul>
     * @param signatureElement Parameter that represents the <code>ds:Signature</code> element.
     * @return the format associated to the signer. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}.</li>
     * </ul>
     */
    private static String resolveXAdESNoBaselineFormat(String temporalFormat, Element signatureElement) {
	String format = temporalFormat;

	// Comprobamos si el firmante
	// tiene
	// el formato XAdES-A
	if (isXAdESA(signatureElement)) {
	    // Indicamos que el formato es XAdES-A
	    format = ISignatureFormatDetector.FORMAT_XADES_A;
	}
	// Comprobamos si el firmante
	// tiene
	// el formato XAdES-XL1
	else if (isXAdESXL1(signatureElement)) {
	    // Indicamos que el formato es XAdES-XL1
	    format = ISignatureFormatDetector.FORMAT_XADES_XL1;
	}
	// Comprobamos si el firmante
	// tiene
	// el formato XAdES-XL2
	else if (isXAdESXL2(signatureElement)) {
	    // Indicamos que el formato es XAdES-XL2
	    format = ISignatureFormatDetector.FORMAT_XADES_XL2;
	}
	// Comprobamos si el firmante
	// tiene
	// el formato XAdES-X1
	else if (isXAdESX1(signatureElement)) {
	    // Indicamos que el formato es XAdES-X1
	    format = ISignatureFormatDetector.FORMAT_XADES_X1;
	}
	// Comprobamos si el firmante
	// tiene
	// el formato XAdES-X2
	else if (isXAdESX2(signatureElement)) {
	    // Indicamos que el formato es XAdES-X2
	    format = ISignatureFormatDetector.FORMAT_XADES_X2;
	}
	// Comprobamos si el firmante
	// tiene
	// el formato XAdES-C
	else if (isXAdESC(signatureElement)) {
	    // Indicamos que el formato es XAdES-C
	    format = ISignatureFormatDetector.FORMAT_XADES_C;
	}
	// Comprobamos si el firmante
	// tiene
	// el formato XAdES-T
	else if (isXAdEST(signatureElement) && !format.equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
	    // Indicamos que el formato es XAdES-T
	    format = ISignatureFormatDetector.FORMAT_XADES_T;
	}
	return format;
    }

    /**
     * Method that indicates if a signature format is associated to Baseline form.
     * @param signatureFormat Parameter that represents the signature format.
     * @return a boolean that indicates if a signature format is associated to Baseline form.
     */
    public static boolean isXAdESBaseline(String signatureFormat) {
	return isXAdESBaselineTS(signatureFormat) || isXAdESBaselineEN(signatureFormat);
    }
    
    /**
     * Method that indicates if a signature format is associated to Baseline Technical Specification form.
     * @param signatureFormat Parameter that represents the signature format.
     * @return a boolean that indicates if a signature format is associated to Baseline Technical Specification form.
     */
    public static boolean isXAdESBaselineTS(String signatureFormat) {
	return signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LT_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LTA_LEVEL);
    }
    
    /**
     * Method that indicates if a signature format is associated to Baseline European Standard form.
     * @param signatureFormat Parameter that represents the signature format.
     * @return a boolean that indicates if a signature format is associated to Baseline European Standard form.
     */
    public static boolean isXAdESBaselineEN(String signatureFormat) {
	return signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_B_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_T_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LT_LEVEL) || signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LTA_LEVEL);
    }
}
