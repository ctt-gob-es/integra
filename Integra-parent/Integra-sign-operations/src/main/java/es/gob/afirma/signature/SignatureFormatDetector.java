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
 * <b>File:</b><p>es.gob.afirma.signature.SignatureFormatDetector.java.</p>
 * <b>Description:</b><p>Class that contains all the functionality related to recognize the signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2014.
 */
package es.gob.afirma.signature;

import org.bouncycastle.cms.SignerInformation;
import org.w3c.dom.Element;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.signature.pades.PDFSignatureDictionary;
import es.gob.afirma.utils.GenericUtilsCommons;

/**
 * <p>Class that contains all the functionality related to recognize the signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2014.
 */
public final class SignatureFormatDetector implements ISignatureFormatDetector {

	/**
	 * Constructor method for the class SignatureFormatDetector.java.
	 */
	private SignatureFormatDetector() {
	}

	/**
	 * Method that obtains the format of a signature.
	 * @param signature Parameter that represents the element to evaluate. This element can be an ASN.1 signature, a XML document, a PDF document or a ZIP file.
	 * @return the signature format of the element. If the element is an ASN.1 signature, the value to return will be on of these:
	 * <ul>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LTA_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LT_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
	 * </ul>
	 * If the element is a XML document, the value to return will be on of these:
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
	 * If the element is a PDF document, the value to return will be on of these:
	 * <ul>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LTA_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LT_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LTV}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BASIC}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PDF}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
	 * </ul>
	 * If the element is a ZIP file, the value to return will be on of these:
	 * <ul>
	 * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LTA_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LT_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_T_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_B_LEVEL}.</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
	 * </ul>
	 */
	public static String getSignatureFormat(byte[ ] signature) {
		// Comprobamos que se ha indicado el elemento a comprobar
		GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.SFD_LOG001));

		// Si se ha indicado un documento XML
		if (SignatureFormatDetectorCommons.isXMLFormat(signature)) {
			return SignatureFormatDetectorXades.getSignatureFormat(signature);
		}
		// Si se ha indicado un fichero ZIP
		else if (SignatureFormatDetectorCommons.isASiCFormat(signature)) {
			return SignatureFormatDetectorASiC.getSignatureFormat(signature);
		} else {
			return SignatureFormatDetectorCadesPades.getSignatureFormat(signature);
		}
	}

	/**
	 * Method that indicates if a signature has the ASiC-S format (true) or not (false).
	 * @param signature Parameter that represents a ZIP file.
	 * @return a boolean that indicates if the signature has the ASiC-S format (true) or not (false).
	 */
	public static boolean isASiCFormat(byte[ ] signature) {
		return SignatureFormatDetectorCommons.isASiCFormat(signature);
	}

	/**
	 * Method that indicates whether a signature is ASN.1 (true) or not (false).
	 * @param signature Parameter that represents the signature to check.
	 * @return a boolean that indicates whether a signature is ASN.1 (true) or not (false).
	 */
	public static boolean isASN1Format(byte[ ] signature) {
		return SignatureFormatDetectorCadesPades.isASN1Format(signature);
	}

	/**
	 * Method that indicates whether a signature is XML (true) or not (false).
	 * @param signature Parameter that represents the signature to check.
	 * @return a boolean that indicates whether a signature is XML (true) or not (false).
	 */
	public static boolean isXMLFormat(byte[ ] signature) {
		return SignatureFormatDetectorCommons.isXMLFormat(signature);
	}

	/**
	 * Method that indicates whether a signature is PDF (true) or not (false).
	 * @param signature Parameter that represents the signature to check.
	 * @return a boolean that indicates whether a signature is PDF (true) or not (false).
	 */
	public static boolean isPDFFormat(byte[ ] signature) {
		return SignatureFormatDetectorCadesPades.isPDFFormat(signature);
	}

	/**
	 * Method that indicates whether a signature dictionary has PAdES-EPES signature format (true) or not (false).
	 * @param signatureDictionary Parameter that represents the signature dictionary.
	 * @return a boolean that indicates whether a signature dictionary has PAdES-EPES signature format (true) or not (false).
	 */
	public static boolean isPAdESEPES(PDFSignatureDictionary signatureDictionary) {
		return SignatureFormatDetectorCadesPades.isPAdESEPES(signatureDictionary);
	}

	/**
	 * Method that indicates whether a signature dictionary has PAdES-BES signature format (true) or not (false).
	 * @param signatureDictionary Parameter that represents the signature dictionary.
	 * @return a boolean that indicates whether a signature dictionary has PAdES-BES signature format (true) or not (false).
	 */
	public static boolean isPAdESBES(PDFSignatureDictionary signatureDictionary) {
		return SignatureFormatDetectorCadesPades.isPAdESBES(signatureDictionary);
	}

	/**
	 * Method that indicates whether a signature dictionary has PAdES-Basic signature format (true) or not (false).
	 * @param signatureDictionary Parameter that represents the signature dictionary.
	 * @return a boolean that indicates whether a signature dictionary has PAdES-Basic signature format (true) or not (false).
	 */
	public static boolean isPAdESBasic(PDFSignatureDictionary signatureDictionary) {
		return SignatureFormatDetectorCadesPades.isPAdESBasic(signatureDictionary);
	}

	/**
	 * Method that indicates whether a signature dictionary has PDF signature format (true) or not (false).
	 * @param signatureDictionary Parameter that represents the signature dictionary.
	 * @return a boolean that indicates whether a signature dictionary has PDF signature format (true) or not (false).
	 */
	public static boolean isPDF(PDFSignatureDictionary signatureDictionary) {
		return SignatureFormatDetectorCadesPades.isPDF(signatureDictionary);
	}

	/**
	 * Method that checks whether an ASN.1 signature has <code>SignaturePolicyIdentifier</code> element.
	 * @param signerInformation Parameter that represents the information about the signer.
	 * @return a boolean that indicates whether the ASN.1 signature has <code>SignaturePolicyIdentifier</code> element (true) or not (false).
	 */
	public static boolean hasSignaturePolicyIdentifier(SignerInformation signerInformation) {
		return SignatureFormatDetectorCadesPades.hasSignaturePolicyIdentifier(signerInformation);
	}

	/**
	 * Method that checks whether a XML signature has <code>SignaturePolicyIdentifier</code> element.
	 * @param dsSignature Parameter that represents <code>Signature</code> element.
	 * @return a boolean that indicates whether the XML signature has <code>SignaturePolicyIdentifier</code> element (true) or not (false).
	 */
	public static boolean hasSignaturePolicyIdentifier(Element dsSignature) {
		return SignatureFormatDetectorXades.hasSignaturePolicyIdentifier(dsSignature);
	}
}
