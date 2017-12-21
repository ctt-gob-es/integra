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
 * <b>File:</b><p>es.gob.afirma.integraFacade.IntegraFacadeBind.java.</p>
 * <b>Description:</b><p>Class to bind protected methods of IntegraFacade.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/05/2016.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.integraFacade;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.List;

import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.validation.PDFValidationResult;
import es.gob.afirma.signature.validation.ValidationResult;

/**
 * <p>Class to bind protected methods of IntegraFacade.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public final class IntegraFacadeBind {

	/**
	 * Constructor method for the class IntegraFacadeBind.java.
	 */
	private IntegraFacadeBind() {

	}

	/**
	 * Method that generates a signature.
	 * @param signatureTypeParam Parameter that represents signature type.
	 * @param dataToSign Parameter that represents the data to sign.
	 * @param privateKey Parameter that represents the private key of the signing certificate.
	 * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
	 * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
	 * @param idClient client identifier of ws invocation.
	 * @return a signature with one of the next formats:
	 * <ul>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}</li>
	 * </ul>
	 * @throws SigningException If the method fails.
	 */
	public static byte[ ] generateSignature(String signatureTypeParam, byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
		return IntegraFacade.generateSignature(signatureTypeParam, dataToSign, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	}

	/**
	 * Method that generates a co-signature.
	 * @param signatureTypeParam Parameter that represents signature type.
	 * @param signature Parameter that represents the signature to co-sign.
	 * @param signedData Parameter that represents the data to sign.
	 * @param privateKey Parameter that represents the private key of the signing certificate.
	 * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the co-signature (true) or not (false).
	 * @param includeTimestamp Parameter that indicates if to add a timestamp to the co-signature (true) or not (false).
	 * @param idClient client identifier of ws invocation.
	 * @return a co-signature with one of the next formats:
	 * <ul>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}</li>
	 * </ul>
	 * @throws SigningException If the method fails.
	 */
	public static byte[ ] generateCoSignature(String signatureTypeParam, byte[ ] signature, byte[ ] signedData, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
		return IntegraFacade.generateCoSignature(signatureTypeParam, signature, signedData, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	}

	/**
	 * Method that generates a counter-signature over a signature.
	 * @param signatureTypeParam Parameter that represents signature type.
	 * @param signature Parameter that represents the signature to counter-sign.
	 * @param privateKey Parameter that represents the private key of the signing certificate.
	 * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the co-signature (true) or not (false).
	 * @param includeTimestamp Parameter that indicates if to add a timestamp to the co-signature (true) or not (false).
	 * @param idClient client identifier of ws invocation.
	 * @return a signature with a counter-signature with one of the next formats:
	 * <ul>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}</li>
	 * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}</li>
	 * </ul>
	 * @throws SigningException If the method fails.
	 */
	public static byte[ ] generateCounterSignature(String signatureTypeParam, byte[ ] signature, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
		return IntegraFacade.generateCounterSignature(signatureTypeParam, signature, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	}

	/**
	 * Method that upgrades a signature adding a timestamp to all of the signers indicated. If the list of signers is null or empty, the timestamp
	 * will be added to all of the signers of the signature. The timestamp will be added only to those signers that don't have a previous timestamp.
	 * If the signature has a PDF format (PAdES-Basic, PAdES-BES, PAdES-EPES or PAdES-LTV), this method adds a Document Time-stamp dictionary and the
	 * signature form will be PAdES-LTV.
	 * @param signature Parameter that represents the signature to upgrade.
	 * @param listSigners Parameter that represents the list of signers of the signature to upgrade with a timestamp. Only for ASN.1 and XML signatures.
	 * @param idClient client identifier of ws invocation.
	 * @return the upgraded signature.
	 * @throws SigningException If the method fails.
	 */
	public static byte[ ] upgradeSignature(byte[ ] signature, List<X509Certificate> listSigners, String idClient) throws SigningException {
		return IntegraFacade.upgradeSignature(signature, listSigners, idClient);
	}

	/**
	 * Method that validates the signers of a signature.
	 * @param signature Parameter that represents the signature to validate.
	 * @param signedData Parameter that represents the original data signed by the signature.
	 * @param idClient client identifier of web service invocation.
	 * @return an object that contains the information about the validation result. The result must be an instance of:
	 * <ul>
	 * <li>{@link ValidationResult} for ASN.1, XML and ASiC-S signatures.</li>
	 * <li>{@link PDFValidationResult} for PDF signatures.</li>
	 * </ul>
	 */
	public static Object verifySignature(byte[ ] signature, byte[ ] signedData, String idClient) {
		return IntegraFacade.verifySignature(signature, signedData, idClient);
	}

	/**
	 * Method that generates a signature with rubric.
	 * @param signatureTypeParam Parameter that represents signature type.
	 * @param dataToSign Parameter that represents the data to sign.
	 * @param privateKey Parameter that represents the private key of the signing certificate.
	 * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
	 * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
	 * @param image Parameter that represents the image to be inserted as a rubric in the PDF.
	 * @param imagePage Parameter that represents the page where the image will be inserted.
	 * @param lowerLeftX Parameter that represents the coordinate horizontal lower left of the image position.
	 * @param lowerLeftY Parameter that represents the coordinate vertically lower left of the image position.
	 * @param upperRightX Parameter that represents the coordinate horizontal upper right of the image position.
	 * @param upperRightY Parameter that represents the coordinate vertically upper right of the image position.
	 * @param idClient client identifier of ws invocation.
	 * @return a signature PAdES (Baseline or no)
	 * @throws SigningException If the method fails.
	 */
	public static byte[ ] generateSignaturePAdESRubric(String signatureTypeParam, byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, byte[ ] image, String imagePage, int lowerLeftX, int lowerLeftY, int upperRightX, int upperRightY, String idClient) throws SigningException {
		return IntegraFacade.generateSignaturePAdESRubric(signatureTypeParam, dataToSign, privateKey, includeSignaturePolicy, includeTimestamp, image, imagePage, lowerLeftX, lowerLeftY, upperRightX, upperRightY, idClient);
	}

	/**
	 * Method that generates a multi-signature with rubric.
	 * @param signatureTypeParam Parameter that represents signature type.
	 * @param dataToSign Parameter that represents the data to sign.
	 * @param privateKey Parameter that represents the private key of the signing certificate.
	 * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
	 * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
	 * @param image Parameter that represents the image to be inserted as a rubric in the PDF.
	 * @param imagePage Parameter that represents the page where the image will be inserted.
	 * @param lowerLeftX Parameter that represents the coordinate horizontal lower left of the image position.
	 * @param lowerLeftY Parameter that represents the coordinate vertically lower left of the image position.
	 * @param upperRightX Parameter that represents the coordinate horizontal upper right of the image position.
	 * @param upperRightY Parameter that represents the coordinate vertically upper right of the image position.
	 * @param idClient client identifier of ws invocation.
	 * @return a signature PAdES (Baseline or no)
	 * @throws SigningException If the method fails.
	 */
	public static byte[ ] generateMultiSignaturePAdESRubric(String signatureTypeParam, byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, byte[ ] image, String imagePage, int lowerLeftX, int lowerLeftY, int upperRightX, int upperRightY, String idClient) throws SigningException {
		return IntegraFacade.generateMultiSignaturePAdESRubric(signatureTypeParam, dataToSign, privateKey, includeSignaturePolicy, includeTimestamp, image, imagePage, lowerLeftX, lowerLeftY, upperRightX, upperRightY, idClient);
	}

}
