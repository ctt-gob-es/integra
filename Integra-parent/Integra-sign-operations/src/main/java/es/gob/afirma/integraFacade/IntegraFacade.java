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
 * <b>File:</b><p>es.gob.afirma.integraFacade.IntegraFacade.java.</p>
 * <b>Description:</b><p>Class that represents the facade which manages the generation, validation, and upgrade of signatures.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * <b>Date:</b><p>29/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.integraFacade;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.signature.ISignatureFormatDetector;
import es.gob.afirma.signature.OriginalSignedData;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.signature.SignatureFormatDetector;
import es.gob.afirma.signature.SignatureProperties;
import es.gob.afirma.signature.Signer;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.asic.ASiCSBaselineENSigner;
import es.gob.afirma.signature.asic.ASiCSBaselineTSSigner;
import es.gob.afirma.signature.cades.CAdESBaselineENSigner;
import es.gob.afirma.signature.cades.CAdESBaselineTSSigner;
import es.gob.afirma.signature.cades.CadesSigner;
import es.gob.afirma.signature.pades.PAdESBaselineENSigner;
import es.gob.afirma.signature.pades.PAdESBaselineTSSigner;
import es.gob.afirma.signature.pades.PadesSigner;
import es.gob.afirma.signature.policy.ISignPolicyConstants;
import es.gob.afirma.signature.validation.PDFValidationResult;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.signature.xades.XAdESBaselineENSigner;
import es.gob.afirma.signature.xades.XAdESBaselineTSSigner;
import es.gob.afirma.signature.xades.XadesSigner;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.UtilsResourcesSignOperations;

/**
 * <p>Class that represents the facade which manages the generation, validation, and upgrade of signatures.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.2, 14/03/2017.
 */
public final class IntegraFacade {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(IntegraFacade.class);

    /**
     * Constructor method for the class IntegraFacade.java.
     */
    private IntegraFacade() {
    }

    /**
     * Method that checks if the input signature algorithm isn't <code>null</code> and empty, and it's allowed.
     * @param signatureAlgorithm Parameter that represents the signature algorithm to check.
     * @throws SigningException If the validation fails.
     */
    private static void checkSignatureAlgorithm(String signatureAlgorithm) throws SigningException {
	// Comprobamos que el algoritmo de firma no es nulo ni vacío
	checkIsNotNullAndNotEmpty(signatureAlgorithm, Language.getFormatResIntegra(ILogConstantKeys.IF_LOG003, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	// Comprobamos que el algoritmo de firma está soportado
	if (!SignatureConstants.SIGN_ALGORITHMS_SUPPORT_CADES.containsKey(signatureAlgorithm)) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG004, new Object[ ] { signatureAlgorithm, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}

    }

    /**
     * Method that generates a signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
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
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    public static byte[ ] generateSignature(byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp) throws SigningException {
	return generateSignature(null, dataToSign, privateKey, includeSignaturePolicy, includeTimestamp, null);
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
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    protected static byte[ ] generateSignature(String signatureTypeParam, byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG001));
	try {
	    // Accedemos al archivo con las propiedades asociadas a la fachada
	    // de Integr@
	    Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo de propiedades el algoritmo de firma a
	    // usar
	    String signatureAlgorithm = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_ALGORITHM);

	    // Comprobamos que el algoritmo de firma a usar no es nulo y está
	    // soportado
	    checkSignatureAlgorithm(signatureAlgorithm);

	    String signatureType = signatureTypeParam;
	    if (signatureType == null) {
		// Rescatamos del archivo de propiedades el tipo de firma a
		// generar
		signatureType = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_TYPE);
	    }

	    // Comprobamos que el tipo de firma a generar no es nula ni vacía
	    checkIsNotNullAndNotEmpty(signatureType, Language.getFormatResIntegra(ILogConstantKeys.IF_LOG005, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Si la firma a generar es CAdES
	    if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES)) {
		return generateCAdESSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es XAdES
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES)) {
		return generateXAdESSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es PAdES
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES) || signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASIC)) {
		return generatePAdESSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, signatureType, idClient);
	    }
	    // Si la firma a generar es CAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES_BASELINE_TS)) {
		return generateCAdESBaselineTSSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es XAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES_BASELINE_TS)) {
		return generateXAdESBaselineTSSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es PAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_TS)) {
		return generatePAdESBaselineTSSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es ASiC-S CAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_ASICS_CADES_BASELINE_TS)) {
		return generateASiCSCAdESBaselineTS(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es ASiC-S Baseline XAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_ASICS_XADES_BASELINE_TS)) {
		return generateASiCSXAdESBaselineTS(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	 // Si la firma a generar es CAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES_BASELINE_EN)) {
		return generateCAdESBaselineENSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es XAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES_BASELINE_EN)) {
		return generateXAdESBaselineENSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es PAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_EN)) {
		return generatePAdESBaselineENSignature(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es ASiC-S Baseline CAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_ASICS_CADES_BASELINE_EN)) {
		return generateASiCSCAdESBaselineEN(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la firma a generar es ASiC-S Baseline XAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_ASICS_XADES_BASELINE_EN)) {
		return generateASiCSXAdESBaselineEN(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si el tipo de firma a generar no está reconocido
	    else {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG009, new Object[ ] { signatureType, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG002));
	}
    }

    /**
     * Method that generates a co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the co-signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the co-signature (true) or not (false).
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
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    public static byte[ ] generateCoSignature(byte[ ] signature, byte[ ] signedData, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp) throws SigningException {
	return generateCoSignature(null, signature, signedData, privateKey, includeSignaturePolicy, includeTimestamp, null);
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
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    protected static byte[ ] generateCoSignature(String signatureTypeParam, byte[ ] signature, byte[ ] signedData, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG010));
	try {
	    // Accedemos al archivo con las propiedades asociadas a la fachada
	    // de Integr@
	    Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo de propiedades el algoritmo de firma a
	    // usar
	    String signatureAlgorithm = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_ALGORITHM);

	    // Comprobamos que el algoritmo de firma a usar no es nulo y está
	    // soportado
	    checkSignatureAlgorithm(signatureAlgorithm);

	    String signatureType = signatureTypeParam;
	    if (signatureType == null) {
		// Rescatamos del archivo de propiedades el tipo de firma a
		// generar
		signatureType = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_TYPE);
	    }

	    // Comprobamos que el tipo de firma a generar no es nula ni vacía
	    checkIsNotNullAndNotEmpty(signatureType, Language.getFormatResIntegra(ILogConstantKeys.IF_LOG005, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Si la co-firma a generar es CAdES
	    if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES)) {
		return generateCAdESCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es XAdES
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES)) {
		return generateXAdESCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es PAdES
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES)) {
		return generatePAdESCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es CAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES_BASELINE_TS)) {
		return generateCAdESBaselineTSCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es XAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES_BASELINE_TS)) {
		return generateXAdESBaselineTSCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es PAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_TS)) {
		return generatePAdESBaselineTSCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es CAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES_BASELINE_EN)) {
		return generateCAdESBaselineENCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es XAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES_BASELINE_EN)) {
		return generateXAdESBaselineENCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es PAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_EN)) {
		return generatePAdESBaselineENCoSignature(signature, signedData, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si el tipo de co-firma a generar no está reconocido
	    else {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG009, new Object[ ] { signatureType, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG011));
	}

    }

    /**
     * Method that generates a counter-signature over a signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the co-signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the co-signature (true) or not (false).
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
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    public static byte[ ] generateCounterSignature(byte[ ] signature, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp) throws SigningException {
	return generateCounterSignature(null, signature, privateKey, includeSignaturePolicy, includeTimestamp, null);
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
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    protected static byte[ ] generateCounterSignature(String signatureTypeParam, byte[ ] signature, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG012));
	try {
	    // Accedemos al archivo con las propiedades asociadas a la fachada
	    // de Integr@
	    Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo de propiedades el algoritmo de firma a
	    // usar
	    String signatureAlgorithm = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_ALGORITHM);

	    // Comprobamos que el algoritmo de firma a usar no es nulo y está
	    // soportado
	    checkSignatureAlgorithm(signatureAlgorithm);

	    String signatureType = signatureTypeParam;
	    if (signatureType == null) {
		// Rescatamos del archivo de propiedades el tipo de firma a
		// generar
		signatureType = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_TYPE);
	    }

	    // Comprobamos que el tipo de firma a generar no es nula ni vacía
	    checkIsNotNullAndNotEmpty(signatureType, Language.getFormatResIntegra(ILogConstantKeys.IF_LOG005, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Si la contra-firma a generar es CAdES
	    if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES)) {
		return generateCAdESCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la contra-firma a generar es XAdES
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES)) {
		return generateXAdESCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la contra-firma a generar es PAdES
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES)) {
		return generatePAdESCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la contra-firma a generar es CAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES_BASELINE_TS)) {
		return generateCAdESBaselineTSCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la contra-firma a generar es XAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES_BASELINE_TS)) {
		return generateXAdESBaselineTSCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la contra-firma a generar es PAdES Baseline Technical Specification
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_TS)) {
		return generatePAdESBaselineTSCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es CAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_CADES_BASELINE_EN)) {
		return generateCAdESBaselineENCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es XAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_XADES_BASELINE_EN)) {
		return generateXAdESBaselineENCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si la co-firma a generar es PAdES Baseline European Standard
	    else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_EN)) {
		return generatePAdESBaselineENCounterSignature(signature, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, idClient);
	    }
	    // Si el tipo de contra-firma a generar no está reconocido
	    else {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG009, new Object[ ] { signatureType, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG013));
	}
    }

    /**
     * Method that generates a signature with rubric.
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
     *
     * @return a signature PAdES (Baseline or no)
     * @throws SigningException If the method fails.
     */
    public static byte[ ] generateSignaturePAdESRubric(byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, byte[ ] image, String imagePage, int lowerLeftX, int lowerLeftY, int upperRightX, int upperRightY) throws SigningException {
	return generateSignaturePAdESRubric(null, dataToSign, privateKey, includeSignaturePolicy, includeTimestamp, image, imagePage, lowerLeftX, lowerLeftY, upperRightX, upperRightY, null);
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
    protected static byte[ ] generateSignaturePAdESRubric(String signatureTypeParam, byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, byte[ ] image, String imagePage, int lowerLeftX, int lowerLeftY, int upperRightX, int upperRightY, String idClient) throws SigningException {

	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG022));
	try {
	    // Accedemos al archivo con las propiedades asociadas a la fachada
	    // de Integr@
	    Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);
	    // Rescatamos del archivo de propiedades el algoritmo de firma a
	    // usar
	    String signatureAlgorithm = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_ALGORITHM);

	    // Comprobamos que el algoritmo de firma a usar no es nulo y está
	    // soportado
	    checkSignatureAlgorithm(signatureAlgorithm);

	    String signatureType = signatureTypeParam;
	    if (signatureType == null) {
		// Rescatamos del archivo de propiedades el tipo de firma a
		// generar
		signatureType = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_TYPE);
	    }

	    // Comprobamos que el tipo de firma a generar no es nula ni vacía
	    checkIsNotNullAndNotEmpty(signatureType, Language.getFormatResIntegra(ILogConstantKeys.IF_LOG005, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Comprobamos que se trate de un firma PAdES o PAdES Baseline
	    checkIsSignaturePades(signatureType, Language.getResIntegra(ILogConstantKeys.IF_LOG024));

	    // creamos un objeto Properties donde se incluirán los datos
	    // necesarios para insertar la rúbrica.
	    Properties extraParams = new Properties();
	    extraParams.put(SignatureProperties.PADES_IMAGE, image);
	    extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, imagePage);
	    extraParams.put(SignatureProperties.PADES_LOWER_LEFT_X, String.valueOf(lowerLeftX));
	    extraParams.put(SignatureProperties.PADES_LOWER_LEFT_Y, String.valueOf(lowerLeftY));
	    extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_X, String.valueOf(upperRightX));
	    extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_Y, String.valueOf(upperRightY));

	    if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES)) {
		// Si la firma a generar es PAdES
		return generatePAdESSignatureWithRubric(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, signatureType, extraParams, idClient);
	    } else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_TS)) {
		// si la firma a generar es PAdES Baseline
		return generatePAdESBaselineTSSignatureWithRubric(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, extraParams, idClient);
	    } else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_EN)) {
		// si la firma a generar es PAdES Baseline
		return generatePAdESBaselineENSignatureWithRubric(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, extraParams, idClient);
	    }
	    // Si el tipo de firma a generar no está reconocido
	    else {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG009, new Object[ ] { signatureType, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG023));
	}
    }

    /**
     * Method that generates a multi-signature with rubric.
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
     *
     * @return a signature PAdES (Baseline or no)
     * @throws SigningException If the method fails.
     */
    public static byte[ ] generateMultiSignaturePAdESRubric(byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, byte[ ] image, String imagePage, int lowerLeftX, int lowerLeftY, int upperRightX, int upperRightY) throws SigningException {
	return generateMultiSignaturePAdESRubric(null, dataToSign, privateKey, includeSignaturePolicy, includeTimestamp, image, imagePage, lowerLeftX, lowerLeftY, upperRightX, upperRightY, null);
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
    protected static byte[ ] generateMultiSignaturePAdESRubric(String signatureTypeParam, byte[ ] dataToSign, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, byte[ ] image, String imagePage, int lowerLeftX, int lowerLeftY, int upperRightX, int upperRightY, String idClient) throws SigningException {

	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG025));
	try {
	    // Accedemos al archivo con las propiedades asociadas a la fachada
	    // de Integr@
	    Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);
	    // Rescatamos del archivo de propiedades el algoritmo de firma a
	    // usar
	    String signatureAlgorithm = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_ALGORITHM);

	    // Comprobamos que el algoritmo de firma a usar no es nulo y está
	    // soportado
	    checkSignatureAlgorithm(signatureAlgorithm);

	    String signatureType = signatureTypeParam;
	    if (signatureType == null) {
		// Rescatamos del archivo de propiedades el tipo de firma a
		// generar
		signatureType = (String) integraProperties.get(IntegraFacadeConstants.KEY_FACADE_SIGNATURE_TYPE);
	    }

	    // Comprobamos que el tipo de firma a generar no es nula ni vacía
	    checkIsNotNullAndNotEmpty(signatureType, Language.getFormatResIntegra(ILogConstantKeys.IF_LOG005, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

	    // Comprobamos que se trate de un firma PAdES o PAdES Baseline
	    checkIsSignaturePades(signatureType, Language.getResIntegra(ILogConstantKeys.IF_LOG024));

	    // creamos un objeto Properties donde se incluirán los datos
	    // necesarios para insertar la rúbrica.
	    Properties extraParams = new Properties();
	    extraParams.put(SignatureProperties.PADES_IMAGE, image);
	    extraParams.put(SignatureProperties.PADES_IMAGE_PAGE, imagePage);
	    extraParams.put(SignatureProperties.PADES_LOWER_LEFT_X, String.valueOf(lowerLeftX));
	    extraParams.put(SignatureProperties.PADES_LOWER_LEFT_Y, String.valueOf(lowerLeftY));
	    extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_X, String.valueOf(upperRightX));
	    extraParams.put(SignatureProperties.PADES_UPPER_RIGHT_Y, String.valueOf(upperRightY));
	    // Si la firma a generar es PAdES
	    if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES)) {
		return generatePAdESSignatureWithRubric(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, signatureType, extraParams, idClient);
	    } else if (signatureType.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_TS)) {
		return generatePAdESBaselineTSSignatureWithRubric(dataToSign, signatureAlgorithm, privateKey, includeSignaturePolicy, includeTimestamp, extraParams, idClient);
	    }
	    // Si el tipo de firma a generar no está reconocido
	    else {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG009, new Object[ ] { signatureType, IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }

	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG026));
	}
    }

    /**
     * Method that indicates if the format of a signature is related to CAdES signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to CAdES signature format (true) or not (false).
     */
    private static boolean isCAdESSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_BES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_EPES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_T)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_C)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_X1)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_X2)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_XL1)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_XL2)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_A)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to XAdES signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to XAdES signature format (true) or not (false).
     */
    private static boolean isXAdESSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_BES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_EPES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_T)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_C)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_X1)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_X2)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_XL1)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_XL2)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_A)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to PAdES signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to PAdES signature format (true) or not (false).
     */
    private static boolean isPAdESSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_BASIC)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_BES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_EPES)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_LTV)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to CAdES Baseline signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to CAdES Baseline signature format (true) or not (false).
     */
    private static boolean isCAdESBaselineTSSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to XAdES Baseline signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to XAdES Baseline signature format (true) or not (false).
     */
    private static boolean isXAdESBaselineTSSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to PAdES Baseline signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to PAdES Baseline signature format (true) or not (false).
     */
    private static boolean isPAdESBaselineTSSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to ASiC-S Baseline signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to ASiC-S Baseline signature format (true) or not (false).
     */
    private static boolean isASiCSBaselineTSSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }
    
    /**
     * Method that indicates if the format of a signature is related to CAdES Baseline European
     * Standard signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to CAdES Baseline
     * European Standard signature format (true) or not (false).
     */
    private static boolean isCAdESBaselineENSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to XAdES Baseline European
     * Standard signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to XAdES Baseline
     * European Standar signature format (true) or not (false).
     */
    private static boolean isXAdESBaselineENSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to PAdES Baseline European
     * Standard signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to PAdES Baseline
     * European Standard signature format (true) or not (false).
     */
    private static boolean isPAdESBaselineENSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_B_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_B_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_B_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_PADES_B_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates if the format of a signature is related to ASiC-S Baseline European
     * Standard signature format.
     * @param signatureFormat Parameter that represents the signature format to process.
     * @return a boolean that indicates if the format of a signature is related to ASiC-S Baseline
     * European Standard signature format (true) or not (false).
     */
    private static boolean isASiCSBaselineENSignatureFormat(String signatureFormat) {
	if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_B_B_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_B_T_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_B_LT_LEVEL)) {
	    return true;
	} else if (signatureFormat.equals(ISignatureFormatDetector.FORMAT_ASIC_S_B_LTA_LEVEL)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that upgrades a signature adding a timestamp to all of the signers indicated. If the list of signers is null or empty, the timestamp
     * will be added to all of the signers of the signature. The timestamp will be added only to those signers that don't have a previous timestamp.
     * If the signature has a PDF format (PAdES-Basic, PAdES-BES, PAdES-EPES or PAdES-LTV), this method adds a Document Time-stamp dictionary and the
     * signature form will be PAdES-LTV.
     * @param signature Parameter that represents the signature to upgrade.
     * @param listSigners Parameter that represents the list of signers of the signature to upgrade with a timestamp. Only for ASN.1 and XML signatures.
     * @return the upgraded signature.
     * @throws SigningException If the method fails.
     */
    public static byte[ ] upgradeSignature(byte[ ] signature, List<X509Certificate> listSigners) throws SigningException {
	return upgradeSignature(signature, listSigners, null);
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
    protected static byte[ ] upgradeSignature(byte[ ] signature, List<X509Certificate> listSigners, String idClient) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG014));
	try {
	    // Comprobamos que se ha indicado la firma a actualizar
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.IF_LOG016));

	    Signer signer = null;

	    // Determinamos el formato de la firma a actualizar a fin de
	    // determinar qué implementación de Signer llevará a cabo la
	    // actualización
	    String signatureFormat = SignatureFormatDetector.getSignatureFormat(signature);

	    // Si el formato es CAdES-BES, CAdES-EPES, CAdES-T, CAdES-C,
	    // CAdES-X1, CAdES-X2, CAdES-XL o CAdES-A
	    if (isCAdESSignatureFormat(signatureFormat)) {
		signer = new CadesSigner();

		// Actualizamos los firmantes de la firma CAdES
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si el formato es XAdES-BES, XAdES-EPES, XAdES-T, XAdES-C,
	    // XAdES-X1, XAdES-X2, XAdES-XL o XAdES-A
	    else if (isXAdESSignatureFormat(signatureFormat)) {
		signer = new XadesSigner();

		// Actualizamos los firmantes de la firma XAdES
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si el formato es PAdES-Basic, PAdES-BES, PAdES-EPES o PAdES-LTV
	    else if (isPAdESSignatureFormat(signatureFormat)) {
		signer = new PadesSigner();

		// Actualizamos los firmantes de la firma PAdES
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si el formato es CAdES Baseline Technical Specification
	    else if (isCAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new CAdESBaselineTSSigner();

		// Actualizamos los firmantes de la firma
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si el formato es XAdES Baseline Technical Specification
	    else if (isXAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new XAdESBaselineTSSigner();

		// Actualizamos los firmantes de la firma
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si el formato es PAdES Baseline Technical Specification
	    else if (isPAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new PAdESBaselineTSSigner();

		// Actualizamos los firmantes de la firma
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si el formato es ASiC-S Baseline Technical Specification
	    else if (isASiCSBaselineTSSignatureFormat(signatureFormat)) {
		signer = new ASiCSBaselineTSSigner();

		// Actualizamos los firmantes de la firma CAdES o XAdES
		// contenida dentro de la firma ASiC-S
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si es formato CAdES Baseline European Standard
	    else if (isCAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new CAdESBaselineENSigner();

		// Actualizamos los firmantes de la firma
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si es formato XAdES Baseline European Standard
	    else if (isXAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new XAdESBaselineENSigner();

		// Actualizamos los firmantes de la firma
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si es formato PAdES Baseline European Standard
	    else if (isPAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new PAdESBaselineENSigner();

		// Actualizamos los firmantes de la firma
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si el formato es ASiC-S Baseline European Standard
	    else if (isASiCSBaselineENSignatureFormat(signatureFormat)) {
		signer = new ASiCSBaselineENSigner();

		// Actualizamos los firmantes de la firma CAdES o XAdES
		// contenida dentro de la firma ASiC-S
		return signer.upgrade(signature, listSigners, idClient);
	    }
	    // Si el formato no es ninguno de los anteriores
	    else {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.IF_LOG017);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG015));
	}
    }

    /**
     * Method that validates the signers of a signature.
     * @param signature Parameter that represents the signature to validate.
     * @param signedData Parameter that represents the original data signed by the signature.
     * @return an object that contains the information about the validation result. The object will be an instance of
     * <ul>
     * <li>{@link ValidationResult} for ASN.1, XML and ASiC-S signatures.</li>
     * <li>{@link PDFValidationResult} for PDF signatures.</li>
     * </ul>
     */
    public static Object verifySignature(byte[ ] signature, byte[ ] signedData) {
	return verifySignature(signature, signedData, null);
    }

    /**
     * Method that validates the signers of a signature.
     * @param signature Parameter that represents the signature to validate.
     * @param signedData Parameter that represents the original data signed by the signature.
     * @param idClient client identifier of ws invocation.
     * @return an object that contains the information about the validation result. The object will be an instance of
     * <ul>
     * <li>{@link ValidationResult} for ASN.1, XML and ASiC-S signatures.</li>
     * <li>{@link PDFValidationResult} for PDF signatures.</li>
     * </ul>
     */
    protected static Object verifySignature(byte[ ] signature, byte[ ] signedData, String idClient) {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG018));

	try {
	    // Comprobamos que se ha indicado la firma a validar
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.IF_LOG016));

	    Signer signer = null;

	    // Determinamos el formato de la firma a validar a fin de
	    // determinar qué implementación de Signer llevará a cabo la
	    // validación
	    String signatureFormat = SignatureFormatDetector.getSignatureFormat(signature);

	    // Si el formato es CAdES-BES, CAdES-EPES, CAdES-T, CAdES-C,
	    // CAdES-X1, CAdES-X2, CAdES-XL o CAdES-A
	    if (isCAdESSignatureFormat(signatureFormat)) {
		signer = new CadesSigner();

		// Validamos los firmantes de la firma CAdES
		return ((CadesSigner) signer).verifySignature(signature, signedData, idClient);
	    }
	    // Si el formato es XAdES-BES, XAdES-EPES, XAdES-T, XAdES-C,
	    // XAdES-X1, XAdES-X2, XAdES-XL o XAdES-A
	    else if (isXAdESSignatureFormat(signatureFormat)) {
		signer = new XadesSigner();

		// Validamos los firmantes de la firma XAdES
		return ((XadesSigner) signer).verifySignature(signature, idClient);
	    }
	    // Si el formato es PAdES-Basic, PAdES-BES, PAdES-EPES o PAdES-LTV
	    else if (isPAdESSignatureFormat(signatureFormat)) {
		signer = new PadesSigner();

		// Validamos los firmantes de la firma PAdES
		return ((PadesSigner) signer).verifySignature(signature, idClient);
	    }
	    // Si el formato es CAdES Baseline Techanical Specification
	    else if (isCAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new CAdESBaselineTSSigner();

		// Validamos los firmantes de la firma CAdES Baseline
		return ((CAdESBaselineTSSigner) signer).verifySignature(signature, signedData, idClient);
	    }
	    // Si el formato es XAdES Baseline Techanical Specification
	    else if (isXAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new XAdESBaselineTSSigner();

		// Validamos los firmantes de la firma XAdES Baseline
		return ((XAdESBaselineTSSigner) signer).verifySignature(signature, idClient);
	    }
	    // Si el formato es PAdES Baseline Techanical Specification
	    else if (isPAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new PAdESBaselineTSSigner();

		// Validamos los firmantes de la firma PAdES Baseline
		return ((PAdESBaselineTSSigner) signer).verifySignature(signature, idClient);
	    }
	    // Si el formato es ASiC-S Baseline Techanical Specification
	    else if (isASiCSBaselineTSSignatureFormat(signatureFormat)) {
		signer = new ASiCSBaselineTSSigner();

		// Validamos la firma ASiC-S
		return ((ASiCSBaselineTSSigner) signer).verifySignature(signature);
	    }
	    // Si el formato es CAdES Baseline European Standard
	    else if (isCAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new CAdESBaselineENSigner();

		// Validamos los firmantes de la firma CAdES Baseline
		return ((CAdESBaselineENSigner) signer).verifySignature(signature, signedData, idClient);
	    }
	    // Si el formato es XAdES Baseline European Standard
	    else if (isXAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new XAdESBaselineENSigner();

		// Validamos los firmantes de la firma XAdES Baseline
		return ((XAdESBaselineENSigner) signer).verifySignature(signature, idClient);
	    }
	    // Si el formato es PAdES Baseline European Standard
	    else if (isPAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new PAdESBaselineENSigner();

		// Validamos los firmantes de la firma PAdES Baseline
		return ((PAdESBaselineENSigner) signer).verifySignature(signature, idClient);
	    }
	    // Si el formato es ASiC-S Baseline European Standard
	    else if (isASiCSBaselineENSignatureFormat(signatureFormat)) {
		signer = new ASiCSBaselineENSigner();

		// Validamos la firma ASiC-S Baseline European Standard
		return ((ASiCSBaselineENSigner) signer).verifySignature(signature);
	    }
	    // Si el formato no es ninguno de los anteriores
	    else {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.IF_LOG017);
		LOGGER.error(errorMsg);
		ValidationResult vr = new ValidationResult();
		vr.setErrorMsg(errorMsg);
		vr.setCorrect(false);
		return vr;
	    }
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG019));

	}

    }

    /**
     * Method that obtains the data originally signed from a signature.
     * 
     * @param signature Parameter that represents the signature of which is to obtain the data.
     * @return Information about data originally signed.
     * @throws SigningException If the method fails.
     */
    public static OriginalSignedData getSignedData(byte[ ] signature) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG020));
	try {
	    // Comprobamos que se ha indicado la firma de la que se quiere
	    // obtener los datos firmados
	    GenericUtilsCommons.checkInputParameterIsNotNull(signature, Language.getResIntegra(ILogConstantKeys.IF_LOG016));

	    Signer signer = null;

	    // Determinamos el formato de la firma de la que se quiere obtener
	    // los datos para ver a qué implementación de Signer llevará a cabo
	    // la extración de datos.
	    String signatureFormat = SignatureFormatDetector.getSignatureFormat(signature);

	    // Si el formato es CAdES
	    if (isCAdESSignatureFormat(signatureFormat)) {
		signer = new CadesSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);

	    }
	    // Si es formato XAdES
	    else if (isXAdESSignatureFormat(signatureFormat)) {
		signer = new XadesSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato PAdES
	    else if (isPAdESSignatureFormat(signatureFormat)) {
		signer = new PadesSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato ASiC-S Baseline Technical Specification
	    else if (isASiCSBaselineTSSignatureFormat(signatureFormat)) {
		signer = new ASiCSBaselineTSSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato CAdES Baseline Technical Specification
	    else if (isCAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new CAdESBaselineTSSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato XAdES Baseline Technical Specification
	    else if (isXAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new XAdESBaselineTSSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato PAdES Baseline Technical Specification
	    else if (isPAdESBaselineTSSignatureFormat(signatureFormat)) {
		signer = new PAdESBaselineTSSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato ASiC-S Baseline European Standard
	    else if (isASiCSBaselineENSignatureFormat(signatureFormat)) {
		signer = new ASiCSBaselineENSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato CAdES Baseline European Standard
	    else if (isCAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new CAdESBaselineENSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato XAdES Baseline European Standard
	    else if (isXAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new XAdESBaselineENSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // Si es formato PAdES Baseline European Standard
	    else if (isPAdESBaselineENSignatureFormat(signatureFormat)) {
		signer = new PAdESBaselineENSigner();

		// obtenemos los datos firmados

		return signer.getSignedData(signature);
	    }
	    // si el formato no es ninguno de los anteriores
	    else {
		String errorMsg = Language.getResIntegra(ILogConstantKeys.IF_LOG017);
		LOGGER.error(errorMsg);
		throw new SigningException(errorMsg);

	    }
	} catch (SigningException e) {
	    LOGGER.error(e.getMessage());
	    return null;
	} finally {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IF_LOG021));
	}
    }

    /**
     * Method that generates a CAdES signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma CAdES
	Signer signer = new CadesSigner();

	// Generamos la firma CAdES
	String signatureForm = ISignatureFormatDetector.FORMAT_CADES_BES;
	if (includeSignaturePolicy) {
	    signatureForm = ISignatureFormatDetector.FORMAT_CADES_EPES;
	}
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a CAdES Baseline Technical Specification signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESBaselineTSSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma CAdES
	// Baseline
	Signer signer = new CAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas ASN.1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma CAdES Baseline
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, policyID, idClient);
    }
    

    /**
     * Method that generates a CAdES Baseline European Standard signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESBaselineENSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma CAdES
	// Baseline European Standard
	Signer signer = new CAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas ASN.1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma CAdES Baseline European Standard
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_CADES_B_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a XAdES signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	Signer signer = new XadesSigner();

	// Generamos la firma XAdES
	String signatureForm = ISignatureFormatDetector.FORMAT_XADES_BES;
	if (includeSignaturePolicy) {
	    signatureForm = ISignatureFormatDetector.FORMAT_XADES_EPES;
	}
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a XAdES Baseline Technical Specifications signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESBaselineTSSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	// Baseline
	Signer signer = new XAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas XML
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG007, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}

	// Generamos la firma XAdES Baseline
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a XAdES Baseline European Standard signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESBaselineENSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	// Baseline European Standard
	Signer signer = new XAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas XML
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG007, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}

	// Generamos la firma XAdES Baseline European Standard
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_XADES_B_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a PAdES signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param signatureType Parameter that indicates the signature type.
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String signatureType, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	Signer signer = new PadesSigner();

	// Generamos la firma PAdES
	String signatureForm;
	if (ISignatureFormatDetector.FORMAT_PADES_BASIC.equals(signatureType)) {
	    signatureForm = ISignatureFormatDetector.FORMAT_PADES_BASIC;
	} else {
	    signatureForm = ISignatureFormatDetector.FORMAT_PADES_BES;
	}

	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a PAdES Baseline Technical Specification signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESBaselineTSSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	// Baseline
	Signer signer = new PAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG008, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma PAdES Baseline
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, policyID, idClient);
    }
    

    /**
     * Method that generates a PAdES Baseline European Standard signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESBaselineENSignature(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	// Baseline European Standard
	Signer signer = new PAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG008, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma PAdES Baseline European Standard
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_PADES_B_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a CAdES co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la co-firma CAdES
	Signer signer = new CadesSigner();

	// Generamos la co-firma CAdES
	String signatureForm = ISignatureFormatDetector.FORMAT_CADES_BES;
	if (includeSignaturePolicy) {
	    signatureForm = ISignatureFormatDetector.FORMAT_CADES_EPES;
	}
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a CAdES Baseline Technical Specification co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESBaselineTSCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma CAdES
	// Baseline
	Signer signer = new CAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas ASN.1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma CAdES Baseline
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a CAdES Baseline European Standard co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESBaselineENCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma CAdES
	// Baseline European Standard
	Signer signer = new CAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas ASN.1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma CAdES Baseline European Standard
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_CADES_B_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a XAdES co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	Signer signer = new XadesSigner();

	// Generamos la firma XAdES
	String signatureForm = ISignatureFormatDetector.FORMAT_XADES_BES;
	if (includeSignaturePolicy) {
	    signatureForm = ISignatureFormatDetector.FORMAT_XADES_EPES;
	}
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a XAdES Baseline Technical Specification co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESBaselineTSCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	// Baseline Technical Specification
	Signer signer = new XAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas XML
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG007, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}

	// Generamos la co-firma XAdES Baseline Technical Specification
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a XAdES Baseline European Standard co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESBaselineENCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	// Baseline European Standard
	Signer signer = new XAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas XML
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG007, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}

	// Generamos la co-firma XAdES Baseline European Standard
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_XADES_B_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a PAdES co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	Signer signer = new PadesSigner();

	// Generamos la firma PAdES
	String signatureForm = ISignatureFormatDetector.FORMAT_PADES_BES;
	if (includeSignaturePolicy) {
	    signatureForm = ISignatureFormatDetector.FORMAT_PADES_EPES;
	}
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a PAdES Baseline Technical Specification co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESBaselineTSCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	// Baseline Technical Specification
	Signer signer = new PAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG008, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma PAdES Baseline Technical Specification
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a PAdES Baseline European Standard co-signature.
     * @param signature Parameter that represents the signature to co-sign.
     * @param signedData Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a co-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESBaselineENCoSignature(byte[ ] signature, byte[ ] signedData, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	// Baseline European Standard
	Signer signer = new PAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG008, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma PAdES Baseline European Standard
	return signer.coSign(signature, signedData, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_PADES_B_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a CAdES counter-signature over a CAdES signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a CAdES signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la co-firma CAdES
	Signer signer = new CadesSigner();

	// Generamos la co-firma CAdES
	String signatureForm = ISignatureFormatDetector.FORMAT_CADES_BES;
	if (includeSignaturePolicy) {
	    signatureForm = ISignatureFormatDetector.FORMAT_CADES_EPES;
	}
	return signer.counterSign(signature, signatureAlgorithm, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a CAdES Baseline Technical Specification counter-signature over a CAdES Baseline signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a CAdES Baseline signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESBaselineTSCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma CAdES
	// Baseline Technical Specification
	Signer signer = new CAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas ASN.1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma CAdES Baseline Technical Specification
	return signer.counterSign(signature, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a CAdES Baseline European Standard counter-signature over a CAdES Baseline signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a CAdES Baseline signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_B_LEVEL}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_T_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateCAdESBaselineENCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma CAdES
	// Baseline European Standard
	Signer signer = new CAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas ASN.1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma CAdES Baseline European Standard
	return signer.counterSign(signature, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_CADES_B_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a XAdES counter-signature over a XAdES signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a XAdES signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	Signer signer = new XadesSigner();

	// Generamos la firma XAdES
	String signatureForm = ISignatureFormatDetector.FORMAT_XADES_BES;
	if (includeSignaturePolicy) {
	    signatureForm = ISignatureFormatDetector.FORMAT_XADES_EPES;
	}
	return signer.counterSign(signature, signatureAlgorithm, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a XAdES Baseline Technical Specification counter-signature over a XAdES Baseline signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a XAdES Baseline signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_Level}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_T_Level}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESBaselineTSCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	// Baseline Technical Specification
	Signer signer = new XAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas XML
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG007, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}

	// Creamos el mapa para propiedades adicionales, en el caso de
	// XAdES Baseline son obligatorias las asociadas a la generación
	// del elemento xades:DataObjectFormat
	Properties extraParams = new Properties();

	// Para la descripción usaremos un texto constante
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Data signed by the signer facade of Integr@");

	// Para el Mime-Type de los datos a firmar utilizaremos la
	// librería Tika
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, UtilsResourcesSignOperations.getMimeType(signature));

	// Generamos la contra-firma XAdES Baseline Technical Specification
	return signer.counterSign(signature, signatureAlgorithm, privateKey, extraParams, includeTimestamp, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a XAdES Baseline European Standard counter-signature over a XAdES Baseline signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a XAdES Baseline signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_B_Level}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_T_Level}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateXAdESBaselineENCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma XAdES
	// Baseline European Standard
	Signer signer = new XAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas XML
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG007, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}

	// Creamos el mapa para propiedades adicionales, en el caso de
	// XAdES Baseline son obligatorias las asociadas a la generación
	// del elemento xades:DataObjectFormat
	Properties extraParams = new Properties();

	// Para la descripción usaremos un texto constante
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_DESCRIPTION_PROP, "Data signed by the signer facade of Integr@");

	// Para el Mime-Type de los datos a firmar utilizaremos la
	// librería Tika
	extraParams.put(SignatureProperties.XADES_DATA_FORMAT_MIME_PROP, UtilsResourcesSignOperations.getMimeType(signature));

	// Generamos la contra-firma XAdES Baseline European Standard
	return signer.counterSign(signature, signatureAlgorithm, privateKey, extraParams, includeTimestamp, ISignatureFormatDetector.FORMAT_XADES_B_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a PAdES counter-signature over a PAdES signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a PAdES signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	Signer signer = new PadesSigner();

	// Generamos la firma PAdES
	String signatureForm = ISignatureFormatDetector.FORMAT_PADES_BES;
	if (includeSignaturePolicy) {
	    signatureForm = ISignatureFormatDetector.FORMAT_PADES_EPES;
	}
	return signer.counterSign(signature, signatureAlgorithm, privateKey, null, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a PAdES Baseline counter-signature Technical Specification over a PAdES Baseline signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a PAdES Baseline signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_Level}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_Level}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESBaselineTSCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	// Baseline Technical Specification 
	Signer signer = new PAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG008, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma PAdES Baseline Technical Specification 
	return signer.counterSign(signature, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a PAdES Baseline counter-signature European Standard over a PAdES Baseline counter-signature signature.
     * @param signature Parameter that represents the signature to counter-sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a PAdES Baseline signature with a counter-signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_B_Level}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_T_Level}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESBaselineENCounterSignature(byte[ ] signature, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	// Baseline European Standard
	Signer signer = new PAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG008, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma PAdES Baseline European Standard
	return signer.counterSign(signature, signatureAlgorithm, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_PADES_B_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that verifies if a value is not empty and not null.
     * @param value Parameter that represents the value to check.
     * @param errorMsg Parameter that represents the error message to include inside of the exception where the value is empty or null.
     * @throws SigningException If the value is empty or null.
     */
    private static void checkIsNotNullAndNotEmpty(String value, String errorMsg) throws SigningException {
	if (!GenericUtilsCommons.assertStringValue(value)) {
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that verifies if a value is signature type is PAdES or PAdES Baseline.
     * 
     * @param value Parameter that represents the value to check.
     * @param errorMsg Parameter that represents the error message to include inside of the exception where the value isn't PAdEs or PAdES Baseline.
     * @throws SigningException If the value isn't PAdES or PAdES Baseline.
     */
    private static void checkIsSignaturePades(String value, String errorMsg) throws SigningException {
	if (!value.equals(SignatureConstants.SIGN_FORMAT_PADES) && !value.equals(SignatureConstants.SIGN_FORMAT_PADES_BASELINE_TS)) {
	    LOGGER.error(errorMsg);
	    throw new SigningException(errorMsg);
	}
    }

    /**
     * Method that generates a PAdES signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param signatureType Parameter that indicates the signature type.
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * </ul>
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESSignatureWithRubric(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String signatureType, Properties extraParams, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	Signer signer = new PadesSigner();

	// Generamos la firma PAdES
	String signatureForm;
	if (ISignatureFormatDetector.FORMAT_PADES_BASIC.equals(signatureType)) {
	    signatureForm = ISignatureFormatDetector.FORMAT_PADES_BASIC;
	} else {
	    signatureForm = ISignatureFormatDetector.FORMAT_PADES_BES;
	}

	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, extraParams, includeTimestamp, signatureForm, null, idClient);
    }

    /**
     * Method that generates a PAdES Baseline Technical Specification signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * </ul>
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESBaselineTSSignatureWithRubric(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, Properties extraParams, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	// Baseline
	Signer signer = new PAdESBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // nojava
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG008, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma PAdES Baseline
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, extraParams, includeTimestamp, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a PAdES Baseline European Standard signature.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * </ul>
     * @param idClient client identifier of ws invocation.
     * @return a signature with one of the next formats:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
     * </ul>
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generatePAdESBaselineENSignatureWithRubric(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, Properties extraParams, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma PAdES
	// Baseline
	Signer signer = new PAdESBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(idClient);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas PDF
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_PDF_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // nojava
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG008, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma PAdES Baseline
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_IMPLICIT, privateKey, extraParams, includeTimestamp, ISignatureFormatDetector.FORMAT_PADES_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a ASiC-S CAdES Baseline Technical Specification.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature ASiC-S Baseline CAdES Baseline
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateASiCSCAdESBaselineTS(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma ASiC-S
	// Baseline Technical Specification
	Signer signer = new ASiCSBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(null);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas ASN1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma ASiC-S CAdES Baseline Technical Specification
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_CADES_B_LEVEL, policyID, idClient);
    }
    
    /**
     * Method that generates a ASiC-S CAdES Baseline European Standard.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature ASiC-S CAdES Baseline European Standard.
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateASiCSCAdESBaselineEN(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma ASiC-S
	// Baseline European Standard
	Signer signer = new ASiCSBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(null);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas ASN1
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_ASN1_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma ASiC-S CAdES Baseline European Standard
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_MODE_EXPLICIT, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_CADES_B_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a ASiC-S XAdES Baseline Technical Specification.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature ASiC-S CAdES Baseline Technical Specification.
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateASiCSXAdESBaselineTS(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma ASiC-S
	// Baseline Technical Specification
	Signer signer = new ASiCSBaselineTSSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(null);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas XML
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG007, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma ASiC-S XAdES Baseline Technical Specification.
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_XADES_B_LEVEL, policyID, idClient);
    }

    /**
     * Method that generates a ASiC-S XAdES Baseline European Specification.
     * @param dataToSign Parameter that represents the data to sign.
     * @param signatureAlgorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param includeSignaturePolicy Parameter that indicates if to include signature policy into the signature (true) or not (false).
     * @param includeTimestamp Parameter that indicates if to add a timestamp to the signature (true) or not (false).
     * @param idClient client identifier of ws invocation.
     * @return a signature ASiC-S CAdES Baseline European Specification.
     * @throws SigningException If the method fails.
     */
    private static byte[ ] generateASiCSXAdESBaselineEN(byte[ ] dataToSign, String signatureAlgorithm, PrivateKeyEntry privateKey, boolean includeSignaturePolicy, boolean includeTimestamp, String idClient) throws SigningException {
	// Instanciamos la implementación que generará la firma ASiC-S
	// Baseline European Specification
	Signer signer = new ASiCSBaselineENSigner();

	// Si se ha indicado que la firma debe contener política de
	// firma
	String policyID = null;
	if (includeSignaturePolicy) {
	    // Accedemos al archivo con las propiedades asociadas a las
	    // políticas de firma
	    Properties policyProperties = new IntegraProperties().getIntegraProperties(null);

	    // Rescatamos del archivo con las propiedades asociadas a
	    // las
	    // políticas de firma el identificador de la política de
	    // firma
	    // asociada a las firmas XML
	    policyID = (String) policyProperties.get(ISignPolicyConstants.KEY_XML_POLICY_ID);

	    // Comprobamos que el identificador de la política de firma
	    // no
	    // sea nulo ni vacío
	    if (!GenericUtilsCommons.assertStringValue(policyID)) {
		String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.IF_LOG007, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
		LOGGER.warn(errorMsg);
		policyID = null;
	    }
	}
	// Generamos la firma ASiC-S XAdES Baseline European Specification.
	return signer.sign(dataToSign, signatureAlgorithm, SignatureConstants.SIGN_FORMAT_XADES_DETACHED, privateKey, null, includeTimestamp, ISignatureFormatDetector.FORMAT_XADES_B_B_LEVEL, policyID, idClient);
    }
}
