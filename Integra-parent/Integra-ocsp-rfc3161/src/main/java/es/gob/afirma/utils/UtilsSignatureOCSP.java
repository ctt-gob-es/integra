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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsSignature.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>07/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 07/11/2014.
 */
package es.gob.afirma.utils;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.OCSPRespStatus;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.ocsp.OCSPClient;
import es.gob.afirma.ocsp.OCSPEnhancedResponse;
import es.gob.afirma.signature.SigningException;

/**
 * <p>Class that contains methods related to the manage of signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 07/11/2014.
 */
public final class UtilsSignatureOCSP {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsSignatureOCSP.class);

    /**
     * Constructor method for the class SignatureUtils.java.
     */
    private UtilsSignatureOCSP() {
    }

    /**
     * Method that validates a certificate against an OCSP responder.
     * @param certificateToValidate Parameter that represents the certificate to validate.
     * @param validationDate Parameter that represents the validation date.
     * @param idClient Parameter that represents the client application identifier.
     * @throws SigningException If the method fails or the certificate isn't correct and valid.
     */
    public static void validateCertificateViaOCSP(X509Certificate certificateToValidate, Date validationDate, String idClient) throws SigningException {
	LOGGER.debug(Language.getResIntegra(ILogConstantKeys.US_LOG006));

	OCSPEnhancedResponse ocspEnhancedResponse = null;
	try {
	    ocspEnhancedResponse = OCSPClient.validateCertificate(certificateToValidate, idClient);
	} catch (Exception e) {
	    String msgError = Language.getResIntegra(ILogConstantKeys.US_LOG034);
	    LOGGER.error(msgError, e);
	    throw new SigningException(msgError, e);
	}

	// Comprobamos el estado de la respuesta
	checkOCSPResponseStatus(ocspEnhancedResponse.getStatus());

	// Procesamos la respuesta OCSP
	processOCSPResponse(ocspEnhancedResponse, validationDate);
    }

    /**
     * Method that verifies if the OCSP response has some associated error and if the certificate is revoked or not.
     * @param ocspEnhancedResponse Parameter that represents the OCSP response with the date when the cached OCSP response expires, as defined on the lightweight
     * profile recommendations defined in the RFC 5019.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException If the status isn't correct.
     */
    private static void processOCSPResponse(OCSPEnhancedResponse ocspEnhancedResponse, Date validationDate) throws SigningException {
	// Comprobamos si hay un error asociado a la respuesta
	if (ocspEnhancedResponse.getErrorMsg() != null) {
	    LOGGER.error(ocspEnhancedResponse.getErrorMsg());
	    throw new SigningException(ocspEnhancedResponse.getErrorMsg());
	} else {
	    // Comprobamos si el certificado está revocado
	    Date revocationDate = ocspEnhancedResponse.getRevocationDate();
	    // Comprobamos que la fecha de revocación sea anterior a la
	    // fecha de validación, si no, quiere decir que el certificado
	    // no estaba revocado
	    // en la fecha de verificación
	    if (revocationDate != null && revocationDate.before(validationDate)) {
		String msgError = Language.getResIntegra(ILogConstantKeys.US_LOG082);
		LOGGER.error(msgError);
		throw new SigningException(msgError);
	    }
	}
    }

    /**
     * Method that checks the value of the status field included into the OCSP response.
     * @param status Parameter that represents the status field.
     * @throws SigningException If the value of the status field is different to {@link OCSPRespStatus#SUCCESSFUL}
     */
    private static void checkOCSPResponseStatus(int status) throws SigningException {
	String msgError = null;
	switch (status) {
	    case OCSPRespStatus.INTERNAL_ERROR:
		msgError = Language.getResIntegra(ILogConstantKeys.US_LOG089);
		break;
	    case OCSPRespStatus.MALFORMED_REQUEST:
		msgError = Language.getResIntegra(ILogConstantKeys.US_LOG088);
		break;
	    case OCSPRespStatus.SIGREQUIRED:
		msgError = Language.getResIntegra(ILogConstantKeys.US_LOG087);
		break;
	    case OCSPRespStatus.TRY_LATER:
		msgError = Language.getResIntegra(ILogConstantKeys.US_LOG086);
		break;
	    case OCSPRespStatus.UNAUTHORIZED:
		msgError = Language.getResIntegra(ILogConstantKeys.US_LOG084);
	    case OCSPRespStatus.SUCCESSFUL:
		break;
	    default:
		msgError = Language.getResIntegra(ILogConstantKeys.US_LOG083);
	}

	if (msgError != null) {
	    LOGGER.error(msgError);
	    throw new SigningException(msgError);
	}
    }

}
