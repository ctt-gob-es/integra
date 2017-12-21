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
 * <b>File:</b><p>es.gob.afirma.integraFacade.ValidateRequest.java.</p>
 * <b>Description:</b><p>Class that manages the verification of the requests for @Firma web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>16/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 16/12/2014.
 */
package es.gob.afirma.integraFacade;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.pojo.ArchiveRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureRequest;
import es.gob.afirma.integraFacade.pojo.CoSignRequest;
import es.gob.afirma.integraFacade.pojo.ContentRequest;
import es.gob.afirma.integraFacade.pojo.CounterSignRequest;
import es.gob.afirma.integraFacade.pojo.DocumentRequest;
import es.gob.afirma.integraFacade.pojo.PendingRequest;
import es.gob.afirma.integraFacade.pojo.Repository;
import es.gob.afirma.integraFacade.pojo.ServerSignerRequest;
import es.gob.afirma.integraFacade.pojo.TimestampRequest;
import es.gob.afirma.integraFacade.pojo.UpgradeSignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.VerifySignatureRequest;
import es.gob.afirma.utils.DSSConstants;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.GenericUtilsCommons;

/**
 * <p>Class that manages the verification of the requests for @Firma web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 16/12/2014.
 */
public final class ValidateRequest {

    /**
     * Constructor method for the class ValidateRequest.java.
     */
    private ValidateRequest() {
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the server signature service are correct.
     * @param serSigReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateServerSignerRequest(ServerSignerRequest serSigReq) {
	String result = null;

	if (serSigReq.getDocumentHash() != null && !GenericUtilsCommons.assertArrayValid(serSigReq.getDocumentHash().getDigestValue()) && !GenericUtilsCommons.assertArrayValid(serSigReq.getDocument()) && (!GenericUtilsCommons.assertStringValue(serSigReq.getDocumentId()) || GenericUtilsCommons.checkNullValues(serSigReq.getDocumentRepository()))) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG018);
	} else if (!GenericUtilsCommons.assertStringValue(serSigReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (!GenericUtilsCommons.assertStringValue(serSigReq.getKeySelector())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.KEY_SELECTOR });
	} else if (serSigReq.getDocumentRepository() != null && (!GenericUtilsCommons.assertStringValue(serSigReq.getDocumentRepository().getId()) || !GenericUtilsCommons.assertStringValue(serSigReq.getDocumentRepository().getObject()))) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG021);
	}
	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the server co-signature service are correct.
     * @param coSigReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateCoSignRequest(CoSignRequest coSigReq) {
	String result = null;
	if (!GenericUtilsCommons.assertStringValue(coSigReq.getTransactionId()) && (!GenericUtilsCommons.assertArrayValid(coSigReq.getSignature()) || !GenericUtilsCommons.assertArrayValid(coSigReq.getDocument())) && (coSigReq.getSignatureRepository() == null || coSigReq.getDocumentRepository() == null)) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG023, new Object[ ] { GeneralConstants.TRANSACTION_ID, GeneralConstants.DOC_REPOSITORY, GeneralConstants.SIG_REPOSITORY });
	} else if (!GenericUtilsCommons.assertStringValue(coSigReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (!GenericUtilsCommons.assertStringValue(coSigReq.getKeySelector())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.KEY_SELECTOR });
	} else if (checkRepository(coSigReq.getDocumentRepository())) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG024);
	} else if (checkRepository(coSigReq.getSignatureRepository())) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG025);
	}

	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the server counter-signature service are correct.
     * @param couSigReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateCounterSignRequest(CounterSignRequest couSigReq) {
	String result = null;
	if (!GenericUtilsCommons.assertStringValue(couSigReq.getTransactionId()) && !GenericUtilsCommons.assertArrayValid(couSigReq.getSignature()) && couSigReq.getSignatureRepository() == null) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG026, new Object[ ] { GeneralConstants.TRANSACTION_ID, GeneralConstants.SIG_REPOSITORY, GeneralConstants.SIGNATURE });
	} else if (!GenericUtilsCommons.assertStringValue(couSigReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (!GenericUtilsCommons.assertStringValue(couSigReq.getKeySelector())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.KEY_SELECTOR });
	}
	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the verify signature service are correct.
     * @param verSigReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateVerifySignerRequest(VerifySignatureRequest verSigReq) {
	String result = null;
	// signature y signatureRepository no pueden ser las dos nulas
	if (!GenericUtilsCommons.assertArrayValid(verSigReq.getSignature()) && verSigReq.getSignatureRepository() == null) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG029);
	} else if (!GenericUtilsCommons.assertStringValue(verSigReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	}

	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the upgrade signature service are correct.
     * @param upgSigReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateUpgradeSignatureRequest(UpgradeSignatureRequest upgSigReq) {
	String result = null;
	// no puede estar a null signature y signatureRepository
	if (!GenericUtilsCommons.assertArrayValid(upgSigReq.getSignature()) && GenericUtilsCommons.checkNullValues(upgSigReq.getSignatureRepository())) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG029);
	} else if (!GenericUtilsCommons.checkNullValues(upgSigReq.getSignatureRepository()) && upgSigReq.getTransactionId() == null) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.TRANSACTION_ID });
	} else if (!GenericUtilsCommons.assertStringValue(upgSigReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	}
	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the verify certificate service are correct.
     * @param verCerReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateVerifyCertificateRequest(VerifyCertificateRequest verCerReq) {
	String result = null;
	// no puede estar a null signature y signatureRepository
	if (!GenericUtilsCommons.assertArrayValid(verCerReq.getCertificate()) && GenericUtilsCommons.checkNullValues(verCerReq.getCertificateRepository())) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG029);
	} else if (!GenericUtilsCommons.assertStringValue(verCerReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	}
	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the verify signatures on batch service are correct.
     * @param batVerSigReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateBatchVerifySignatureRequest(BatchVerifySignatureRequest batVerSigReq) {
	String result = null;
	if (!GenericUtilsCommons.assertStringValue(batVerSigReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (batVerSigReq.getListVerifySignature() == null || batVerSigReq.getListVerifySignature().isEmpty()) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG034);
	}
	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the verify certificates on batch service are correct.
     * @param batVerCerReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateBatchVerifyCertificateRequest(BatchVerifyCertificateRequest batVerCerReq) {
	String result = null;
	if (!GenericUtilsCommons.assertStringValue(batVerCerReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (batVerCerReq.getListVerifyCertificate() == null || batVerCerReq.getListVerifyCertificate().isEmpty()) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG035);
	}
	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the async processes of sign and verify service are correct.
     * @param pendingRequest Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validatePendingRequest(PendingRequest pendingRequest) {
	String result = null;
	if (!GenericUtilsCommons.assertStringValue(pendingRequest.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (!GenericUtilsCommons.assertStringValue(pendingRequest.getResponseId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.RESPONSE_ID });
	}

	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the archive signatures retrieve service are correct.
     * @param archiveRequest Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateArchiveRequest(ArchiveRequest archiveRequest) {
	String result = null;
	if (!GenericUtilsCommons.assertStringValue(archiveRequest.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (!GenericUtilsCommons.assertStringValue(archiveRequest.getTransactionId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.TRANSACTION_ID });
	}

	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the services related to the content of a document are correct.
     * @param conReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateContentRequest(ContentRequest conReq) {
	String result = null;
	if (!GenericUtilsCommons.assertStringValue(conReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (!GenericUtilsCommons.assertStringValue(conReq.getTransactionId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.TRANSACTION_ID });
	}
	return result;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the services related to retrieve a document are correct.
     * @param docReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateDocumentRequest(DocumentRequest docReq) {
	String result = null;

	if (!GenericUtilsCommons.assertStringValue(docReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	} else if (!GenericUtilsCommons.assertArrayValid(docReq.getDocument())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.DOCUMENT });
	} else if (!GenericUtilsCommons.assertStringValue(docReq.getName())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.NAME });
	} else if (!GenericUtilsCommons.assertStringValue(docReq.getType())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.TYPE });
	}
	return result;
    }

    /**
     * Method that validates whether the information related to locate a document repository or a document manager is correct (true) or not (false).
     * @param repository Parameter that represents the information related to locate a document repository or a document manager.
     * @return a boolean that indicates whether the information related to locate a document repository or a document manager is correct (true) or not (false).
     */
    private static boolean checkRepository(Repository repository) {

	if (!GenericUtilsCommons.checkNullValues(repository) && (GenericUtilsCommons.assertStringValue(repository.getId()) || GenericUtilsCommons.assertStringValue(repository.getObject()))) {
	    return true;
	}
	return false;
    }

    /**
     * Method that validates whether the attributes for the request message to invoke the server signature service are correct.
     * @param timestampReq Parameter that represents the request message.
     * @return a message with the result of the validation.
     */
    public static String validateTimestampRequest(TimestampRequest timestampReq) {
	String result = null;

	if (timestampReq.getTimestampType() == null || timestampReq.getTimestampType().getType().isEmpty()) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG052);
	} else if (timestampReq.getDocumentHash() != null && !GenericUtilsCommons.assertArrayValid(timestampReq.getDocumentHash().getDigestValue()) && (DSSConstants.AlgorithmTypes.SHA1.equals(timestampReq.getDocumentHash().getDigestMethod().getUri()) || DSSConstants.AlgorithmTypes.SHA256.equals(timestampReq.getDocumentHash().getDigestMethod().getUri()))) {
	    result = Language.getResIntegra(ILogConstantKeys.IFWS_LOG018);
	} else if (!GenericUtilsCommons.assertStringValue(timestampReq.getApplicationId())) {
	    result = Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG019, new Object[ ] { GeneralConstants.APPLICATION_ID });
	}
	return result;
    }
}
