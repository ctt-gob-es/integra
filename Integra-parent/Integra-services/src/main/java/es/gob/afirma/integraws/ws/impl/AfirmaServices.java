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
 * <b>File:</b><p>es.gob.afirma.integraws.ws.impl.AfirmaServices.java.</p>
 * <b>Description:</b><p> Class that contains afirma service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 17/03/2020.
 */
package es.gob.afirma.integraws.ws.impl;

import java.security.cert.CertificateException;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.IntegraFacadeWSDSSBind;
import es.gob.afirma.integraFacade.ValidateRequest;
import es.gob.afirma.integraFacade.pojo.ArchiveRequest;
import es.gob.afirma.integraFacade.pojo.ArchiveResponse;
import es.gob.afirma.integraFacade.pojo.AsynchronousResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureResponse;
import es.gob.afirma.integraFacade.pojo.CoSignRequest;
import es.gob.afirma.integraFacade.pojo.CounterSignRequest;
import es.gob.afirma.integraFacade.pojo.PendingRequest;
import es.gob.afirma.integraFacade.pojo.Result;
import es.gob.afirma.integraFacade.pojo.ServerSignerRequest;
import es.gob.afirma.integraFacade.pojo.ServerSignerResponse;
import es.gob.afirma.integraFacade.pojo.UpgradeSignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.VerifySignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerifySignatureResponse;
import es.gob.afirma.integraws.beans.RequestServerArchive;
import es.gob.afirma.integraws.beans.RequestServerBatchVerifyCertificate;
import es.gob.afirma.integraws.beans.RequestServerBatchVerifySignature;
import es.gob.afirma.integraws.beans.RequestServerCoSign;
import es.gob.afirma.integraws.beans.RequestServerCounterSign;
import es.gob.afirma.integraws.beans.RequestServerPending;
import es.gob.afirma.integraws.beans.RequestServerSign;
import es.gob.afirma.integraws.beans.RequestServerUpgradeSignature;
import es.gob.afirma.integraws.beans.RequestServerVerifyCertificate;
import es.gob.afirma.integraws.beans.RequestServerVerifySignature;
import es.gob.afirma.integraws.beans.RequestValidateOCSP;
import es.gob.afirma.integraws.beans.ResponseServerArchive;
import es.gob.afirma.integraws.beans.ResponseServerAsynchronous;
import es.gob.afirma.integraws.beans.ResponseServerBatchVerifyCertificate;
import es.gob.afirma.integraws.beans.ResponseServerBatchVerifySignature;
import es.gob.afirma.integraws.beans.ResponseServerSign;
import es.gob.afirma.integraws.beans.ResponseServerVerifyCertificate;
import es.gob.afirma.integraws.beans.ResponseServerVerifySignature;
import es.gob.afirma.integraws.beans.ResponseValidateOCSP;
import es.gob.afirma.integraws.ws.IAfirmaServices;
import es.gob.afirma.integraws.ws.IWSConstantKeys;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.ocsp.OCSPClient;
import es.gob.afirma.ocsp.OCSPClientException;
import es.gob.afirma.ocsp.OCSPEnhancedResponse;
import es.gob.afirma.utils.UtilsCertificate;

/**
 * <p>Class that contains afirma service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 17/03/2020.
 */
public class AfirmaServices implements IAfirmaServices {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(AfirmaServices.class);

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverValidateCertificateOcsp(es.gob.afirma.integraws.beans.RequestValidateOCSP)
     */
    public final ResponseValidateOCSP serverValidateCertificateOcsp(RequestValidateOCSP request) {
	ResponseValidateOCSP result = null;
	try {
	    if (request == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
		return new ResponseValidateOCSP(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	    } else {
		if (request.getIdClient() == null) {
		    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		    return new ResponseValidateOCSP(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
		}
		if (request.getCertificate() == null) {
		    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_003));
		    return new ResponseValidateOCSP(false, Language.getResIntegra(IWSConstantKeys.IWS_003));
		}
	    }
	    OCSPEnhancedResponse ocspResponse = OCSPClient.validateCertificate(UtilsCertificate.generateCertificate(request.getCertificate()), request.getIdClient());
	    result = new ResponseValidateOCSP(ocspResponse.getStatus(), ocspResponse.getErrorMsg(), ocspResponse.getRevocationDate(), ocspResponse.getMaxAge(), true);
	} catch (CertificateException e) {
	    LOGGER.error(e.getMessage(), e);
	    result = new ResponseValidateOCSP(false, e.getMessage());
	} catch (OCSPClientException e) {
	    LOGGER.error(e.getMessage(), e);
	    result = new ResponseValidateOCSP(false, e.getMessage());
	}
	return result;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverSign(es.gob.afirma.integraws.beans.RequestServerSign)
     */
    public final ResponseServerSign serverSign(RequestServerSign request) {
	ServerSignerRequest req = new ServerSignerRequest();
	if (request != null) {
	    if (request.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(request.getApplicationId());
	    req.setDocument(request.getDocument());
	    req.setDocumentHash(request.getDocumentHash());
	    req.setDocumentId(request.getDocumentId());
	    req.setDocumentRepository(request.getDocumentRepository());
	    req.setHashAlgorithm(request.getHashAlgorithm());
	    req.setIgnoreGracePeriod(request.isIgnoreGracePeriod());
	    req.setKeySelector(request.getKeySelector());
	    req.setSignatureFormat(request.getSignatureFormat());
	    req.setSignaturePolicyIdentifier(request.getSignaturePolicyIdentifier());
	    req.setXmlSignatureMode(request.getXmlSignatureMode());

	    String resultValidate = ValidateRequest.validateServerSignerRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerSign(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    ServerSignerResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().sign(req, request.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return returnResponseServerSignWithAfirmaMsg(resultAfirma.getResult());
	    }

	    return new ResponseServerSign(resultAfirma.getAsyncResponse(), resultAfirma.getTransactionId(), resultAfirma.getResult(), resultAfirma.getSignature(), resultAfirma.getSignatureFormat(), resultAfirma.getUpdatedSignature(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverCoSign(es.gob.afirma.integraws.beans.RequestServerCoSign)
     */
    public final ResponseServerSign serverCoSign(RequestServerCoSign coSigReq) {
	CoSignRequest req = new CoSignRequest();
	if (coSigReq != null) {
	    if (coSigReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(coSigReq.getApplicationId());
	    req.setDocument(coSigReq.getDocument());
	    req.setDocumentRepository(coSigReq.getDocumentRepository());
	    req.setHashAlgorithm(coSigReq.getHashAlgorithm());
	    req.setIgnoreGracePeriod(coSigReq.isIgnoreGracePeriod());
	    req.setKeySelector(coSigReq.getKeySelector());
	    req.setSignature(coSigReq.getSignature());
	    req.setSignaturePolicyIdentifier(coSigReq.getSignaturePolicyIdentifier());
	    req.setSignatureRepository(coSigReq.getSignatureRepository());
	    req.setTransactionId(coSigReq.getTransactionId());

	    String resultValidate = ValidateRequest.validateCoSignRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerSign(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    ServerSignerResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().coSign(req, coSigReq.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return returnResponseServerSignWithAfirmaMsg(resultAfirma.getResult());
	    }

	    return new ResponseServerSign(resultAfirma.getAsyncResponse(), resultAfirma.getTransactionId(), resultAfirma.getResult(), resultAfirma.getSignature(), resultAfirma.getSignatureFormat(), resultAfirma.getUpdatedSignature(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverCounterSign(es.gob.afirma.integraws.beans.RequestServerCounterSign)
     */
    public final ResponseServerSign serverCounterSign(RequestServerCounterSign couSigReq) {
	CounterSignRequest req = new CounterSignRequest();
	if (couSigReq != null) {
	    if (couSigReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(couSigReq.getApplicationId());
	    req.setHashAlgorithm(couSigReq.getHashAlgorithm());
	    req.setIgnoreGracePeriod(couSigReq.isIgnoreGracePeriod());
	    req.setKeySelector(couSigReq.getKeySelector());
	    req.setSignature(couSigReq.getSignature());
	    req.setSignaturePolicyIdentifier(couSigReq.getSignaturePolicyIdentifier());
	    req.setSignatureRepository(couSigReq.getSignatureRepository());
	    req.setTargetSigner(couSigReq.getTargetSigner());
	    req.setTransactionId(couSigReq.getTransactionId());

	    String resultValidate = ValidateRequest.validateCounterSignRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerSign(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    ServerSignerResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().counterSign(req, couSigReq.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return returnResponseServerSignWithAfirmaMsg(resultAfirma.getResult());
	    }

	    return new ResponseServerSign(resultAfirma.getAsyncResponse(), resultAfirma.getTransactionId(), resultAfirma.getResult(), resultAfirma.getSignature(), resultAfirma.getSignatureFormat(), resultAfirma.getUpdatedSignature(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverUpgradeSignature(es.gob.afirma.integraws.beans.RequestServerUpgradeSignature)
     */
    public final ResponseServerSign serverUpgradeSignature(RequestServerUpgradeSignature upgSigReq) {
	UpgradeSignatureRequest req = new UpgradeSignatureRequest();
	if (upgSigReq != null) {
	    if (upgSigReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    if (upgSigReq.getSignatureFormat() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_012));
		return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_012));
	    }
	    req.setApplicationId(upgSigReq.getApplicationId());
	    req.setIgnoreGracePeriod(upgSigReq.isIgnoreGracePeriod());
	    req.setSignature(upgSigReq.getSignature());
	    req.setSignatureFormat(upgSigReq.getSignatureFormat());
	    req.setSignatureRepository(upgSigReq.getSignatureRepository());
	    req.setTargetSigner(upgSigReq.getTargetSigner());
	    req.setTransactionId(upgSigReq.getTransactionId());

	    String resultValidate = ValidateRequest.validateUpgradeSignatureRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerSign(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    ServerSignerResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().upgradeSignature(req, upgSigReq.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return returnResponseServerSignWithAfirmaMsg(resultAfirma.getResult());
	    }

	    return new ResponseServerSign(resultAfirma.getAsyncResponse(), resultAfirma.getTransactionId(), resultAfirma.getResult(), resultAfirma.getSignature(), resultAfirma.getSignatureFormat(), resultAfirma.getUpdatedSignature(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * Auxiliary method that generates an server sign/co-sign/counter-sign response when the process fails.
     * @param result Afirma result object with the received information.
     * @return a response with the available information or a generic message if no information has been given.
     */
    private ResponseServerSign returnResponseServerSignWithAfirmaMsg(Result result) {
	if (result != null) {
	    String afirmaMsg = result.getResultMessage();
	    if (afirmaMsg != null && !afirmaMsg.isEmpty()) {
		return new ResponseServerSign(false, afirmaMsg);
	    }
	}
	return new ResponseServerSign(false, Language.getResIntegra(IWSConstantKeys.IWS_009));
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverAsynchronousRequest(es.gob.afirma.integraws.beans.RequestServerPending)
     */
    public final ResponseServerAsynchronous serverAsynchronousRequest(RequestServerPending pendingRequest) {
	PendingRequest req = new PendingRequest();
	if (pendingRequest != null) {
	    if (pendingRequest.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerAsynchronous(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(pendingRequest.getApplicationId());
	    req.setResponseId(pendingRequest.getResponseId());

	    String resultValidate = ValidateRequest.validatePendingRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerAsynchronous(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    AsynchronousResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().asynchronousRequest(req, pendingRequest.getIdClient());

	    if (resultAfirma.getBatVerCerRes() == null && resultAfirma.getBatVerSigRes() == null && resultAfirma.getInvAsyRes() == null && resultAfirma.getSerSigRes() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return new ResponseServerAsynchronous(false, Language.getResIntegra(IWSConstantKeys.IWS_009));
	    }

	    return new ResponseServerAsynchronous(resultAfirma.getBatVerCerRes(), resultAfirma.getBatVerSigRes(), resultAfirma.getInvAsyRes(), resultAfirma.getSerSigRes(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerAsynchronous(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverBatchVerifyCertificate(es.gob.afirma.integraws.beans.RequestServerBatchVerifyCertificate)
     */
    public final ResponseServerBatchVerifyCertificate serverBatchVerifyCertificate(RequestServerBatchVerifyCertificate batVerCerReq) {
	BatchVerifyCertificateRequest req = new BatchVerifyCertificateRequest();
	if (batVerCerReq != null) {
	    if (batVerCerReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerBatchVerifyCertificate(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(batVerCerReq.getApplicationId());
	    req.setListVerifyCertificate(batVerCerReq.getListVerifyCertificate());

	    String resultValidate = ValidateRequest.validateBatchVerifyCertificateRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerBatchVerifyCertificate(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    BatchVerifyCertificateResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().batchVerifyCertificate(req, batVerCerReq.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return new ResponseServerBatchVerifyCertificate(false, Language.getResIntegra(IWSConstantKeys.IWS_009));
	    }

	    return new ResponseServerBatchVerifyCertificate(resultAfirma.getAsyncResponse(), resultAfirma.getResult(), resultAfirma.getListVerifyResponse(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerBatchVerifyCertificate(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverBatchVerifySignature(es.gob.afirma.integraws.beans.RequestServerBatchVerifySignature)
     */
    public final ResponseServerBatchVerifySignature serverBatchVerifySignature(RequestServerBatchVerifySignature batVerSigReq) {
	BatchVerifySignatureRequest req = new BatchVerifySignatureRequest();
	if (batVerSigReq != null) {
	    if (batVerSigReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerBatchVerifySignature(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(batVerSigReq.getApplicationId());
	    req.setListVerifySignature(batVerSigReq.getListVerifySignature());

	    String resultValidate = ValidateRequest.validateBatchVerifySignatureRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerBatchVerifySignature(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    BatchVerifySignatureResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().batchVerifySignature(req, batVerSigReq.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return new ResponseServerBatchVerifySignature(false, Language.getResIntegra(IWSConstantKeys.IWS_009));
	    }

	    return new ResponseServerBatchVerifySignature(resultAfirma.getAsyncResponse(), resultAfirma.getListVerifyResponse(), resultAfirma.getResult(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerBatchVerifySignature(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverGetArchiveRetrieval(es.gob.afirma.integraws.beans.RequestServerArchive)
     */
    public final ResponseServerArchive serverGetArchiveRetrieval(RequestServerArchive archiveRequest) {
	ArchiveRequest req = new ArchiveRequest();
	if (archiveRequest != null) {
	    if (archiveRequest.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerArchive(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(archiveRequest.getApplicationId());
	    req.setTransactionId(archiveRequest.getTransactionId());

	    String resultValidate = ValidateRequest.validateArchiveRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerArchive(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    ArchiveResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().getArchiveRetrieval(req, archiveRequest.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return returnResponseServerArchiveRetrievalWithAfirmaMsg(resultAfirma.getResult());
	    }

	    return new ResponseServerArchive(resultAfirma.getResult(), resultAfirma.getSignature(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerArchive(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }
    
    /**
     * Auxiliary method that generates an server archive retrieval response when the process fails.
     * @param result Afirma result object with the received information.
     * @return a response with the available information or a generic message if no information has been given.
     */
    private ResponseServerArchive returnResponseServerArchiveRetrievalWithAfirmaMsg(Result result) {
	if (result != null) {
	    String afirmaMsg = result.getResultMessage();
	    if (afirmaMsg != null && !afirmaMsg.isEmpty()) {
		return new ResponseServerArchive(false, afirmaMsg);
	    }
	}
	return new ResponseServerArchive(false, Language.getResIntegra(IWSConstantKeys.IWS_009));
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverVerifySignature(es.gob.afirma.integraws.beans.RequestServerVerifySignature)
     */
    public final ResponseServerVerifySignature serverVerifySignature(RequestServerVerifySignature verSigReq) {
	VerifySignatureRequest req = new VerifySignatureRequest();
	if (verSigReq != null) {
	    if (verSigReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerVerifySignature(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(verSigReq.getApplicationId());
	    req.setDocument(verSigReq.getDocument());
	    req.setDocumentHash(verSigReq.getDocumentHash());
	    req.setDocumentRepository(verSigReq.getDocumentRepository());
	    req.setOptionalParameters(verSigReq.getOptionalParameters());
	    req.setSignature(verSigReq.getSignature());
	    req.setSignatureRepository(verSigReq.getSignatureRepository());
	    req.setVerificationReport(verSigReq.getVerificationReport());

	    String resultValidate = ValidateRequest.validateVerifySignerRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerVerifySignature(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    VerifySignatureResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().verifySignature(req, verSigReq.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return returnResponseServerVerifySigWithAfirmaMsg(resultAfirma.getResult());
	    }

	    return new ResponseServerVerifySignature(resultAfirma.getResult(), resultAfirma.getSignatureFormat(), resultAfirma.getSignedDataInfo(), resultAfirma.getVerificationReport(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerVerifySignature(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }
    
    /**
     * Auxiliary method that generates an server archive retrieval response when the process fails.
     * @param result Afirma result object with the received information.
     * @return a response with the available information or a generic message if no information has been given.
     */
    private ResponseServerVerifySignature returnResponseServerVerifySigWithAfirmaMsg(Result result) {
	if (result != null) {
	    String afirmaMsg = result.getResultMessage();
	    if (afirmaMsg != null && !afirmaMsg.isEmpty()) {
		return new ResponseServerVerifySignature(false, afirmaMsg);
	    }
	}
	return new ResponseServerVerifySignature(false, Language.getResIntegra(IWSConstantKeys.IWS_009));
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IAfirmaServices#serverVerifyCertificate(es.gob.afirma.integraws.beans.RequestServerVerifyCertificate)
     */
    public final ResponseServerVerifyCertificate serverVerifyCertificate(RequestServerVerifyCertificate verCerReq) {
	VerifyCertificateRequest req = new VerifyCertificateRequest();
	if (verCerReq != null) {
	    if (verCerReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseServerVerifyCertificate(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(verCerReq.getApplicationId());
	    req.setCertificate(verCerReq.getCertificate());
	    req.setCertificateRepository(verCerReq.getCertificateRepository());
	    req.setReturnReadableCertificateInfo(verCerReq.getReturnReadableCertificateInfo());
	    req.setReturnVerificationReport(verCerReq.getReturnVerificationReport());

	    String resultValidate = ValidateRequest.validateVerifyCertificateRequest(req);
	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseServerVerifyCertificate(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    VerifyCertificateResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().verifyCertificate(req, verCerReq.getIdClient());

	    if (resultAfirma.getResult() == null || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Invalid") || resultAfirma.getResult().getResultMajor() != null && resultAfirma.getResult().getResultMajor().contains("Error")) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_009));
		return returnResponseServerVerifyCertWithAfirmaMsg(resultAfirma.getResult());
	    }

	    return new ResponseServerVerifyCertificate(resultAfirma.getResult(), resultAfirma.getCertificatePathValidity(), resultAfirma.getReadableCertificateInfo(), true);

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseServerVerifyCertificate(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }
    
    /**
     * Auxiliary method that generates an server archive retrieval response when the process fails.
     * @param result @firma result object with the received information.
     * @return a response with the available information or a generic message if no information has been given.
     */
    private ResponseServerVerifyCertificate returnResponseServerVerifyCertWithAfirmaMsg(Result result) {
	if (result != null) {
	    String afirmaMsg = result.getResultMessage();
	    if (afirmaMsg != null && !afirmaMsg.isEmpty()) {
		return new ResponseServerVerifyCertificate(false, afirmaMsg);
	    }
	}
	return new ResponseServerVerifyCertificate(false, Language.getResIntegra(IWSConstantKeys.IWS_009));
    }

}
