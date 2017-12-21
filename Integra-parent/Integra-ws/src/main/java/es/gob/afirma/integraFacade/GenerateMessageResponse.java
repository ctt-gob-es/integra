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
 * <b>File:</b><p>es.gob.afirma.integraFacade.GenerateMessageResponse.java.</p>
 * <b>Description:</b><p>Class that manages the generation of response messages to invoke the DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 06/10/2017.
 */
package es.gob.afirma.integraFacade;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.pojo.ArchiveResponse;
import es.gob.afirma.integraFacade.pojo.AsynchronousResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureResponse;
import es.gob.afirma.integraFacade.pojo.CertificatePathValidity;
import es.gob.afirma.integraFacade.pojo.CertificateValidity;
import es.gob.afirma.integraFacade.pojo.DataInfo;
import es.gob.afirma.integraFacade.pojo.Detail;
import es.gob.afirma.integraFacade.pojo.DocumentHash;
import es.gob.afirma.integraFacade.pojo.HashAlgorithmEnum;
import es.gob.afirma.integraFacade.pojo.IndividualSignatureReport;
import es.gob.afirma.integraFacade.pojo.InvalidAsyncResponse;
import es.gob.afirma.integraFacade.pojo.ProcessingDetail;
import es.gob.afirma.integraFacade.pojo.Result;
import es.gob.afirma.integraFacade.pojo.ServerSignerResponse;
import es.gob.afirma.integraFacade.pojo.TimestampResponse;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.VerifySignatureResponse;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.DSSConstants;
import es.gob.afirma.utils.DSSTagsResponse;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that manages the generation of response messages to invoke the DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 06/10/2017.
 */
@SuppressWarnings("unchecked")
public final class GenerateMessageResponse {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(GenerateMessageResponse.class);

    /**
     * Constructor method for the class GenerateMessageResponse.java.
     */
    private GenerateMessageResponse() {
    }

    /**
     * Method that processes the response of a server signature service, server co-signature service, server counter-signature service or upgrade signature
     * service to transform it to a {@link ServerSignerResponse} object.
     * @param propertiesResult Parameter that represents the response of the web service as a map.
     * @param serSigRes Parameter that represents the object to update.
     */
    public static void generateServerSignerResponse(Map<String, Object> propertiesResult, ServerSignerResponse serSigRes) {

	// Result
	serSigRes.setResult(getResultResponse(propertiesResult));

	// signatureFormat
	if (propertiesResult.get(DSSTagsResponse.SIGNATURE_TYPE) != null) {
	    serSigRes.setSignatureFormat(getSignatureFormat(propertiesResult));
	}
	// transactionId
	if (propertiesResult.get(DSSTagsResponse.ARCHIVE_IDENTIFIER) != null) {
	    serSigRes.setTransactionId(propertiesResult.get(DSSTagsResponse.ARCHIVE_IDENTIFIER).toString());
	}
	// signature
	serSigRes.setSignature(getSignature(propertiesResult));

	// asyncResponse
	if (propertiesResult.get(DSSTagsResponse.RESPONSE_ID) != null) {
	    serSigRes.setAsyncResponse(getAsyncResponse(propertiesResult));
	}

	if (serSigRes.getSignature() == null) {
	    try {
		throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.IFWS_LOG032));
	    } catch (WSServiceInvokerException e) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG022, new Object[ ] { e.getMessage() }));
	    }
	}

    }

    /**
     * Method that processes the response of a verify signature service to transform it to a {@link VerifySignatureResponse} object.
     * @param propertiesResult Parameter that represents the response of the web service as a map.
     * @param verSigRes Parameter that represents the object to update.
     */
    public static void generateVerifySignatureResponse(Map<String, Object> propertiesResult, VerifySignatureResponse verSigRes) {
	// Result
	verSigRes.setResult(getResultResponse(propertiesResult));

	// signatureFormat
	verSigRes.setSignatureFormat(getSignatureFormat(propertiesResult));

	// list<IndividualSignatureReport> vr:VerificationReport
	List<IndividualSignatureReport> listIndSigRep = generateListIndividualSignatureReport(propertiesResult);
	verSigRes.setVerificationReport(listIndSigRep);

	// List<DataInfo> signedDataInfo
	List<DataInfo> signedDataInfo = generateListDataInfo(propertiesResult);
	verSigRes.setSignedDataInfo(signedDataInfo);

    }

    /**
     * Method that processes the response of a verify certificate service to transform it to a {@link VerifyCertificateResponse} object.
     * @param propertiesResult Parameter that represents the response of the web service as a map.
     * @param verCerRes Parameter that represents the object to update.
     */
    public static void generateVerifyCertificateResponse(Map<String, Object> propertiesResult, VerifyCertificateResponse verCerRes) {
	// Result
	verCerRes.setResult(getResultResponse(propertiesResult));

	// verCerRes.setCertificatePathValidity(certificatePathValidity)
	verCerRes.setCertificatePathValidity(getCertificatePathValidity(propertiesResult));

	// readableCertificateInfo
	// (dss:OptionalOutputs/afxp:ReadableCertificateInfo)
	Map<String, String> certificateInfo = (Map<String, String>) propertiesResult.get(DSSTagsResponse.READABLE_CERT_INFO);
	verCerRes.setReadableCertificateInfo(certificateInfo);
    }

    /**
     * Method that removes from the keys of a map certain text.
     * @param mapToProcess Parameter that represents the map to process.
     * @param textToRemove Parameter that represents the text to remove from the keys.
     */
    private static void replaceKeysFromMap(Map<String, Object> mapToProcess, String textToRemove) {
	String[ ] keyArray = mapToProcess.keySet().toArray(new String[mapToProcess.size()]);
	Set<String> tempSet = new HashSet<String>();
	for (String orginalKeys: keyArray) {
	    String newKey = orginalKeys.replace(textToRemove, "");
	    if (!newKey.equals(orginalKeys)) {
		mapToProcess.put(newKey, mapToProcess.get(orginalKeys));
		tempSet.add(orginalKeys);
		mapToProcess.remove(orginalKeys);
	    }
	}
    }

    /**
     * Method that processes the response of a verify signatures on batch service to transform it to a {@link BatchVerifySignatureResponse} object.
     * @param propertiesResult Parameter that represents the response of the web service as a map.
     * @param batVerSigRes Parameter that represents the object to update.
     */
    public static void generateBatchVerifySignatureResponse(Map<String, Object> propertiesResult, BatchVerifySignatureResponse batVerSigRes) {
	// Result
	batVerSigRes.setResult(getResultResponse(propertiesResult));

	// si está pendiente de procesado, devuelve async:ResponseID y
	// afxp:ResponseTime
	if (propertiesResult.get(DSSTagsResponse.BATCH_RESPONSE_ID) != null) {
	    String asyncResponse = propertiesResult.get(DSSTagsResponse.BATCH_RESPONSE_ID).toString();
	    if (propertiesResult.get(DSSTagsResponse.BATCH_RESPONSE_TIME) != null) {
		asyncResponse = asyncResponse + " - " + propertiesResult.get(DSSTagsResponse.BATCH_RESPONSE_TIME).toString();
	    }
	    batVerSigRes.setAsyncResponse(asyncResponse);
	}

	// si la petición está ya procesada, se tiene que obtener lista de
	// VerifySignatureResponse
	if (propertiesResult.get(DSSTagsResponse.RESULT_MAJOR).equals(DSSConstants.ResultProcessIds.SUCESS)) {
	    List<VerifySignatureResponse> listVerifySignatureResponses = new ArrayList<VerifySignatureResponse>();
	    Map<String, Object>[ ] arrayresponses = (HashMap<String, Object>[ ]) propertiesResult.get(DSSTagsResponse.BATCH_RESPONSES + DSSTagsResponse.VERIFY_RESPONSE);
	    if (arrayresponses != null) {
		for (int i = 0; i < arrayresponses.length; i++) {
		    Map<String, Object> verifyResponseMap = (HashMap<String, Object>) arrayresponses[i];
		    // Eliminamos la cadena de texto
		    // afxp:Responses/dss:VerifyResponse/ de todas las claves
		    // del mapa
		    replaceKeysFromMap(verifyResponseMap, DSSTagsResponse.BATCH_RESPONSES + DSSTagsResponse.VERIFY_RESPONSE + "/");
		    Map<String, Object>[ ] signReports = (HashMap<String, Object>[ ]) verifyResponseMap.get(DSSTagsResponse.INDIVIDUAL_SIGNATURE_REPORT);
		    if (signReports != null) {
			for (int j = 0; j < signReports.length; j++) {
			    Map<String, Object> individualSignatureReportMap = (HashMap<String, Object>) signReports[j];
			    // Eliminamos la cadena de texto
			    // afxp:Responses/dss:VerifyResponse/ de todas las
			    // claves del mapa
			    replaceKeysFromMap(individualSignatureReportMap, DSSTagsResponse.BATCH_RESPONSES + DSSTagsResponse.VERIFY_RESPONSE + "/");
			}
		    }
		    VerifySignatureResponse verifySignatureResponse = new VerifySignatureResponse();
		    generateVerifySignatureResponse(verifyResponseMap, verifySignatureResponse);
		    listVerifySignatureResponses.add(verifySignatureResponse);
		}
	    }
	    batVerSigRes.setListVerifyResponse(listVerifySignatureResponses);
	}
    }

    /**
     * Method that processes the response of a verify certificates on batch service to transform it to a {@link BatchVerifyCertificateResponse} object.
     * @param propertiesResult Parameter that represents the response of the web service as a map.
     * @param batVerCerRes Parameter that represents the object to update.
     */
    public static void generateBatchVerifyCertificateResponse(Map<String, Object> propertiesResult, BatchVerifyCertificateResponse batVerCerRes) {
	batVerCerRes.setResult(getResultResponse(propertiesResult));

	if (propertiesResult.get(DSSTagsResponse.BATCH_RESPONSE_ID) != null) {
	    String asyncResponse = propertiesResult.get(DSSTagsResponse.BATCH_RESPONSE_ID).toString();
	    if (propertiesResult.get(DSSTagsResponse.BATCH_RESPONSE_TIME) != null) {
		asyncResponse = asyncResponse + " - " + propertiesResult.get(DSSTagsResponse.BATCH_RESPONSE_TIME).toString();
	    }
	    batVerCerRes.setAsyncResponse(asyncResponse);
	}
	if (propertiesResult.get(DSSTagsResponse.RESULT_MAJOR).equals(DSSConstants.ResultProcessIds.SUCESS)) {
	    List<VerifyCertificateResponse> listVerifyCertificateResponses = new ArrayList<VerifyCertificateResponse>();
	    Map<String, Object>[ ] arrayresponses = (HashMap<String, Object>[ ]) propertiesResult.get(DSSTagsResponse.BATCH_RESPONSES + DSSTagsResponse.VERIFY_RESPONSE);
	    if (arrayresponses != null) {
		for (int i = 0; i < arrayresponses.length; i++) {
		    Map<String, Object> verifyResponseMap = (HashMap<String, Object>) arrayresponses[i];
		    replaceKeysFromMap(verifyResponseMap, DSSTagsResponse.BATCH_RESPONSES + DSSTagsResponse.VERIFY_RESPONSE + "/");

		    VerifyCertificateResponse verifyCertificateResponse = new VerifyCertificateResponse();
		    generateVerifyCertificateResponse(verifyResponseMap, verifyCertificateResponse);
		    listVerifyCertificateResponses.add(verifyCertificateResponse);
		}
	    }
	    batVerCerRes.setListVerifyResponse(listVerifyCertificateResponses);
	}
    }

    /**
     * Method that processes the response of an async processes service to transform it to a {@link AsynchronousResponse} object.
     * @param propertiesResult Parameter that represents the response of the web service as a map.
     * @param asyncResponse Parameter that represents the object to update.
     * @param service Parameter that represents the name async service process.
     */
    public static void generateAsynchronousResponse(Map<String, Object> propertiesResult, AsynchronousResponse asyncResponse, String service) {
	if (service.equals(GeneralConstants.SERVER_SIGNER_RESPONSE)) {
	    ServerSignerResponse serSigRes = new ServerSignerResponse();
	    generateServerSignerResponse(propertiesResult, serSigRes);
	    asyncResponse.setSerSigRes(serSigRes);

	} else if (service.equals(GeneralConstants.BATH_VERIFY_CERTIFICATE)) {
	    BatchVerifyCertificateResponse batVerCerRes = new BatchVerifyCertificateResponse();
	    generateBatchVerifyCertificateResponse(propertiesResult, batVerCerRes);
	    asyncResponse.setBatVerCerRes(batVerCerRes);

	} else if (service.equals(GeneralConstants.BATH_VERIFY_SIGNATURE)) {
	    BatchVerifySignatureResponse batVerSigRes = new BatchVerifySignatureResponse();
	    generateBatchVerifySignatureResponse(propertiesResult, batVerSigRes);
	    asyncResponse.setBatVerSigRes(batVerSigRes);
	} else if (service.equals(GeneralConstants.INVALID_ASYNC_RESPONSE)) {
	    InvalidAsyncResponse invAsyRes = new InvalidAsyncResponse();
	    invAsyRes.setResult(getResultResponse(propertiesResult));
	    asyncResponse.setInvAsyRes(invAsyRes);
	}
    }

    /**
     * Method that processes the response of an archive signatures retrieve service to transform it to a {@link ArchiveResponse} object.
     * @param propertiesResult Parameter that represents the response of the web service as a map.
     * @param archiveResponse Parameter that represents the object to update.
     */
    public static void generateArchiveResponse(Map<String, Object> propertiesResult, ArchiveResponse archiveResponse) {
	// Result
	archiveResponse.setResult(getResultResponse(propertiesResult));
	// Signature
	archiveResponse.setSignature(getSignature(propertiesResult));
    }

    /**
     * Method that obtains an object with the information about the validation process of a signning certificate.
     * @param propertiesResult Parameter that represents the information about the validation process of a signning certificate.
     * @return the object with the information about the validation process of the signning certificate.
     */
    private static CertificatePathValidity getCertificatePathValidity(Map<String, Object> propertiesResult) {

	CertificatePathValidity cerPathVal = new CertificatePathValidity();
	// identifier
	if (propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_IDENTIFIER_ISSUER) != null) {
	    String identifier = propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_IDENTIFIER_ISSUER).toString();
	    if (propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_IDENTIFIER_SER_NUM) != null) {
		identifier = identifier + " - " + propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_IDENTIFIER_SER_NUM).toString();
	    }
	    cerPathVal.setIdentifier(identifier);
	}

	// summary
	Detail summary = new Detail();
	if (propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_SUMMARY_TYPE) != null) {
	    summary.setType(propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_SUMMARY_TYPE).toString());
	}
	if (propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_SUMMARY_CODE) != null) {
	    summary.setCode(propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_SUMMARY_CODE).toString());
	}

	if (propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_SUMMARY_MESSAGE) != null) {
	    summary.setType(propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_SUMMARY_MESSAGE).toString());
	}
	cerPathVal.setSummary(summary);

	// details
	if (propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_DETAIL) != null) {
	    List<CertificateValidity> listCertificateValidity = new ArrayList<CertificateValidity>();
	    // se obtiene array de CertificateValidity
	    HashMap<String, String>[ ] arrayCertificateValidity = (HashMap<String, String>[ ]) propertiesResult.get(DSSTagsResponse.CERT_PATH_VAL_DETAIL);
	    for (int i = 0; i < arrayCertificateValidity.length; i++) {
		HashMap<String, String> cerValHashMap = arrayCertificateValidity[i];
		CertificateValidity cerVal = new CertificateValidity();
		for (String key: cerValHashMap.keySet()) {
		    cerVal.getInfoMap().put(key, cerValHashMap.get(key));
		}
		listCertificateValidity.add(cerVal);
	    }
	    cerPathVal.setDetail(listCertificateValidity);
	}

	return cerPathVal;
    }

    /**
     * Method that obtains an object with the information about the result of a web service.
     * @param propertiesResult Parameter that represents the information about the response of the web service.
     * @return the object with the information about the result of the web service.
     */
    private static Result getResultResponse(Map<String, Object> propertiesResult) {
	Result result = new Result();
	result.setResultMajor(propertiesResult.get(DSSTagsResponse.RESULT_MAJOR).toString());

	if (propertiesResult.get(DSSTagsResponse.RESULT_MINOR) != null) {
	    result.setResultMinor(propertiesResult.get(DSSTagsResponse.RESULT_MINOR).toString());
	}
	if (propertiesResult.get(DSSTagsResponse.RESULT_MESSAGE) != null) {
	    result.setResultMessage(propertiesResult.get(DSSTagsResponse.RESULT_MESSAGE).toString());
	}

	return result;
    }

    /**
     * Method that obtains the signature format from the response of a web service.
     * @param propertiesResult Parameter that represents the information about the response of the web service.
     * @return the signature format.
     */
    private static String getSignatureFormat(Map<String, Object> propertiesResult) {
	String signatureFormat = null;
	if (propertiesResult.get(DSSTagsResponse.SIGNATURE_TYPE) != null) {
	    String type = propertiesResult.get(DSSTagsResponse.SIGNATURE_TYPE).toString();
	    String form = null;
	    if (propertiesResult.get(DSSTagsResponse.SIGNATURE_FORM) != null) {
		form = propertiesResult.get(DSSTagsResponse.SIGNATURE_FORM).toString();
	    }
	    if (GenericUtilsCommons.assertStringValue(form)) {
		signatureFormat = type + "-" + form;
	    } else {
		signatureFormat = type;
	    }
	}
	return signatureFormat;
    }

    /**
     * Method that obtains the identifier of an async web service response.
     * @param propertiesResult Parameter that represents the information about the response of the web service.
     * @return the identifier of the async web service response.
     */
    private static String getAsyncResponse(Map<String, Object> propertiesResult) {
	String asyncResponse = null;

	String id = propertiesResult.get(DSSTagsResponse.RESPONSE_ID).toString();
	String time = propertiesResult.get(DSSTagsResponse.RESPONSE_ID).toString();

	if (time != null) {
	    asyncResponse = id + "-" + time;
	} else {
	    asyncResponse = id;
	}
	return asyncResponse;
    }

    /**
     * Method that obtains the signature from a web service response.
     * @param propertiesResult Parameter that represents the information about the response of the web service.
     * @return the signature from the web service response.
     */
    private static byte[ ] getSignature(Map<String, Object> propertiesResult) {
	byte[ ] signature = null;
	String signatureEncoded = null;
	try {
	    if (propertiesResult.get(DSSTagsResponse.DOCUMENT_WITH_SIGNATURE) != null) {
		signatureEncoded = propertiesResult.get(DSSTagsResponse.DOCUMENT_WITH_SIGNATURE).toString();
		signature = Base64CoderCommons.decodeBase64(signatureEncoded.getBytes());
	    }
	    if (propertiesResult.get(DSSTagsResponse.SIGNATURE) != null) {
		signature = propertiesResult.get(DSSTagsResponse.SIGNATURE).toString().getBytes();
	    }
	    if (propertiesResult.get(DSSTagsResponse.SIGNATURE_B64) != null) {
		signatureEncoded = propertiesResult.get(DSSTagsResponse.SIGNATURE_B64).toString();
		signature = Base64CoderCommons.decodeBase64(signatureEncoded.getBytes());
	    }

	    if (propertiesResult.get(DSSTagsResponse.UPDATED_SIGNATURE) != null) {
		signature = propertiesResult.get(DSSTagsResponse.UPDATED_SIGNATURE).toString().getBytes();
	    }
	    if (propertiesResult.get(DSSTagsResponse.UPDATED_SIGNATURE_B64) != null) {
		signatureEncoded = propertiesResult.get(DSSTagsResponse.UPDATED_SIGNATURE_B64).toString();
		signature = Base64CoderCommons.decodeBase64(signatureEncoded.getBytes());
	    }
	} catch (TransformersException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG048), e);
	}
	return signature;
    }

    /**
     * Method that obtains a list with the reports of individual signatures from a web service response.
     * @param propertiesResult Parameter that represents the information about the response of the web service.
     * @return the list with the reports of individual signatures from the web service response.
     */
    private static List<IndividualSignatureReport> generateListIndividualSignatureReport(Map<String, Object> propertiesResult) {

	List<IndividualSignatureReport> listIndSigRep = new ArrayList<IndividualSignatureReport>();
	// se obtiene un array de Map
	Map<String, Object>[ ] signReports = (Map<String, Object>[ ]) propertiesResult.get(DSSTagsResponse.INDIVIDUAL_SIGNATURE_REPORT);

	if (signReports != null) {
	    // se recorre el array y se va obteniendo la información de cada
	    // firmante.
	    for (int i = 0; i < signReports.length; i++) {
		IndividualSignatureReport indSigRep = new IndividualSignatureReport();
		Map<String, Object> indSigRepMap = signReports[i];

		// Result
		Result result = new Result();
		result.setResultMajor(indSigRepMap.get(DSSTagsResponse.IND_SIG_RESULT_MAJOR).toString());
		if (indSigRepMap.get(DSSTagsResponse.IND_SIG_RESULT_MINOR) != null) {
		    result.setResultMinor(indSigRepMap.get(DSSTagsResponse.IND_SIG_RESULT_MINOR).toString());
		}
		if (indSigRepMap.get(DSSTagsResponse.IND_SIG_RESULT_MESSAGE) != null) {
		    result.setResultMessage(indSigRepMap.get(DSSTagsResponse.IND_SIG_RESULT_MESSAGE).toString());
		}
		indSigRep.setResult(result);

		// readableCertificateIngo (Details/readableCertificateInfo)
		Map<String, Object> certificateInfo = (Map<String, Object>) indSigRepMap.get(DSSTagsResponse.IND_SIG_DETAILS_READABLE_CERTIFICATE_INFO);
		if (certificateInfo != null) {
		    indSigRep.setReadableCertificateInfo(certificateInfo);
		}

		// signaturePolicyIdentifier
		// (Details/VerifiedUnderSignaturePolicy/SignaturePolicy/signaturePolicyIdentifier)
		if (indSigRepMap.get(DSSTagsResponse.IND_SIG_POLICY_IDENTIFIER) != null) {
		    indSigRep.setSignaturePolicyIdentifier(indSigRepMap.get(DSSTagsResponse.IND_SIG_POLICY_IDENTIFIER).toString());
		}

		// sigPolicyDocument (Details/ afxp:SigPolicyDocument@Type)
		//
		if (indSigRepMap.get(DSSTagsResponse.IND_SIG_POLICY_DOCUMENT) != null) {
		    String sigPolDoc = indSigRepMap.get(DSSTagsResponse.IND_SIG_POLICY_DOCUMENT).toString();
		    // se devuelve sin codificar
		    byte[ ] decodedSigPolDoc = null;
		    try {
			decodedSigPolDoc = Base64CoderCommons.decodeBase64(sigPolDoc).getBytes();
		    } catch (TransformersException e) {
			LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG049), e);
		    }
		    indSigRep.setSigPolicyDocument(decodedSigPolDoc);
		}

		// vr:Details/dss:processingDetails
		ProcessingDetail processingDetail = generateProcessingDetail(indSigRepMap);
		indSigRep.setProcessingDetails(processingDetail);

		listIndSigRep.add(indSigRep);
	    }
	}

	return listIndSigRep;

    }

    /**
     * Method that obtains the information about the result of different steps related to the verify of a signature from the response of a web service.
     * @param indSigRepMap Parameter that represents the information about the response of the web service.
     * @return the information about the result of different steps related to the verify of a signature from the response of the web service.
     */
    private static ProcessingDetail generateProcessingDetail(Map<String, Object> indSigRepMap) {
	ProcessingDetail processingDetail = new ProcessingDetail();
	// vr:Details/dss:processingDetails/dss:ValidDetail
	if (indSigRepMap.get(DSSTagsResponse.IND_SIG_VALID_DETAIL) != null) {
	    List<Detail> listValidDetail = new ArrayList<Detail>();
	    HashMap<String, String>[ ] listValidDetailHashMap = (HashMap<String, String>[ ]) indSigRepMap.get(DSSTagsResponse.IND_SIG_VALID_DETAIL);
	    for (int j = 0; j < listValidDetailHashMap.length; j++) {
		HashMap<String, String> valDet = listValidDetailHashMap[j];
		Detail detailValid = new Detail();
		detailValid.setType(valDet.get(DSSTagsResponse.IND_SIG_VALID_DETAIL_TYPE));
		detailValid.setCode(valDet.get(DSSTagsResponse.IND_SIG_VALID_DETAIL_CODE));
		detailValid.setMessage(valDet.get(DSSTagsResponse.IND_SIG_VALID_DETAIL_MESSAGE));
		listValidDetail.add(detailValid);
	    }
	    processingDetail.setListValidDetail(listValidDetail);
	}

	// vr:Details/dss:processingDetails/dss:InvalidDetail
	if (indSigRepMap.get(DSSTagsResponse.IND_SIG_INVALID_DETAIL) != null) {
	    List<Detail> listInvalidDetail = new ArrayList<Detail>();
	    HashMap<String, String>[ ] listInvalidDetailHashMap = (HashMap<String, String>[ ]) indSigRepMap.get(DSSTagsResponse.IND_SIG_INVALID_DETAIL);
	    for (int j = 0; j < listInvalidDetailHashMap.length; j++) {
		HashMap<String, String> invalDet = listInvalidDetailHashMap[j];
		Detail detailInvalid = new Detail();
		detailInvalid.setType(invalDet.get(DSSTagsResponse.IND_SIG_INVALID_DETAIL_TYPE));
		detailInvalid.setCode(invalDet.get(DSSTagsResponse.IND_SIG_INVALID_DETAIL_CODE));
		detailInvalid.setMessage(invalDet.get(DSSTagsResponse.IND_SIG_INVALID_DETAIL_MESSAGE));
		listInvalidDetail.add(detailInvalid);
	    }
	    processingDetail.setListInvalidDetail(listInvalidDetail);
	}

	// vr:Details/dss:processingDetails/dss:IndeterminateDetail
	if (indSigRepMap.get(DSSTagsResponse.IND_SIG_INDETERMINATE_DETAIL) != null) {
	    List<Detail> listIndeterminateDetail = new ArrayList<Detail>();
	    HashMap<String, String>[ ] listIndeterminateDetailHashMap = (HashMap<String, String>[ ]) indSigRepMap.get(DSSTagsResponse.IND_SIG_INDETERMINATE_DETAIL);
	    for (int j = 0; j < listIndeterminateDetailHashMap.length; j++) {
		HashMap<String, String> indDet = listIndeterminateDetailHashMap[j];
		Detail detailIndeterminate = new Detail();
		detailIndeterminate.setType(indDet.get(DSSTagsResponse.IND_SIG_INDETERMINATE_DETAIL_TYPE));
		detailIndeterminate.setCode(indDet.get(DSSTagsResponse.IND_SIG_INDETERMINATE_DETAIL_CODE));
		detailIndeterminate.setMessage(indDet.get(DSSTagsResponse.IND_SIG_INDETERMINATE_DETAIL_MESSAGE));
		listIndeterminateDetail.add(detailIndeterminate);
	    }
	    processingDetail.setListIndeterminateDetail(listIndeterminateDetail);
	}

	return processingDetail;
    }

    /**
     * Method that updates the information of the data signed by an individual signature contained inside of the response of verified signature if a map
     * with the values to process has a values for {@link DSSTagsResponse#DATA_INFO_DOC_HASH_METHOD} key or for
     * {@link DSSTagsResponse#DATA_INFO_DOC_HASH_VALUE}.
     * @param datInf Parameter that represents the information of the data signed by an individual signature contained inside of the response of
     * verified signature
     * @param dataInfo Parameter that represents the map with the values to process.
     */
    private static void processDocumentHash(DataInfo datInf, Map<String, Object> dataInfo) {
	if (dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_METHOD) != null || dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_VALUE) != null) {
	    DocumentHash documentHash = new DocumentHash();
	    if (dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_METHOD) != null) {
		if (HashAlgorithmEnum.SHA1.equals(dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_METHOD).toString())) {
		    documentHash.setDigestMethod(HashAlgorithmEnum.SHA1);
		} else if (HashAlgorithmEnum.SHA256.equals(dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_METHOD).toString())) {
		    documentHash.setDigestMethod(HashAlgorithmEnum.SHA256);
		} else if (HashAlgorithmEnum.SHA384.equals(dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_METHOD).toString())) {
		    documentHash.setDigestMethod(HashAlgorithmEnum.SHA384);
		} else if (HashAlgorithmEnum.SHA512.equals(dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_METHOD).toString())) {
		    documentHash.setDigestMethod(HashAlgorithmEnum.SHA512);
		}

	    }
	    if (dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_VALUE) != null) {
		String digestValue = dataInfo.get(DSSTagsResponse.DATA_INFO_DOC_HASH_VALUE).toString();
		// se devuelve sin codificar
		byte[ ] decodedDigestValue = null;
		try {
		    decodedDigestValue = Base64CoderCommons.decodeBase64(digestValue.getBytes());
		} catch (TransformersException e) {
		    LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG050), e);
		}

		documentHash.setDigestValue(decodedDigestValue);
	    }
	    datInf.setDocumentHash(documentHash);
	}
    }

    /**
     * Method that generates a {@link DataInfo} object from a Map of values.
     * @param dataInfo Parameter that represents the map with the values to process.
     * @return the generated {@link DataInfo} object.
     */
    private static DataInfo generateDataInfo(Map<String, Object> dataInfo) {
	DataInfo datInf = new DataInfo();

	// dataInfo puede devolver algunos de los siguientes compentes:
	// contendData, documentHash o SignedDataRefs

	// si la firma verificada es implícita y no XML, devolverá
	// afxp:ContentData
	if (dataInfo.get(DSSTagsResponse.DATA_INFO_CONTENT_DATA) != null) {
	    // devuelve datos firmados originalmente en Base64
	    String contentDataB64 = dataInfo.get(DSSTagsResponse.DATA_INFO_CONTENT_DATA).toString();
	    // se devuelve sin codificar
	    byte[ ] decodedContentData = null;
	    try {
		decodedContentData = Base64CoderCommons.decodeBase64(contentDataB64.getBytes());
	    } catch (TransformersException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.IFWS_LOG050), e);
	    }
	    datInf.setContentData(decodedContentData);
	}

	// si la firma verificada es explícita y no XML, o si la firma
	// es PAdES, devolverá afxp:DocumentHash
	processDocumentHash(datInf, dataInfo);

	// si la firma verificada es XML, devolveá afxp:SignedDataRefs
	if (dataInfo.get(DSSTagsResponse.DATA_INFO_SIGNED_DATA_REFS) != null) {
	    // se obtiene array de SignedDataRef
	    HashMap<String, Object>[ ] listSignedDataRef = (HashMap<String, Object>[ ]) dataInfo.get(DSSTagsResponse.DATA_INFO_SIGNED_DATA_REFS);
	    List<String> signedDataRefs = new ArrayList<String>();
	    // se recorre el array y se va obteniendo información de
	    // cada componente SignedDataRef
	    for (int j = 0; j < listSignedDataRef.length; j++) {
		HashMap<String, Object> signedDataRef = listSignedDataRef[j];
		if (signedDataRef.get(DSSTagsResponse.DATA_INFO_SIGNED_DATA_REF_XPATH) != null) {
		    signedDataRefs.add(signedDataRef.get(DSSTagsResponse.DATA_INFO_SIGNED_DATA_REF_XPATH).toString());
		}
	    }
	    datInf.setSignedDataRefs(signedDataRefs);
	}
	return datInf;
    }

    /**
     * Method that obtains a list with the information about the validation of each individual signature from a web service.
     * @param propertiesResult Parameter that represents the information about the response of the web service.
     * @return the list with the information about the validation of each individual signature from the web service.
     */
    private static List<DataInfo> generateListDataInfo(Map<String, Object> propertiesResult) {
	List<DataInfo> listDataInfo = new ArrayList<DataInfo>();
	// se obtiene array de DataInfo (devuelve una array de hashMap)
	HashMap<String, Object>[ ] arrayDataInfo = (HashMap<String, Object>[ ]) propertiesResult.get(DSSTagsResponse.DATA_INFO);
	if (arrayDataInfo != null) {
	    // se recorre el array y se va obteniendo la información de cada
	    // componente DataInfo
	    for (int i = 0; i < arrayDataInfo.length; i++) {
		listDataInfo.add(generateDataInfo(arrayDataInfo[i]));
	    }
	}
	return listDataInfo;
    }

    /**
     * Method that processes the response of a server timestamp service, server co-timestamp service or upgrade timestamp
     * service to transform it to a {@link TimestampResponse} object.
     * @param propertiesResult Parameter that represents the response of the web service as a map.
     * @param timestampRes Parameter that represents the object to update.
     * @param service Parameter that represents the service.
     */
    public static void generateTimestampResponse(Map<String, Object> propertiesResult, TimestampResponse timestampRes, String service) {

	// Result
	timestampRes.setResult(getResultResponse(propertiesResult));

	// timestamp
	if (GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE.equals(service)) {
	    timestampRes.setTimestamp(getVerifyTimestamp(propertiesResult));
	} else {
	    timestampRes.setTimestamp(getTimestamp(propertiesResult));
	}

	if (timestampRes.getTimestamp() == null) {
	    try {
		throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.IFWS_LOG032));
	    } catch (WSServiceInvokerException e) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG022, new Object[ ] { e.getMessage() }));
	    }
	}
    }

    /**
     * Method that obtains the timestamp from a web service response.
     * @param propertiesResult Parameter that represents the information about the response of the web service.
     * @return the timestamp from the web service response.
     */
    private static byte[ ] getTimestamp(Map<String, Object> propertiesResult) {
	String signatureEncoded = null;
	if (propertiesResult.get(DSSTagsResponse.TIMESTAMP_SIGNATURE_TIMESTAMPTOKEN) != null) {
	    signatureEncoded = propertiesResult.get(DSSTagsResponse.TIMESTAMP_SIGNATURE_TIMESTAMPTOKEN).toString();
	}
	if (propertiesResult.get(DSSTagsResponse.TIMESTAMP_RFC3161_TIMESTAMPTOKEN) != null) {
	    signatureEncoded = propertiesResult.get(DSSTagsResponse.TIMESTAMP_RFC3161_TIMESTAMPTOKEN).toString();
	}
	return signatureEncoded != null ? signatureEncoded.getBytes() : null;
    }

    /**
     * Method that obtains the timestamp from a web service response.
     * @param propertiesResult Parameter that represents the information about the response of the web service.
     * @return the timestamp from the web service response.
     */
    private static byte[ ] getVerifyTimestamp(Map<String, Object> propertiesResult) {
	byte[ ] optional = null;
	if (propertiesResult.get(DSSTagsResponse.SIG_INF_SIGNING_TIME) != null) {
	    optional = propertiesResult.get(DSSTagsResponse.SIG_INF_SIGNING_TIME).toString().getBytes();
	}
	if (propertiesResult.get(DSSTagsResponse.SIG_INF_LOWER_BOUNDARY) != null) {
	    optional = propertiesResult.get(DSSTagsResponse.SIG_INF_LOWER_BOUNDARY).toString().getBytes();
	}
	if (propertiesResult.get(DSSTagsResponse.SIG_INF_UPPER_BOUNDARY) != null) {
	    optional = propertiesResult.get(DSSTagsResponse.SIG_INF_UPPER_BOUNDARY).toString().getBytes();
	}
	if (propertiesResult.get(DSSTagsResponse.OP_OUT_VALID_DETAIL) != null) {
	    optional = propertiesResult.get(DSSTagsResponse.OP_OUT_VALID_DETAIL).toString().getBytes();
	}
	if (propertiesResult.get(DSSTagsResponse.OP_OUT_INVALID_DETAIL) != null) {
	    optional = propertiesResult.get(DSSTagsResponse.OP_OUT_INVALID_DETAIL).toString().getBytes();
	}
	if (propertiesResult.get(DSSTagsResponse.OP_OUT_INDETERMINATE_DETAIL) != null) {
	    optional = propertiesResult.get(DSSTagsResponse.OP_OUT_INDETERMINATE_DETAIL).toString().getBytes();
	}
	return optional;
    }
}
