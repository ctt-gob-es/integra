// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraws.ws.impl.EvisorServices.java.</p>
 * <b>Description:</b><p> Class that contains evisor service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.ws.impl;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.opensaml.xml.util.Base64;

import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraws.beans.BarcodeEvisorRequest;
import es.gob.afirma.integraws.beans.EvisorResult;
import es.gob.afirma.integraws.beans.ParameterEvisorRequest;
import es.gob.afirma.integraws.beans.RequestEvisorGenerateReport;
import es.gob.afirma.integraws.beans.RequestEvisorValidateReport;
import es.gob.afirma.integraws.beans.ResponseEvisorGenerateReport;
import es.gob.afirma.integraws.beans.ResponseEvisorValidateReport;
import es.gob.afirma.integraws.ws.IEvisorServices;
import es.gob.afirma.integraws.ws.IWSConstantKeys;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.EVisorConstants;
import es.gob.afirma.utils.EVisorUtilCommons;
import es.gob.afirma.utils.EVisorConstants.EVisorTagsRequest;
import es.gob.afirma.wsServiceInvoker.EvisorServiceInvokerFacade;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/** 
 * <p>Class that contains evisor service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class EvisorServices implements IEvisorServices {
    
    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(EvisorServices.class);

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IEvisorServices#generateReport(es.gob.afirma.integraws.beans.RequestEvisorGenerateReport)
     */
    public final ResponseEvisorGenerateReport generateReport(RequestEvisorGenerateReport request) {
	
	if (request.getIdClient() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
	    return new ResponseEvisorGenerateReport(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	}

	Map<String, Object> inputParams = setParams(request);

	try {
	    String inputXml;
	    String outputXml;

	    inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	    outputXml = EvisorServiceInvokerFacade.getInstance().invokeService(inputXml, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, request.getApplicationId(), request.getIdClient());
	    Map<String, Object> result = TransformersFacade.getInstance().parseResponse(outputXml, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.GENERATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	    
	    String codeResult = (String) result.get("srsm:Result/srsm:Code");
	    String message = (String) result.get("srsm:Result/srsm:Message");
	    String cause = (String) result.get("srsm:Result/srsm:Cause");
	    String report = (String) result.get("srsm:Report");
	    byte[] reportByteArray = null;
	    if (report != null) {
		reportByteArray = Base64.decode(report);
	    }

	    return new ResponseEvisorGenerateReport(new EvisorResult(codeResult, message, cause), reportByteArray, true);
	} catch (TransformersException e) {
	    LOGGER.error(e.getMessage(), e);
	    return new ResponseEvisorGenerateReport(false, e.getMessage());
	} catch (WSServiceInvokerException e) {
	    LOGGER.error(e.getMessage(), e);
	    return new ResponseEvisorGenerateReport(false, e.getMessage());
	}
    }

    /**
     * Method that sets the params from request.
     * @param request 
     * @return input params object
     */
    private Map<String, Object> setParams(RequestEvisorGenerateReport request) {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	//set params in three methods for cyclomatic complex
	inputParams.putAll(getParamsPart1(request));
	inputParams.putAll(getParamsPart2(request));
	inputParams.putAll(getParamsPart3(request));

	
	return inputParams;
    }

    /**
     * Sets params part 1.
     * @param request request object
     * @return input params
     */
    private Map<String, Object> getParamsPart1(RequestEvisorGenerateReport request) {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	if (request.getApplicationId() != null) {
	    inputParams.put(EVisorTagsRequest.APPLICATION_ID, request.getApplicationId());
	}
	if (request.getBarcodeList() != null && !request.getBarcodeList().isEmpty()) {
	    Map<?, ?>[ ] barcodes = new Map<?, ?>[request.getBarcodeList().size()];
	    int i = 0;
	    for (BarcodeEvisorRequest barcode: request.getBarcodeList()) {
		Map<String, String> params = new HashMap<String, String>();
		if (barcode.getConfigurationParameterList() != null && !barcode.getConfigurationParameterList().isEmpty()) {
		    for (ParameterEvisorRequest param: barcode.getConfigurationParameterList()) {
			params.put(param.getParameterId(), param.getParameterValue());
		    }
		    if (params.isEmpty()) {
			params = null;
		    }
		}
		barcodes[i] = EVisorUtilCommons.newBarcodeMap(barcode.getBarcodeMessage(), barcode.getBarcodeType().getType(), params);
		i++;
	    }
	    inputParams.put(EVisorTagsRequest.BARCODE, barcodes);
	}
	if (request.getDocRepositoryLocationObjectId() != null) {
	    inputParams.put(EVisorTagsRequest.DOC_REPO_OBJECT_ID, request.getDocRepositoryLocationObjectId());
	}
	
	return inputParams;
    }

    /**
     * Sets params part 2.
     * @param request request object
     * @return input params
     */
    private Map<String, Object> getParamsPart2(RequestEvisorGenerateReport request) {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	if (request.getDocRepositoryLocationRepositoryId() != null) {
	    inputParams.put(EVisorTagsRequest.DOC_REPO_ID, request.getDocRepositoryLocationRepositoryId());
	}
	if (request.getDocument() != null) {
		inputParams.put(EVisorTagsRequest.ENCODED_DOCUMENT, Base64.encodeBytes(request.getDocument()));
	}
	if (request.getSignature() != null) {
		inputParams.put(EVisorTagsRequest.ENCODED_SIGNATURE, Base64.encodeBytes(request.getSignature()));
	}
	if (request.getExternalParameterList() != null && !request.getExternalParameterList().isEmpty()) {
	    Map<String, String> params = new HashMap<String, String>();
	    for (ParameterEvisorRequest param: request.getExternalParameterList()) {
		params.put(param.getParameterId(), param.getParameterValue());
	    }

	    inputParams.put(EVisorTagsRequest.EXTERNAL_PARAMETERS_PARAM, EVisorUtilCommons.newParameterMap(params));

	}
	
	return inputParams;
    }
    
    /**
     * Sets params part 3.
     * @param request request object
     * @return input params
     */
    private Map<String, Object> getParamsPart3(RequestEvisorGenerateReport request) {
	Map<String, Object> inputParams = new HashMap<String, Object>();
	
	if (request.getSignRepositoryObjectId() != null) {
	    inputParams.put(EVisorTagsRequest.SIGN_REPO_OBJECT_ID, request.getSignRepositoryObjectId());
	}
	if (request.getSignRepositoryRepositoryId() != null) {
	    inputParams.put(EVisorTagsRequest.SIGN_REPO_REPOSITORY_ID, request.getSignRepositoryRepositoryId());
	}
	if (request.getTemplateId() != null) {
	    inputParams.put(EVisorTagsRequest.TEMPLATE_ID, request.getTemplateId());
	}
	if (request.getValidationResponse() != null) {
	    inputParams.put(EVisorTagsRequest.VALIDATION_RESPONSE,  Base64.encodeBytes(request.getValidationResponse()));
	}
	return inputParams;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.IEvisorServices#validateReport(es.gob.afirma.integraws.beans.RequestEvisorValidateReport)
     */
    public final ResponseEvisorValidateReport validateReport(RequestEvisorValidateReport request) {
	
	if (request.getIdClient() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
	    return new ResponseEvisorValidateReport(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	}
	
	Map<String, Object> inputParams = new HashMap<String, Object>();

	if (request.getApplicationId() != null) {
	    inputParams.put(EVisorTagsRequest.APPLICATION_ID, request.getApplicationId());
	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_004));
	    return new ResponseEvisorValidateReport(false, Language.getResIntegra(IWSConstantKeys.IWS_004));
	}
	if (request.getReport() != null) {
	    inputParams.put(EVisorTagsRequest.REPORT, Base64.encodeBytes(request.getReport()));
	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_005));
	    return new ResponseEvisorValidateReport(false, Language.getResIntegra(IWSConstantKeys.IWS_005));
	}

	try {
	    String inputXml = TransformersFacade.getInstance().generateXml(inputParams, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, TransformersConstants.VERSION_10);

	    String outputXml = EvisorServiceInvokerFacade.getInstance().invokeService(inputXml, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, request.getApplicationId(), request.getIdClient());

	    Map<String, Object> result = TransformersFacade.getInstance().parseResponse(outputXml, EVisorConstants.SIGNATURE_REPORT_SERVICE, EVisorConstants.VALIDATE_REPORT_METHOD, TransformersConstants.VERSION_10);
	    
	    String codeResult = (String) result.get("srsm:Result/srsm:Code");
	    String message = (String) result.get("srsm:Result/srsm:Message");
	    String cause = (String) result.get("srsm:Result/srsm:Cause");
	    
	    return new ResponseEvisorValidateReport(new EvisorResult(codeResult, message, cause), true);
	} catch (TransformersException e) {
	    LOGGER.error(e.getMessage(), e);
	    return new ResponseEvisorValidateReport(false, e.getMessage());
	} catch (WSServiceInvokerException e) {
	    LOGGER.error(e.getMessage(), e);
	    return new ResponseEvisorValidateReport(false, e.getMessage());
	}
    }
}
