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
 * <b>File:</b><p>es.gob.afirma.integraFacade.IntegraFacadeWSDSS.java.</p>
 * <b>Description:</b><p>Class that represents the facade which manages the invocation of DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>17/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 17/11/2014.
 */
package es.gob.afirma.integraFacade;

import java.util.Map;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.pojo.TimestampRequest;
import es.gob.afirma.integraFacade.pojo.TimestampResponse;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerFacade;
import es.gob.afirma.utils.DSSConstants;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that represents the facade which manages the invocation of DSS web services of ts@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2016.</p>
 * @author Javier Pantoja.
 * @version 1.0, 04/03/2016.
 */
public final class TsaIntegraFacadeWSDSS {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TsaIntegraFacadeWSDSS.class);

    /**
     * Attribute that represents the instance of the class.
     */
    private static TsaIntegraFacadeWSDSS instance;

    /**
     * Constructor method for the class IntegraFacadeWSDSS.java.
     */
    private TsaIntegraFacadeWSDSS() {
    }

    /**
     * Method that obtains an instance of the class.
     * @return the unique instance of the class.
     */
    public static TsaIntegraFacadeWSDSS getInstance() {
	if (instance == null) {
	    instance = new TsaIntegraFacadeWSDSS();
	}
	return instance;
    }
    
    /**
     * Method that obtains the response of the timestamp generate service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @return an object that represents the response of the server signature service.
     */
    public TimestampResponse generateTimestamp(TimestampRequest timestampReq) {
	return generateTimestamp(timestampReq, null);
    }

    /**
     * Method that obtains the response of the timestamp generate service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server signature service.
     */
    protected TimestampResponse generateTimestamp(TimestampRequest timestampReq, String idClient) {
	TimestampResponse timestampRes = new TimestampResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateTimestampRequest(timestampReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del párametro de entrada

	    Map<String, Object> inputParameters = GenerateMessageRequest.generateTimestampRequest(timestampReq);
	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
		// se invoca al servicio almacenar documento
		String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_SERVICE, timestampReq.getApplicationId(), idClient);
		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_SERVICE, TransformersConstants.VERSION_10);

		// creamos el objeto de respuesta
		if (propertiesResult != null) {
		    GenerateMessageResponse.generateTimestampResponse(propertiesResult, timestampRes, GeneralConstants.TSA_TIMESTAMP_SERVICE);
		}
	    }
	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	} catch (TSAServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	}

	return timestampRes;
    }
    
    /**
     * Method that obtains the response of the timestamp verify service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @return an object that represents the response of the server signature service.
     */
    public TimestampResponse verifyTimestamp(TimestampRequest timestampReq) {
	return verifyTimestamp(timestampReq, null);
    }

    /**
     * Method that obtains the response of the timestamp verify service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server signature service.
     */
    protected TimestampResponse verifyTimestamp(TimestampRequest timestampReq, String idClient) {
	TimestampResponse timestampRes = new TimestampResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateTimestampRequest(timestampReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del párametro de entrada

	    Map<String, Object> inputParameters = GenerateMessageRequest.generateTimestampRequest(timestampReq);
	    String inputDocumentProcessed = new String(timestampReq.getTimestampTimestampToken());
	    if (DSSConstants.TimestampForm.XML.equals(timestampReq.getTimestampType().getType())) {
		inputParameters.put(DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN, inputDocumentProcessed);
	    } else {
		inputParameters.put(DSSTagsRequest.TIMESTAMP_RFC3161_TIMESTAMPTOKEN, inputDocumentProcessed);
	    }

	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
		// se invoca al servicio almacenar documento
		String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, timestampReq.getApplicationId(), idClient);
		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);

		// creamos el objeto de respuesta
		if (propertiesResult != null) {
		    GenerateMessageResponse.generateTimestampResponse(propertiesResult, timestampRes, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE);
		}
	    }
	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	} catch (TSAServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	}

	return timestampRes;
    }
    
    /**
     * Method that obtains the response of the timestamp renove service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @return an object that represents the response of the server signature service.
     */
    public TimestampResponse renewTimestamp(TimestampRequest timestampReq) {
	return renewTimestamp(timestampReq, null);
    }

    /**
     * Method that obtains the response of the timestamp renove service.
     * @param timestampReq Parameter that represents the request of the server signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server signature service.
     */
    protected TimestampResponse renewTimestamp(TimestampRequest timestampReq, String idClient) {
	TimestampResponse timestampRes = new TimestampResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateTimestampRequest(timestampReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del párametro de entrada

	    Map<String, Object> inputParameters = GenerateMessageRequest.generateTimestampRequest(timestampReq);
	    String inputDocumentProcessed = new String(timestampReq.getTimestampPreviousTimestampToken());
	    if (DSSConstants.TimestampForm.XML.equals(timestampReq.getTimestampType().getType())) {
		inputParameters.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_XML_TIMESTAMPTOKEN, inputDocumentProcessed);
	    } else {
		inputParameters.put(DSSTagsRequest.TIMESTAMP_PREVIOUS_RFC3161_TIMESTAMPTOKEN, inputDocumentProcessed);
	    }
	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);
		// se invoca al servicio almacenar documento
		String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_RETIMESTAMP_SERVICE, timestampReq.getApplicationId(), idClient);
		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_RETIMESTAMP_SERVICE, TransformersConstants.VERSION_10);

		// creamos el objeto de respuesta
		if (propertiesResult != null) {
		    GenerateMessageResponse.generateTimestampResponse(propertiesResult, timestampRes, GeneralConstants.TSA_RETIMESTAMP_SERVICE);
		}
	    }
	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	} catch (TSAServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	}

	return timestampRes;
    }

}
