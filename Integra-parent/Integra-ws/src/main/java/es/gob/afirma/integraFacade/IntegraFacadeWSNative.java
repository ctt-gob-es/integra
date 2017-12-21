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
 * <b>File:</b><p>es.gob.afirma.integraFacade.IntegraFacadeWSNative.java.</p>
 * <b>Description:</b><p>Class that represents the facade which manages the invocation of native web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>06/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 06/11/2014.
 */
package es.gob.afirma.integraFacade;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.pojo.CertificateInfoRequest;
import es.gob.afirma.integraFacade.pojo.CertificateInfoResponse;
import es.gob.afirma.integraFacade.pojo.ContentRequest;
import es.gob.afirma.integraFacade.pojo.ContentResponse;
import es.gob.afirma.integraFacade.pojo.DocumentRequest;
import es.gob.afirma.integraFacade.pojo.DocumentResponse;
import es.gob.afirma.integraFacade.pojo.ErrorResponse;
import es.gob.afirma.integraFacade.pojo.SignatureTransactionResponse;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.NativeTagsRequest;
import es.gob.afirma.utils.NativeTagsResponse;
import es.gob.afirma.wsServiceInvoker.Afirma5ServiceInvokerFacade;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that represents the facade which manages the invocation of native web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 06/11/2014.
 */
public final class IntegraFacadeWSNative {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(IntegraFacadeWSNative.class);

    /**
     * Attribute that represents the default error code when an exception is thrown in a request for a service.
     */
    private static final String COD_ERROR = "IFWS";

    /**
     * Attribute that represents the instance of the class.
     */
    private static IntegraFacadeWSNative instance;

    /**
     * Constructor method for the class IntegraFacadeWSNative.java.
     */
    private IntegraFacadeWSNative() {
    }

    /**
     * Method that obtains an instance of the class.
     * @return the unique instance of the class.
     */
    public static IntegraFacadeWSNative getInstance() {
	if (instance == null) {
	    instance = new IntegraFacadeWSNative();
	}
	return instance;
    }

    /**
     * Method that obtains the response of the store document service.
     * @param docReq Parameter that represents the request of the store document service.
     * @return an object that represents the response of the store document service.
     */
    public DocumentResponse storingDocument(DocumentRequest docReq) {
	DocumentResponse docRes = new DocumentResponse();
	Throwable error = null;
	try {
	    // se comprueba que se han introducidos los parámetros obligatorios
	    // para la petición
	    String resultValidate = ValidateRequest.validateDocumentRequest(docReq);
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    Map<String, Object> inParams = new HashMap<String, Object>();
	    inParams.put(NativeTagsRequest.ID_APLICACION, docReq.getApplicationId());
	    byte[ ] document = docReq.getDocument();
	    if (document != null) {
		inParams.put(NativeTagsRequest.DOCUMENTO, new String(docReq.getDocument()));
	    } else {
		inParams.put(NativeTagsRequest.DOCUMENTO, null);
	    }
	    inParams.put(NativeTagsRequest.NOMBRE_DOCUMENTO, docReq.getName());
	    inParams.put(NativeTagsRequest.TIPO_DOCUMENTO, docReq.getType());

	    // se crea mensaje XML de petición.
	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, TransformersConstants.VERSION_10);

	    // se invoca al servicio almacenar documento
	    String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, docReq.getApplicationId());

	    // parseamos el resultado.
	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST, TransformersConstants.VERSION_10);

	    // creamos el objeto de respuesta
	    // preguntamos si la respuesta es válida o no
	    if (propertiesResult.containsKey(NativeTagsResponse.ERROR_RESPONSE_CODE)) {
		// respuesta de error
		String codeError = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_CODE).toString();
		String description = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_DESCRIPTION).toString();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		docRes.setError(errorResponse);

	    } else {
		// respuesta correcta
		if (propertiesResult.get(NativeTagsResponse.STATE).toString().equals(Boolean.TRUE.toString())) {
		    docRes.setState(true);
		} else {
		    docRes.setState(false);
		}
		docRes.setDescription(propertiesResult.get(NativeTagsResponse.DESCRIPTION).toString());
		docRes.setDocumentId(propertiesResult.get(NativeTagsResponse.ID_DOCUMENT).toString());
	    }
	} catch (TransformersException e) {
	    error = e;
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG001));

	} catch (WSServiceInvokerException e) {
	    error = e;
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG002, new Object[ ] { GeneralConstants.ALMACENAR_DOCUMENTO_REQUEST }));
	} finally {
	    if (error != null) {
		// creamos respuesta de error
		String codeError = COD_ERROR;
		String description = error.getMessage();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		docRes.setError(errorResponse);
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG004, new Object[ ] { error.getMessage() }));
	    } else {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG003));
	    }
	}
	return docRes;
    }

    /**
     * Method that obtains the response of the delete document content service.
     * @param conReq Parameter that represents the request of the delete document content service.
     * @return an object that represents the response of the delete document content service.
     */
    public ContentResponse deleteDocumentContent(ContentRequest conReq) {
	Throwable error = null;
	ContentResponse conRes = new ContentResponse();

	Map<String, Object> inParams = new HashMap<String, Object>();
	inParams.put(NativeTagsRequest.ID_APLICACION, conReq.getApplicationId());
	inParams.put(NativeTagsRequest.ID_DOCUMENTO, conReq.getTransactionId());
	try {
	    // se comprueba si los parametros necesarios para la petición no
	    // sea, vacío ni nulos
	    if (!GenericUtilsCommons.assertStringValue(conReq.getApplicationId()) || !GenericUtilsCommons.assertStringValue(conReq.getTransactionId())) {
		throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.IFWS_LOG009));
	    }
	    // se crea mensaje XML de petición.
	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.ELIMINAR_CONTENIDO_DOCUMENTO, GeneralConstants.ELIMINAR_CONTENIDO_DOCUMENTO, TransformersConstants.VERSION_10);

	    // se invoca al servicio almacenar documento
	    String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.ELIMINAR_CONTENIDO_DOCUMENTO, GeneralConstants.ELIMINAR_CONTENIDO_DOCUMENTO, conReq.getApplicationId());

	    // parseamos el resultado.
	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.ELIMINAR_CONTENIDO_DOCUMENTO, GeneralConstants.ELIMINAR_CONTENIDO_DOCUMENTO, TransformersConstants.VERSION_10);

	    // creamos el objeto de respuesta
	    // preguntamos si la respuesta es válida o no
	    if (propertiesResult.containsKey(NativeTagsResponse.ERROR_RESPONSE_CODE)) {
		// respuesta de error
		String codeError = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_CODE).toString();
		String description = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_DESCRIPTION).toString();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		conRes.setError(errorResponse);
	    } else {
		// respuesta correcta
		if (propertiesResult.get(NativeTagsResponse.STATE).toString().equals(Boolean.TRUE.toString())) {
		    conRes.setState(true);
		} else {
		    conRes.setState(false);
		}
		conRes.setDescription(propertiesResult.get(NativeTagsResponse.DESCRIPTION).toString());
	    }
	} catch (TransformersException e) {
	    error = e;
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG001));

	} catch (WSServiceInvokerException e) {
	    error = e;
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG002, new Object[ ] { GeneralConstants.ELIMINAR_CONTENIDO_DOCUMENTO }));
	} finally {
	    if (error != null) {
		// creamos respuesta de error
		String codeError = COD_ERROR;
		String description = error.getMessage();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		conRes.setError(errorResponse);
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG006, new Object[ ] { error.getMessage() }));
	    } else {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG005));
	    }
	}

	return conRes;
    }

    /**
     * Method that obtains the response of the get document service.
     * @param conReq Parameter that represents the request of the get document service.
     * @return an object that represents the response of the get document service.
     */
    public ContentResponse getDocumentContent(ContentRequest conReq) {
	Throwable error = null;
	ContentResponse conRes = new ContentResponse();
	Map<String, Object> inParams = new HashMap<String, Object>();

	inParams.put(NativeTagsRequest.ID_APLICACION, conReq.getApplicationId());
	inParams.put(NativeTagsRequest.ID_TRANSACCION, conReq.getTransactionId());

	try {
	    // se comprueba que se han introducidos los parámetros obligatorios
	    // para la petición
	    if (!GenericUtilsCommons.assertStringValue(conReq.getApplicationId()) || !GenericUtilsCommons.assertStringValue(conReq.getTransactionId())) {
		throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.IFWS_LOG009));
	    }

	    // se crea mensaje XML de petición.
	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO, TransformersConstants.VERSION_10);
	    // se invoca al servicio almacenar documento
	    String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO, conReq.getApplicationId());
	    // parseamos el resultado.
	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO, TransformersConstants.VERSION_10);

	    // se crea el objeto de respuesta
	    // se comprueba si la respuesta es válida o no
	    if (propertiesResult.containsKey(NativeTagsResponse.ERROR_RESPONSE_CODE)) {
		// respuesta de error
		String codeError = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_CODE).toString();
		String description = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_DESCRIPTION).toString();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		conRes.setError(errorResponse);

	    } else {
		// respuesta correcta
		if (propertiesResult.get(NativeTagsResponse.STATE).toString().equals(Boolean.TRUE.toString())) {
		    conRes.setState(true);
		} else {
		    conRes.setState(false);
		}
		conRes.setDescription(propertiesResult.get(NativeTagsResponse.DESCRIPTION).toString());
		byte[ ] contentResult = null;
		if (propertiesResult.get(NativeTagsResponse.DOCUMENT) != null) {
		    contentResult = propertiesResult.get(NativeTagsResponse.DOCUMENT).toString().getBytes();
		}
		conRes.setContent(contentResult);
	    }
	} catch (TransformersException e) {
	    error = e;
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG001));

	} catch (WSServiceInvokerException e) {
	    error = e;
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG002, new Object[ ] { GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO }));
	} finally {
	    if (error != null) {
		// creamos respuesta de error
		String codeError = COD_ERROR;
		String description = error.getMessage();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		conRes.setError(errorResponse);
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG008, new Object[ ] { error.getMessage() }));
	    } else {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG007));
	    }
	}

	return conRes;
    }

    /**
     * Method that obtains the response of the get document content by identifier service.
     * @param conReq Parameter that represents the request of the get document content by identifier service.
     * @return an object that represents the response of the get document content by identifier service.
     */
    public ContentResponse getContentDocumentId(ContentRequest conReq) {
	Throwable error = null;
	ContentResponse conRes = new ContentResponse();
	Map<String, Object> inParams = new HashMap<String, Object>();

	inParams.put(NativeTagsRequest.ID_APLICACION, conReq.getApplicationId());
	inParams.put(NativeTagsRequest.ID_DOCUMENTO, conReq.getTransactionId());

	try {
	    // se comprueba que se han introducidos los parámetros obligatorios
	    // para la petición
	    if (!GenericUtilsCommons.assertStringValue(conReq.getApplicationId()) || !GenericUtilsCommons.assertStringValue(conReq.getTransactionId())) {
		throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.IFWS_LOG009));
	    }

	    // se crea mensaje XML de petición.
	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO_ID, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO_ID, TransformersConstants.VERSION_10);
	    // se invoca al servicio almacenar documento
	    String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO_ID, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO_ID, conReq.getApplicationId());
	    // parseamos el resultado.
	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO_ID, GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO_ID, TransformersConstants.VERSION_10);

	    // se crea el objeto de respuesta
	    // se comprueba si la respuesta es válida o no
	    if (propertiesResult.containsKey(NativeTagsResponse.ERROR_RESPONSE_CODE)) {
		// respuesta de error
		String codeError = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_CODE).toString();
		String description = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_DESCRIPTION).toString();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		conRes.setError(errorResponse);

	    } else {
		// respuesta correcta
		if (propertiesResult.get(NativeTagsResponse.STATE).toString().equals(Boolean.TRUE.toString())) {
		    conRes.setState(true);
		} else {
		    conRes.setState(false);
		}
		conRes.setDescription(propertiesResult.get(NativeTagsResponse.DESCRIPTION).toString());
		byte[ ] contentResult = null;
		if (propertiesResult.get(NativeTagsResponse.DOCUMENT) != null) {
		    contentResult = propertiesResult.get(NativeTagsResponse.DOCUMENT).toString().getBytes();
		}
		conRes.setContent(contentResult);
	    }
	} catch (TransformersException e) {
	    error = e;
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG001));

	} catch (WSServiceInvokerException e) {
	    error = e;
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG002, new Object[ ] { GeneralConstants.OBTENER_CONTENIDO_DOCUMENTO_ID }));
	} finally {
	    if (error != null) {
		// creamos respuesta de error
		String codeError = COD_ERROR;
		String description = error.getMessage();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		conRes.setError(errorResponse);
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG011, new Object[ ] { error.getMessage() }));
	    } else {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG010));
	    }
	}

	return conRes;
    }

    /**
     * Method that obtains the response of the get document identifier service.
     * @param conReq Parameter that represents the request of the get document identifier service.
     * @return an object that represents the response of the get document identifier service.
     */
    public ContentResponse getDocumentId(ContentRequest conReq) {
	Throwable error = null;
	ContentResponse conRes = new ContentResponse();
	Map<String, Object> inParams = new HashMap<String, Object>();

	inParams.put(NativeTagsRequest.ID_APLICACION, conReq.getApplicationId());
	inParams.put(NativeTagsRequest.ID_TRANSACCION, conReq.getTransactionId());

	try {
	    // se comprueba que se han introducidos los parámetros obligatorios
	    // para la petición
	    if (!GenericUtilsCommons.assertStringValue(conReq.getApplicationId()) || !GenericUtilsCommons.assertStringValue(conReq.getTransactionId())) {
		throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.IFWS_LOG009));
	    }

	    // se crea mensaje XML de petición.
	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.OBTENER_ID_DOCUMENTO, GeneralConstants.OBTENER_ID_DOCUMENTO, TransformersConstants.VERSION_10);
	    // se invoca al servicio almacenar documento
	    String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.OBTENER_ID_DOCUMENTO, GeneralConstants.OBTENER_ID_DOCUMENTO, conReq.getApplicationId());
	    // parseamos el resultado.
	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.OBTENER_ID_DOCUMENTO, GeneralConstants.OBTENER_ID_DOCUMENTO, TransformersConstants.VERSION_10);

	    // se crea el objeto de respuesta
	    // se comprueba si la respuesta es válida o no
	    if (propertiesResult.containsKey(NativeTagsResponse.ERROR_RESPONSE_CODE)) {
		// respuesta de error
		String codeError = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_CODE).toString();
		String description = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_DESCRIPTION).toString();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		conRes.setError(errorResponse);

	    } else {
		// respuesta correcta
		if (propertiesResult.get(NativeTagsResponse.STATE).toString().equals(Boolean.TRUE.toString())) {
		    conRes.setState(true);
		} else {
		    conRes.setState(false);
		}
		conRes.setDescription(propertiesResult.get(NativeTagsResponse.DESCRIPTION).toString());
		byte[ ] contentResult = null;
		if (propertiesResult.get(NativeTagsResponse.ID_DOCUMENT) != null) {
		    contentResult = propertiesResult.get(NativeTagsResponse.ID_DOCUMENT).toString().getBytes();
		}

		conRes.setContent(contentResult);
	    }
	} catch (TransformersException e) {
	    error = e;
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG001));

	} catch (WSServiceInvokerException e) {
	    error = e;
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG002, new Object[ ] { GeneralConstants.OBTENER_ID_DOCUMENTO }));
	} finally {
	    if (error != null) {
		// creamos respuesta de error
		String codeError = COD_ERROR;
		String description = error.getMessage();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		conRes.setError(errorResponse);
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG013, new Object[ ] { error.getMessage() }));
	    } else {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG012));
	    }
	}

	return conRes;
    }

    /**
     * Method that obtains the response of the get signature by transaction service.
     * @param conReq Parameter that represents the request of the get signature by transaction service.
     * @return an object that represents the response of the get signature by transaction service.
     */
    public SignatureTransactionResponse getSignatureTransaction(ContentRequest conReq) {
	Throwable error = null;
	SignatureTransactionResponse sigTraRes = new SignatureTransactionResponse();
	Map<String, Object> inParams = new HashMap<String, Object>();

	inParams.put(NativeTagsRequest.ID_APLICACION, conReq.getApplicationId());
	inParams.put(NativeTagsRequest.ID_TRANSACCION, conReq.getTransactionId());

	try {
	    // se comprueba que se han introducidos los parámetros obligatorios
	    // para la petición
	    String resultValidate = ValidateRequest.validateContentRequest(conReq);
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    // se crea mensaje XML de petición.
	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.OBTENER_FIRMA_TRANSACCION, GeneralConstants.OBTENER_FIRMA_TRANSACCION, TransformersConstants.VERSION_10);
	    // se invoca al servicio almacenar documento
	    String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.OBTENER_FIRMA_TRANSACCION, GeneralConstants.OBTENER_FIRMA_TRANSACCION, conReq.getApplicationId());
	    // parseamos el resultado.
	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.OBTENER_FIRMA_TRANSACCION, GeneralConstants.OBTENER_FIRMA_TRANSACCION, TransformersConstants.VERSION_10);

	    // se crea el objeto de respuesta
	    // se comprueba si la respuesta es válida o no
	    if (propertiesResult.containsKey(NativeTagsResponse.ERROR_RESPONSE_CODE)) {
		// respuesta de error
		String codeError = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_CODE).toString();
		String description = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_DESCRIPTION).toString();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		sigTraRes.setError(errorResponse);

	    } else {
		// respuesta correcta
		if (propertiesResult.get(NativeTagsResponse.STATE).toString().equals(Boolean.TRUE.toString())) {
		    sigTraRes.setState(true);
		} else {
		    sigTraRes.setState(false);
		}

		if (propertiesResult.get(NativeTagsResponse.DESCRIPTION) != null) {
		    sigTraRes.setDescription(propertiesResult.get(NativeTagsResponse.DESCRIPTION).toString());
		}
		byte[ ] signature = null;
		if (propertiesResult.get(NativeTagsResponse.FIRMA_ELECTRONICA) != null) {
		    signature = propertiesResult.get(NativeTagsResponse.FIRMA_ELECTRONICA).toString().getBytes();
		}
		sigTraRes.setSignature(signature);
		if (propertiesResult.get(NativeTagsResponse.FORMATO_FIRMA) != null) {
		    sigTraRes.setSignatureFormat(propertiesResult.get(NativeTagsResponse.FORMATO_FIRMA).toString());
		}

	    }
	} catch (TransformersException e) {
	    error = e;
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG001));

	} catch (WSServiceInvokerException e) {
	    error = e;
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG002, new Object[ ] { GeneralConstants.OBTENER_FIRMA_TRANSACCION }));
	} finally {
	    if (error != null) {
		// creamos respuesta de error
		String codeError = COD_ERROR;
		String description = error.getMessage();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		sigTraRes.setError(errorResponse);
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG015, new Object[ ] { error.getMessage() }));
	    } else {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG014));
	    }
	}

	return sigTraRes;
    }

    /**
     * Method that obtains the response of the get certificate information service.
     * @param cerInfReq Parameter that represents the request of the get certificate information service.
     * @return an object that represents the response of the get certificate information service.
     */
    public CertificateInfoResponse getCertificateInfo(CertificateInfoRequest cerInfReq) {
	Throwable error = null;
	CertificateInfoResponse cerInfRes = new CertificateInfoResponse();
	Map<String, Object> inParams = new HashMap<String, Object>();

	inParams.put(NativeTagsRequest.ID_APLICACION, cerInfReq.getApplicationId());
	byte[ ] certificate = cerInfReq.getCertificate();
	if (certificate != null) {
	    inParams.put(NativeTagsRequest.CERTIFICADO, new String(certificate));
	} else {
	    inParams.put(NativeTagsRequest.CERTIFICADO, null);
	}

	try {
	    // se comprueba que se han introducidos los parámetros obligatorios
	    // para la petición
	    if (!GenericUtilsCommons.assertStringValue(cerInfReq.getApplicationId()) || !GenericUtilsCommons.assertArrayValid(cerInfReq.getCertificate())) {
		throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.IFWS_LOG009));
	    }

	    // se crea mensaje XML de petición.
	    String xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, TransformersConstants.VERSION_10);
	    // se invoca al servicio obtenr información certificado
	    String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, cerInfReq.getApplicationId());
	    // parseamos el resultado.
	    Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO, TransformersConstants.VERSION_10);
	    // se crea el objeto de respuesta
	    // se comprueba si la respuesta es válida o no
	    if (propertiesResult.containsKey(NativeTagsResponse.ERROR_RESPONSE_CODE)) {
		// respuesta de error
		String codeError = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_CODE).toString();
		String description = propertiesResult.get(NativeTagsResponse.ERROR_RESPONSE_DESCRIPTION).toString();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		cerInfRes.setError(errorResponse);

	    } else {
		// respuesta correcta
		cerInfRes.setMapInfoCertificate(propertiesResult);
	    }
	} catch (TransformersException e) {
	    error = e;
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG001));

	} catch (WSServiceInvokerException e) {
	    error = e;
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG002, new Object[ ] { GeneralConstants.OBTENER_INFO_CERTIFICADO }));
	} finally {
	    if (error != null) {
		// creamos respuesta de error
		String codeError = COD_ERROR;
		String description = error.getMessage();
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setCodeError(codeError);
		errorResponse.setDescription(description);
		cerInfRes.setError(errorResponse);
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG017, new Object[ ] { error.getMessage() }));
	    } else {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.IFWS_LOG016));
	    }
	}

	return cerInfRes;
    }

}
