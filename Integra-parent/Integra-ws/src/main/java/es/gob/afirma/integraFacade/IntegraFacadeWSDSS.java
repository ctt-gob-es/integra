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
 * <b>File:</b><p>es.gob.afirma.integraFacade.IntegraFacadeWSDSS.java.</p>
 * <b>Description:</b><p>Class that represents the facade which manages the invocation of DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>17/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 06/10/2017.
 */
package es.gob.afirma.integraFacade;

import java.util.Map;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
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
import es.gob.afirma.integraFacade.pojo.ServerSignerRequest;
import es.gob.afirma.integraFacade.pojo.ServerSignerResponse;
import es.gob.afirma.integraFacade.pojo.UpgradeSignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.VerifySignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerifySignatureResponse;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.wsServiceInvoker.Afirma5ServiceInvokerFacade;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that represents the facade which manages the invocation of DSS web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 06/10/2017.
 */
public final class IntegraFacadeWSDSS {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(IntegraFacadeWSDSS.class);

    /**
     * Attribute that represents the instance of the class.
     */
    private static IntegraFacadeWSDSS instance;

    /**
     * Constructor method for the class IntegraFacadeWSDSS.java.
     */
    private IntegraFacadeWSDSS() {
    }

    /**
     * Method that obtains an instance of the class.
     * @return the unique instance of the class.
     */
    public static IntegraFacadeWSDSS getInstance() {
	if (instance == null) {
	    instance = new IntegraFacadeWSDSS();
	}
	return instance;
    }

    /**
     * Method that obtains the response of the server signature service.
     * @param serSigReq Parameter that represents the request of the server signature service.
     * @return an object that represents the response of the server signature service.
     */
    public ServerSignerResponse sign(ServerSignerRequest serSigReq) {
	return sign(serSigReq, null);
    }

    /**
     * Method that obtains the response of the server signature service.
     * @param serSigReq Parameter that represents the request of the server signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server signature service.
     */
    protected ServerSignerResponse sign(ServerSignerRequest serSigReq, String idClient) {
	ServerSignerResponse serSigRes = new ServerSignerResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateServerSignerRequest(serSigReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del párametro de entrada
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateServerSignerRequest(serSigReq);
	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio almacenar documento
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, serSigReq.getApplicationId(), idClient);
		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);

		// creamos el objeto de respuesta
		if (propertiesResult != null) {
		    GenerateMessageResponse.generateServerSignerResponse(propertiesResult, serSigRes);
		}
	    }

	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG040, new Object[ ] { e.getMessage() }));
	}
	return serSigRes;

    }

    /**
     * Method that obtains the response of the server co-signature service.
     * @param coSigReq Parameter that represents the request of the server co-signature service.
     * @return an object that represents the response of the server co-signature service.
     */
    public ServerSignerResponse coSign(CoSignRequest coSigReq) {
	return coSign(coSigReq, null);
    }

    /**
     * Method that obtains the response of the server co-signature service.
     * @param coSigReq Parameter that represents the request of the server co-signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server co-signature service.
     */
    protected ServerSignerResponse coSign(CoSignRequest coSigReq, String idClient) {
	ServerSignerResponse serSigRes = new ServerSignerResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateCoSignRequest(coSigReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del párametro de entrada
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateCoSignRequest(coSigReq);
	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio almacenar documento
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, coSigReq.getApplicationId(), idClient);
		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);

		// creamos el objeto de respuesta
		if (propertiesResult != null) {
		    GenerateMessageResponse.generateServerSignerResponse(propertiesResult, serSigRes);
		}

	    }
	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG041, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG041, new Object[ ] { e.getMessage() }));
	}
	return serSigRes;

    }

    /**
     * Method that obtains the response of the server counter-signature service.
     * @param couSigReq Parameter that represents the request of the server counter-signature service.
     * @return an object that represents the response of the server counter-signature service.
     */
    public ServerSignerResponse counterSign(CounterSignRequest couSigReq) {
	return counterSign(couSigReq, null);
    }

    /**
     * Method that obtains the response of the server counter-signature service.
     * @param couSigReq Parameter that represents the request of the server counter-signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server counter-signature service.
     */
    protected ServerSignerResponse counterSign(CounterSignRequest couSigReq, String idClient) {

	ServerSignerResponse serSigRes = new ServerSignerResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateCounterSignRequest(couSigReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del párametro de entrada
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateCounterSignRequest(couSigReq);
	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio almacenar documento
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, couSigReq.getApplicationId(), idClient);
		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_SIGN_REQUEST, GeneralConstants.DSS_AFIRMA_SIGN_METHOD, TransformersConstants.VERSION_10);

		// creamos el objeto de respuesta
		if (propertiesResult != null) {
		    GenerateMessageResponse.generateServerSignerResponse(propertiesResult, serSigRes);

		}

	    }
	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG042, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG042, new Object[ ] { e.getMessage() }));
	}
	return serSigRes;

    }

    /**
     * Method that obtains the response of the verify signature service.
     * @param verSigReq Parameter that represents the request of the verify signature service.
     * @return an object that represents the response of the verify signature service.
     */
    public VerifySignatureResponse verifySignature(VerifySignatureRequest verSigReq) {
	return verifySignature(verSigReq, null);
    }

    /**
     * Method that obtains the response of the verify signature service.
     * @param verSigReq Parameter that represents the request of the verify signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the verify signature service.
     */
    protected VerifySignatureResponse verifySignature(VerifySignatureRequest verSigReq, String idClient) {
	VerifySignatureResponse verSigRes = new VerifySignatureResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateVerifySignerRequest(verSigReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del párametro de entrada
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateVerifySignRequest(verSigReq);
	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio almacenar documento
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, verSigReq.getApplicationId(), idClient);

		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);

		// creamos el objeto de respuesta
		if (propertiesResult != null) {

		    GenerateMessageResponse.generateVerifySignatureResponse(propertiesResult, verSigRes);
		}

	    }
	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG033, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG033, new Object[ ] { e.getMessage() }));
	}
	return verSigRes;

    }

    /**
     * Method that obtains the response of the upgrade signature service.
     * @param upgSigReq Parameter that represents the request of the upgrade signature service.
     * @return an object that represents the response of the upgrade signature service.
     */
    public ServerSignerResponse upgradeSignature(UpgradeSignatureRequest upgSigReq) {
	return upgradeSignature(upgSigReq, null);
    }

    /**
     * Method that obtains the response of the upgrade signature service.
     * @param upgSigReq Parameter that represents the request of the upgrade signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the upgrade signature service.
     */
    protected ServerSignerResponse upgradeSignature(UpgradeSignatureRequest upgSigReq, String idClient) {
	ServerSignerResponse serSigRes = new ServerSignerResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateUpgradeSignatureRequest(upgSigReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    // se crea el mensaje de petición a partir del párametro de
	    // entrada
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateUpgradeSignatureRequest(upgSigReq);

	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio almacenar documento
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, upgSigReq.getApplicationId(), idClient);

		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);

		if (propertiesResult != null) {
		    GenerateMessageResponse.generateServerSignerResponse(propertiesResult, serSigRes);
		}

	    }

	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG031, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG031, new Object[ ] { e.getMessage() }));
	}
	return serSigRes;
    }

    /**
     * Method that obtains the response of the verify certificate service.
     * @param verCerReq Parameter that represents the request of the verify certificate service.
     * @return an object that represents the response of the verify certificate service.
     */
    public VerifyCertificateResponse verifyCertificate(VerifyCertificateRequest verCerReq) {
	return verifyCertificate(verCerReq, null);
    }

    /**
     * Method that obtains the response of the verify certificate service.
     * @param verCerReq Parameter that represents the request of the verify certificate service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the verify certificate service.
     */
    protected VerifyCertificateResponse verifyCertificate(VerifyCertificateRequest verCerReq, String idClient) {
	VerifyCertificateResponse verCerRes = new VerifyCertificateResponse();
	// se comprueba que cumple los requisitos
	String resultValidate = ValidateRequest.validateVerifyCertificateRequest(verCerReq);
	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del párametro de
	    // entrada
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateVerifyCertificateRequest(verCerReq);

	    if (inputParameters != null) {
		// se crea mensaje XML de petición.
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio "validar certificado"
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, verCerReq.getApplicationId(), idClient);

		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);

		if (propertiesResult != null) {
		    GenerateMessageResponse.generateVerifyCertificateResponse(propertiesResult, verCerRes);
		}

	    }

	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG043, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG043, new Object[ ] { e.getMessage() }));
	}
	return verCerRes;
    }

    /**
     * Method that obtains the response of the verify signatures on batch service.
     * @param batVerSigReq Parameter that represents the request of the verify signatures on batch service.
     * @return an object that represents the response of the verify signatures on batch service.
     */
    public BatchVerifySignatureResponse batchVerifySignature(BatchVerifySignatureRequest batVerSigReq) {
	return batchVerifySignature(batVerSigReq, null);
    }

    /**
     * Method that obtains the response of the verify signatures on batch service.
     * @param batVerSigReq Parameter that represents the request of the verify signatures on batch service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the verify signatures on batch service.
     */
    protected BatchVerifySignatureResponse batchVerifySignature(BatchVerifySignatureRequest batVerSigReq, String idClient) {

	BatchVerifySignatureResponse batVerSigRes = new BatchVerifySignatureResponse();

	// se comprueba que se cumple los requisitos
	String resultValidate = ValidateRequest.validateBatchVerifySignatureRequest(batVerSigReq);

	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del parámetro de entrada.
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateBatchVerifySignatureRequest(batVerSigReq);

	    if (inputParameters != null) {
		// se crea mensaje XML de petición
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_BATCH_VERIFY_SIGNATURE_REQUESTS, GeneralConstants.DSS_AFIRMA_VERIFY_SIGNATURES_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio "verificar firmas en lotes"
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_BATCH_VERIFY_SIGNATURE_REQUESTS, GeneralConstants.DSS_AFIRMA_VERIFY_SIGNATURES_METHOD, batVerSigReq.getApplicationId(), idClient);

		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_BATCH_VERIFY_SIGNATURE_REQUESTS, GeneralConstants.DSS_AFIRMA_VERIFY_SIGNATURES_METHOD, TransformersConstants.VERSION_10);

		if (propertiesResult != null) {
		    GenerateMessageResponse.generateBatchVerifySignatureResponse(propertiesResult, batVerSigRes);
		}

	    }

	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG036, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG036, new Object[ ] { e.getMessage() }));
	}

	return batVerSigRes;
    }

    /**
     * Method that obtains the response of the verify certificates on batch service.
     * @param batVerCerReq Parameter that represents the request of the verify certificates on batch service.
     * @return an object that represents the response of the verify certificates on batch service.
     */
    public BatchVerifyCertificateResponse batchVerifyCertificate(BatchVerifyCertificateRequest batVerCerReq) {
	return batchVerifyCertificate(batVerCerReq, null);
    }

    /**
     * Method that obtains the response of the verify certificates on batch service.
     * @param batVerCerReq Parameter that represents the request of the verify certificates on batch service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the verify certificates on batch service.
     */
    protected BatchVerifyCertificateResponse batchVerifyCertificate(BatchVerifyCertificateRequest batVerCerReq, String idClient) {

	BatchVerifyCertificateResponse batVerCerRes = new BatchVerifyCertificateResponse();

	// se comprueba que se cumple los requisitos
	String resultValidate = ValidateRequest.validateBatchVerifyCertificateRequest(batVerCerReq);

	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    // se crea el mensaje de petición a partir del parámetro de entrada.
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateBatchVerifyCertificateRequest(batVerCerReq);

	    if (inputParameters != null) {
		// se crea mensaje XML de petición
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_BATCH_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATES_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio "verificar certificados en lotes"
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_BATCH_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATES_METHOD, batVerCerReq.getApplicationId(), idClient);

		// parseamos el resultado.
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_BATCH_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATES_METHOD, TransformersConstants.VERSION_10);

		if (propertiesResult != null) {
		    GenerateMessageResponse.generateBatchVerifyCertificateResponse(propertiesResult, batVerCerRes);
		}
	    }

	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG037, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG037, new Object[ ] { e.getMessage() }));
	}

	return batVerCerRes;
    }

    /**
     * Method that obtains the response of the async processes service.
     * @param pendingRequest Parameter that represents the request of the async processes service.
     * @return an object that represents the response of the async processes service.
     */
    public AsynchronousResponse asynchronousRequest(PendingRequest pendingRequest) {
	return asynchronousRequest(pendingRequest, null);
    }

    /**
     * Method that obtains the response of the async processes service.
     * @param pendingRequest Parameter that represents the request of the async processes service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the async processes service.
     */
    protected AsynchronousResponse asynchronousRequest(PendingRequest pendingRequest, String idClient) {

	AsynchronousResponse asyncResponse = new AsynchronousResponse();

	// se comprueba que se cumple los requisitos
	String resultValidate = ValidateRequest.validatePendingRequest(pendingRequest);

	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    // se crea el mensaje de petición a partir del parámetro de entrada.
	    Map<String, Object> inputParameters = GenerateMessageRequest.generatePendingRequest(pendingRequest);

	    if (inputParameters != null) {
		// se crea mensaje XML de petición
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_ASYNC_REQUEST_STATUS, GeneralConstants.DSS_ASYNC_REQUEST_STATUS_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio "consultas peticiones asíncronas"
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_ASYNC_REQUEST_STATUS, GeneralConstants.DSS_ASYNC_REQUEST_STATUS_METHOD, pendingRequest.getApplicationId(), idClient);

		// parseamos el resultado
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_ASYNC_REQUEST_STATUS, GeneralConstants.DSS_ASYNC_REQUEST_STATUS_METHOD, TransformersConstants.VERSION_10);

		if (propertiesResult != null) {

		    // Se comprueba qué servicio se está invocando para generar
		    // el objeto de respuesta
		    String service = null;
		    if (xmlOutput.contains(GeneralConstants.ASYNC_BATCH_REPONSE)) {
			if (xmlOutput.contains(GeneralConstants.ASYNC_BATCH_DS_X509DATA) || xmlOutput.contains(GeneralConstants.VERIFY_CERTIFICATE_TYPE)) {
			    // si contiene ds:X509Data es verificacion de
			    // certificados por lotes
			    service = GeneralConstants.BATH_VERIFY_CERTIFICATE;
			} else {
			    // es verificación de firmas por lotes
			    service = GeneralConstants.BATH_VERIFY_SIGNATURE;
			}

		    } else if (xmlOutput.contains(GeneralConstants.ASYNC_DSS_RESPONSE)) {
			service = GeneralConstants.INVALID_ASYNC_RESPONSE;
		    } else {
			service = GeneralConstants.SERVER_SIGNER_RESPONSE;
		    }

		    GenerateMessageResponse.generateAsynchronousResponse(propertiesResult, asyncResponse, service);
		}

	    }

	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG038, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG038, new Object[ ] { e.getMessage() }));
	}
	return asyncResponse;
    }

    /**
     * Method that obtains the response of the archive signatures retrieve service.
     * @param archiveRequest Parameter that represents the request of the archive signatures retrieve service.
     * @return an object that represents the response of the archive signatures retrieve service.
     */
    public ArchiveResponse getArchiveRetrieval(ArchiveRequest archiveRequest) {
	return getArchiveRetrieval(archiveRequest, null);
    }

    /**
     * Method that obtains the response of the archive signatures retrieve service.
     * @param archiveRequest Parameter that represents the request of the archive signatures retrieve service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the archive signatures retrieve service.
     */
    protected ArchiveResponse getArchiveRetrieval(ArchiveRequest archiveRequest, String idClient) {

	ArchiveResponse archiveResponse = new ArchiveResponse();
	// se comprueba que se cumple los requisitos

	String resultValidate = ValidateRequest.validateArchiveRequest(archiveRequest);

	try {
	    if (resultValidate != null) {
		throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    // se crea el mensaje de petición a partir del parámetro de entrada.
	    Map<String, Object> inputParameters = GenerateMessageRequest.generateArchiveRequest(archiveRequest);

	    if (inputParameters != null) {
		// se crea mensaje XML de petición
		String xmlInput = TransformersFacade.getInstance().generateXml(inputParameters, GeneralConstants.DSS_AFIRMA_ARCHIVE_RETRIEVAL, GeneralConstants.DSS_ARCHIVE_RETRIEVAL_METHOD, TransformersConstants.VERSION_10);

		// se invoca al servicio "obtención de firmas registradas"
		String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_ARCHIVE_RETRIEVAL, GeneralConstants.DSS_ARCHIVE_RETRIEVAL_METHOD, archiveRequest.getApplicationId(), idClient);

		// parseamos el resultado
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_ARCHIVE_RETRIEVAL, GeneralConstants.DSS_ARCHIVE_RETRIEVAL_METHOD, TransformersConstants.VERSION_10);

		if (propertiesResult != null) {

		    GenerateMessageResponse.generateArchiveResponse(propertiesResult, archiveResponse);
		}

	    }

	} catch (WSServiceInvokerException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG039, new Object[ ] { e.getMessage() }));
	} catch (TransformersException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG039, new Object[ ] { e.getMessage() }));
	}
	return archiveResponse;
    }

}
