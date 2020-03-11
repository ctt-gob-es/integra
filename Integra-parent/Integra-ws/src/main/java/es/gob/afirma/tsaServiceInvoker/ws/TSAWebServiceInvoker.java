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
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.ws.TSAWebServiceInvoker.java.</p>
 * <b>Description:</b><p>Class that manages the invoke of TS@ web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.4, 11/03/2020.
 */
package es.gob.afirma.tsaServiceInvoker.ws;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.stream.XMLStreamException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.Handler;
import org.apache.axis2.engine.Phase;
import org.apache.axis2.phaseresolver.PhaseException;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.util.XMLUtils;
import org.apache.log4j.Logger;
import org.apache.xml.crypto.dsig.XMLSignature;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerFacade;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.DSSConstants.ResultProcessIds;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.UtilsAxis;
import es.gob.afirma.utils.UtilsTimestampWS;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerConstants;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that manages the invoke of TS@ web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.4, 11/03/2020.
 */
public class TSAWebServiceInvoker {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TSAWebServiceInvoker.class);

    /**
     * Attribute that represents the properties defined on the configuration file.
     */
    private Properties properties;

    /**
     * Attribute that represents the properties defined on the general configuration file.
     */
    private Properties generalProperties;

    /**
     * Constant attribute that identifies the validation mode <i>NONE</i> of the time-stamp to send to renew time-stamp service of the TS@. In this mode,
     * the previous time-stamp will not be validated before to call to the renew time-stamp service of the TS@.
     */
    public static final int VALIDATION_MODE_RENEW_TIMESTAMP_NONE = 0;

    /**
     * Constant attribute that identifies the validation mode <i>SIMPLE</i> of the time-stamp to send to renew time-stamp service of the TS@. In this mode,
     * the integrity of the previous time-stamp will be validated before to call to the renew time-stamp service of the TS@.
     */
    public static final int VALIDATION_MODE_RENEW_TIMESTAMP_SIMPLE = 1;

    /**
     * Constant attribute that identifies the validation mode <i>SIMPLE</i> of the time-stamp to send to renew time-stamp service of the TS@. In this mode,
     * the previous time-stamp will be validated by the validation time-stamp service of the TS@ before to call to the renew time-stamp service of the TS@.
     */
    public static final int VALIDATION_MODE_RENEW_TIMESTAMP_COMPLETE = 2;

    /**
     * Constant attribute that identifies not secure communication.
     */
    private static final String NO_SECURE_PROTOCOL = "http";

    /**
     * Constant attribute that identifies secure communication.
     */
    private static final String SECURE_PROTOCOL = "https";

    /**
     * Constant attribute that identifier the security Axis2 phase. 
     */
    private static final String PHASE_NAME_SECURITY = "Security";

    /**
     * Constant attribute that identifier the dispatch Axis2 phase. 
     */
    private static final String PHASE_NAME_DISPATCH = "Dispatch";

    /**
     * Attribute that represents the list of handlers added to the Axis engine. 
     */
    private static List<String> handlerAdded = new ArrayList<String>();

    /**
     * Constructor method for the class TSAWebServiceInvoker.java.
     * @param propertiesParam Parameter that represents the properties defined on the configuration file.
     * @param generalPropertiesParam Parameter that represents the general properties of Integr@.
     */
    public TSAWebServiceInvoker(Properties propertiesParam, Properties generalPropertiesParam) {
	properties = propertiesParam;
	generalProperties = generalPropertiesParam;
    }

    /**
     * Method that performs the invocation to a method form TS@ web services.
     * @param serviceName Parameter that represents the name of the service to invoke.
     * @param params List of parameters related to the method to invoke.
     * @param idClient client identifier of WS invocation.
     * @return the response of TS@.
     * @throws TSAServiceInvokerException If the method fails.
     */
    public final Object performCall(String serviceName, Object[ ] params, String idClient) throws TSAServiceInvokerException {
	String endPointURL, securityOption, secureMode, tsaService, protocol,
		endPoint, servicePath, timeout;
	Object res = null;
	ServiceClient client = null;
	try {
	    // Recuperamos el nombre del servicio al que atacar.
	    tsaService = this.properties.getProperty(WSServiceInvokerConstants.TSA_SERVICE);

	    // Recuperamos el protocolo de conexión (http o https).
	    secureMode = this.properties.getProperty(WSServiceInvokerConstants.SECURE_MODE_PROPERTY);
	    protocol = NO_SECURE_PROTOCOL;
	    if (secureMode != null && secureMode.equals("true")) {
		protocol = SECURE_PROTOCOL;
	    }

	    // Recuperamos el socket de conexión al que atacar.
	    endPoint = this.properties.getProperty(WSServiceInvokerConstants.WS_ENDPOINT_PROPERTY);

	    checkSvcInvokerParams(WSServiceInvokerConstants.WS_ENDPOINT_PROPERTY, endPoint);
	    servicePath = this.properties.getProperty(WSServiceInvokerConstants.WS_SRV_PATH_PROPERTY);
	    checkSvcInvokerParams(WSServiceInvokerConstants.WS_SRV_PATH_PROPERTY, servicePath);

	    // Obtenemos la URL completa.
	    endPointURL = protocol + "://" + endPoint + "/" + servicePath + "/" + tsaService;

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG001, new Object[ ] { tsaService }));
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG002, new Object[ ] { endPointURL }));

	    // Recuperamos el modo de autenticación de la comunicación con la
	    // plataforma: UserNameToken, X509CertificateToken o SAMLToken.
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG003));
	    securityOption = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP);
	    checkSvcInvokerParams(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP, securityOption);
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG004, new Object[ ] { securityOption }));

	    // Establecemos los datos relativos al almacén de claves para
	    // conexiones seguras.
	    configureSSLTrustStore();

	    // Comprobamos si el servicio solicitado es el de renovación de
	    // sello de tiempo, en cuyo caso, llevamos a cabo la validación del
	    // sello de tiempo previo en función del parámetro indicado en el
	    // archivo de propiedades
	    int validationMode = processValidationRenewTimestampService(serviceName);

	    // Creamos los handlers de petición y respuesta.
	    TSAClientHandler clientHandler = newRequestHandler(securityOption);
	    TSAResponseHandler responseHandler = newResponseHandler();
	    MustUnderstandResponseHander mustUnderstandResponseHandler = new MustUnderstandResponseHander();
	    TSAClientSymmetricKeyHandler clientSymmetricKeyHandler = newTSAClientSymmetricKeyHandler();
	    TSAResponseSymmetricKeyHandler responseSymmetricKeyHandler = newTSAResponseSymmetricKeyHandler();

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG007, new Object[ ] { serviceName }));

	    // recuperamos el timeout de la conexión.
	    timeout = this.properties.getProperty(WSServiceInvokerConstants.WS_CALL_TIMEOUT_PROP);
	    checkSvcInvokerParams(WSServiceInvokerConstants.WS_CALL_TIMEOUT_PROP, timeout);
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG008, new Object[ ] { timeout }));

	    // Creamos la factoria de objetos XML de AXIS2.
	    OMFactory fac = OMAbstractFactory.getOMFactory();

	    // Creamos el namespace de la petición.
	    OMNamespace ns = fac.createOMNamespace("http://soapinterop.org/", "ns1");
	    // // Creamos el elemento XML raíz del SOAP body que indica la
	    // // operación a realizar.
	    // OMElement operationElem = fac.createOMElement(serviceName, ns);
	    // Creamos el elemento XML que contendrá la petición SOAP completa.
	    OMElement inputParamElem = fac.createOMElement("arg0", ns);
	    // Añadimos la petición al parámetro de entrada principal.

	    // Obtenemos los parámetros obtenidos procesando la plantilla XML
	    String templateXML = params[0].toString();
	    // Eliminamos de la plantilla XML la cabecera XML
	    templateXML = templateXML.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
	    // Definimos el mensaje SOAP
	    String msgString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
	    msgString = msgString + templateXML;
	    // Eliminamos los saltos de línea, retornos de carro y sangrado
	    msgString = msgString.replaceAll("[\n\r\t]", "");

	    // Convertimos la petición en un objeto OM de Axis2.
	    inputParamElem = AXIOMUtil.stringToOM(msgString);

	    // Comprobamos si es necesario realizar alguna validación previa.
	    checkPreviousValidation(validationMode, inputParamElem, idClient);

	    // Creamos un objeto Option que albergará la configuración de
	    // conexión al servicio.
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG006));
	    Options options = new Options();
	    options.setTimeOutInMilliSeconds(Integer.valueOf(timeout));
	    options.setTo(new EndpointReference(endPointURL));

	    // Desactivamos el chunked.
	    options.setProperty(HTTPConstants.CHUNKED, "false");

	    // Generamos el cliente.
	    client = new ServiceClient();
	    client.setOptions(options);

	    // Añadimos los handler generados a las distintas 'phases' de Axis2.
	    addHandlers(client, clientHandler, clientSymmetricKeyHandler, responseHandler, responseSymmetricKeyHandler, mustUnderstandResponseHandler);

	    // Realizamos la llamada.
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG009));
	    OMElement result = client.sendReceive(inputParamElem);

	    if (result != null && result.getFirstElement() != null && !result.getFirstElement().toString().isEmpty()) {
		res = result.toString();
	    } else {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.WSI_LOG018));
	    }

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG011, new Object[ ] { res }));

	} catch (AxisFault e) {
	    throw new TSAServiceInvokerException(e);
	} catch (XMLStreamException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.WSI_LOG019));
	} catch (WSServiceInvokerException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.WSI_LOG020));
	} finally {
	    removeHandlers(client);
	}
	return res;
    }

    /**
     * Auxiliary method that checks if it is necessary to perform some extra validation.
     * @param validationMode Validation mode specified.
     * @param inputParamElem SOAP body content.
     * @param idClient Client ID.
     * @throws TSAServiceInvokerException if some error ocurred.
     */
    private void checkPreviousValidation(int validationMode, OMElement inputParamElem, String idClient) throws TSAServiceInvokerException {
	// En caso de que nos encontremos en una petición de renovación de
	// sello de tiempo y se haya indicado que se debe llevar a cabo una
	// validación integral del sello de tiempo, comprobamos si el
	// InputDocument indicado coincide con el sello de tiempo indicado
	// como previo.
	if (validationMode == VALIDATION_MODE_RENEW_TIMESTAMP_SIMPLE) {
	    SOAPEnvelope se = OMAbstractFactory.getSOAP11Factory().createSOAPEnvelope();
	    se.addChild(OMAbstractFactory.getSOAP11Factory().createSOAPBody());
	    se.getBody().addChild(inputParamElem);
	    validatePreviousTimestampStructurally(se);
	}
	// En caso de que nos encontremos en una petición de renovación de
	// sello de tiempo y se haya indicado que se debe llevar a cabo una
	// validación completa, se lanza una petición de validación de sello
	// de tiempo previo, y posteriormente, se lleva a cabo la petición
	// de renovación de sello de tiempo, en caso de que la respuesta
	// haya sido correcta.
	else if (validationMode == VALIDATION_MODE_RENEW_TIMESTAMP_COMPLETE) {
	    SOAPEnvelope se = OMAbstractFactory.getSOAP11Factory().createSOAPEnvelope();
	    se.addChild(OMAbstractFactory.getSOAP11Factory().createSOAPBody());
	    se.getBody().addChild(inputParamElem);
	    validatePreviousTimestampViaTSA(se, idClient);
	}
    }

    /**
     * Auxiliary method that includes the generated handlers into the Axis2 phases.
     * This method was necessary in order to reduce the cyclomatic complexity.
     * @param client Axis client.
     * @param clientHandler Client handler.
     * @param clientSymmetricKeyHandler Symmetric key handler. 
     * @param responseHandler Response handler.
     * @param responseSymmetricKeyHandler Response symmetric key handler.
     * @param mustUnderstandResponseHandler MustUnderstand response handler.
     * @throws TSAServiceInvokerException if some error occurred in the process.
     */
    private void addHandlers(ServiceClient client, TSAClientHandler clientHandler, TSAClientSymmetricKeyHandler clientSymmetricKeyHandler, TSAResponseHandler responseHandler, TSAResponseSymmetricKeyHandler responseSymmetricKeyHandler, MustUnderstandResponseHander mustUnderstandResponseHandler) throws TSAServiceInvokerException {

	String errorMsg = Language.getResIntegra(ILogConstantKeys.WSI_LOG021);

	// Añadimos el handler de seguridad de salida.
	AxisConfiguration config = client.getAxisConfiguration();
	List<Phase> phasesOut = config.getOutFlowPhases();
	for (Phase phase: phasesOut) {
	    if (PHASE_NAME_SECURITY.equals(phase.getPhaseName())) {
		try {
		    addHandler(phase, clientHandler, 1);
		    addHandler(phase, clientSymmetricKeyHandler, 2);
		    break;
		} catch (PhaseException e) {
		    throw new TSAServiceInvokerException(errorMsg);
		}
	    }
	}

	// Añadimos el handler de seguridad de entrada.
	if (responseHandler != null) {
	    List<Phase> phasesIn = config.getInFlowPhases();
	    for (Phase phase: phasesIn) {
		if (PHASE_NAME_SECURITY.equals(phase.getPhaseName())) {
		    try {
			addHandler(phase, responseHandler, 1);
			addHandler(phase, responseSymmetricKeyHandler, 0);
		    } catch (PhaseException e) {
			throw new TSAServiceInvokerException(errorMsg);
		    }
		}
		if (PHASE_NAME_DISPATCH.equals(phase.getPhaseName())) {
		    try {
			addHandler(phase, mustUnderstandResponseHandler, 2);
		    } catch (PhaseException e) {
			throw new TSAServiceInvokerException(errorMsg);
		    }
		}
	    }
	}
    }

    /**
     * Method that removes the added handler from the axis engine.
     * @param client Axis service client.
     */
    private void removeHandlers(ServiceClient client) {
	if (client != null && !handlerAdded.isEmpty()) {
	    AxisConfiguration config = client.getAxisConfiguration();

	    // Recorremos las phases de salida.
	    List<Phase> phasesOut = config.getOutFlowPhases();
	    for (Phase phase: phasesOut) {
		removeHandler(phase);
	    }

	    // Recorremos las phases de entrada.
	    List<Phase> phasesIn = config.getInFlowPhases();
	    for (Phase phase: phasesIn) {
		removeHandler(phase);
	    }

	    // Reiniciamos la lista de handlers.
	    handlerAdded = new ArrayList<String>();
	}

    }

    /**
     * Auxiliary method that removes the added handler from the given phase.
     * @param phase Axis phase where the handlers are.
     */
    private void removeHandler(Phase phase) {
	if (phase != null) {
	    List<Handler> handlers = phase.getHandlers();
	    for (Handler handler: handlers) {
		if (handlerAdded.contains(handler.getName())) {
		    handler.getHandlerDesc().setHandler(handler);
		    phase.removeHandler(handler.getHandlerDesc());
		}
	    }
	}
    }

    /**
     * Auxiliary method that add a handler into an AXIS2 phase.
     * @param phase AXIS2 phase.
     * @param handler Handler to add.
     * @param position Indicates if the handler is added in the first place of the list (0), at the end (2) or is indifferent (1).
     * @throws PhaseException if it is not possible to add the handler to the phase.
     */
    private void addHandler(Phase phase, Handler handler, int position) throws PhaseException {
	if (position == 0 && !UtilsAxis.isHandlerInPhase(phase, handler)) {
	    phase.setPhaseFirst(handler);
	    handlerAdded.add(handler.getName());
	    return;
	}
	if (position == 1 && !UtilsAxis.isHandlerInPhase(phase, handler)) {
	    phase.addHandler(handler);
	    handlerAdded.add(handler.getName());
	    return;
	}
	if (position == 2 && !UtilsAxis.isHandlerInPhase(phase, handler)) {
	    phase.setPhaseLast(handler);
	    handlerAdded.add(handler.getName());
	    return;
	}
    }

    /**
     * Method that creates a new instance of {@link TSAClientHandler}.
     * @param securityOption Parameter that represents the security options.
     * @return the created instance of {@link TSAClientHandler}.
     * @throws WSServiceInvokerException If the method fails.
     */
    private TSAClientHandler newRequestHandler(String securityOption) throws WSServiceInvokerException {
	String autUser, autPassword, autPassType, keystorePath, keystorePass,
		keystoreType, samlMethod;

	autUser = "";
	autPassword = "";
	autPassType = "";
	keystorePath = "";
	keystorePass = "";
	keystoreType = "";
	samlMethod = "";

	String securityOpt = securityOption;
	if (securityOpt != null) {
	    if (securityOpt.equals(TSAClientHandler.USERNAME_OPTION)) {
		autPassType = "digest";
		autUser = this.properties.getProperty(WSServiceInvokerConstants.TSA__USER_WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZ_METHOD_USER_PROP);
		autPassword = this.properties.getProperty(WSServiceInvokerConstants.TSA__USER_WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_PASS_PROP);
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG013, new Object[ ] { autUser }));
	    } else if (securityOpt.equals(TSAClientHandler.CERTIFICATE_OPTION)) {
		keystorePath = this.properties.getProperty(WSServiceInvokerConstants.TSA_CERTIFICATE_WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PROP);
		keystorePass = this.properties.getProperty(WSServiceInvokerConstants.TSA_CERTIFICATE_WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PASS_PROP);
		keystoreType = this.properties.getProperty(WSServiceInvokerConstants.TSA_CERTIFICATE_WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_TYPE_PROP);
		autUser = this.properties.getProperty(WSServiceInvokerConstants.TSA_CERTIFICATE_WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_CERTNAME_PROP);
		autPassword = this.properties.getProperty(WSServiceInvokerConstants.TSA_CERTIFICATE_WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_AUTHORIZATION_METHOD_PRIVATEKEYPASSWORD_PROP);
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG015, new Object[ ] { keystorePath, keystoreType }));
	    } else if (securityOpt.equals(TSAClientHandler.SAML_OPTION)) {
		samlMethod = this.properties.getProperty(WSServiceInvokerConstants.TSA_SAML_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_SAML_AUTHORIZATION_METHOD_METHOD_PROP);
		keystorePath = this.properties.getProperty(WSServiceInvokerConstants.TSA_SAML_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PROP);
		keystorePass = this.properties.getProperty(WSServiceInvokerConstants.TSA_SAML_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PASS_PROP);
		keystoreType = this.properties.getProperty(WSServiceInvokerConstants.TSA_SAML_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_TYPE_PROP);
		autUser = this.properties.getProperty(WSServiceInvokerConstants.TSA_SAML_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_CERTNAME_PROP);
		autPassword = this.properties.getProperty(WSServiceInvokerConstants.TSA_SAML_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.TSA_AUTHORIZATION_METHOD_PRIVATEKEYPASSWORD_PROP);
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG015, new Object[ ] { keystorePath, keystoreType }));
	    }
	} else {
	    throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG022, new Object[ ] { securityOpt }));
	}

	TSAClientHandler sender = new TSAClientHandler(securityOpt);
	sender.setUserAlias(autUser);
	sender.setPassword(autPassword);
	sender.setSamlMethod(samlMethod);

	// Este parámetro solo tiene sentido si la autorizacion se realiza
	// mediante el tag de seguridad UserNameToken
	sender.setPasswordType(autPassType);

	// Propiedades para X509CertificateToken
	sender.setUserKeystore(keystorePath);
	sender.setUserKeystorePass(keystorePass);
	sender.setUserKeystoreType(keystoreType);
	return sender;
    }

    /**
     * Method that creates a new instance of {@link TSAResponseHandler}.
     * @return the created instance of {@link TSAResponseHandler}.
     */
    private TSAResponseHandler newResponseHandler() {
	if (Boolean.valueOf(this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.RESPONSE_VALIDATE_PROPERTY))) {
	    String keystorePath = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PROP);
	    String keystorePass = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PASS_PROP);
	    String keystoreType = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_TYPE_PROP);
	    String autUser = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.RESPONSE_ALIAS_CERT_PROPERTY);
	    String samlKeystorePath = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.PREFIX_RESPONSE_SAML_PROPERTY + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PROP);
	    String samlKeystorePass = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.PREFIX_RESPONSE_SAML_PROPERTY + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PASS_PROP);
	    String samlKeystoreType = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_TYPE_PROP);
	    String samlAutUser = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.PREFIX_RESPONSE_SAML_PROPERTY + "." + WSServiceInvokerConstants.RESPONSE_ALIAS_CERT_PROPERTY);

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG016, new Object[ ] { keystorePath, keystoreType, autUser }));
	    return new TSAResponseHandler(keystorePath, keystorePass, keystoreType, autUser, "", samlKeystorePath, samlKeystorePass, samlKeystoreType, samlAutUser);
	} else {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG017));
	    return null;
	}
    }

    /**
     * Method that creates a new instance of {@link TSAClientSymmetricKeyHandler}.
     * @return the created instance of {@link TSAClientSymmetricKeyHandler}.
     * @throws WSServiceInvokerException if the method fails.
     */
    private TSAClientSymmetricKeyHandler newTSAClientSymmetricKeyHandler() throws WSServiceInvokerException {
	TSAClientSymmetricKeyHandler handler = new TSAClientSymmetricKeyHandler();
	boolean encryptMessage = false;
	String encryptRequest = properties.getProperty(TSAServiceInvokerConstants.WS_REQUEST_SYMMETRICKEY_USE);
	if (encryptRequest.equalsIgnoreCase("true")) {
	    encryptMessage = true;
	} else if (encryptRequest.equalsIgnoreCase("false")) {
	    encryptMessage = false;
	} else {
	    throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.WSI_LOG023));
	}
	String requestSymmetricKeyAlias = properties.getProperty(TSAServiceInvokerConstants.WS_REQUEST_SYMMETRICKEY_ALIAS);
	String requestSymmetricKeyValue = properties.getProperty(TSAServiceInvokerConstants.WS_REQUEST_SYMMETRICKEY_VALUE);
	String requestSymmetricAlgorithm = properties.getProperty(TSAServiceInvokerConstants.WS_REQUEST_SYMMETRICKEY_ALGORITHM);

	handler.setEncryptMessage(encryptMessage);
	handler.setRequestSymmetricKeyAlias(requestSymmetricKeyAlias);
	handler.setRequestSymmetricKeyValue(requestSymmetricKeyValue);
	handler.setRequestSymmetricAlgorithm(requestSymmetricAlgorithm);
	return handler;
    }

    /**
     * Method that creates a new instance of {@link TSAResponseSymmetricKeyHandler}.
     * @return the created instance of {@link TSAResponseSymmetricKeyHandler}.
     * @throws WSServiceInvokerException if the method fails.
     */
    private TSAResponseSymmetricKeyHandler newTSAResponseSymmetricKeyHandler() throws WSServiceInvokerException {
	TSAResponseSymmetricKeyHandler handler = new TSAResponseSymmetricKeyHandler();
	boolean encryptMessage = false;
	String encryptRequest = properties.getProperty(TSAServiceInvokerConstants.WS_REQUEST_SYMMETRICKEY_USE);
	if (encryptRequest.equalsIgnoreCase("true")) {
	    encryptMessage = true;
	} else if (encryptRequest.equalsIgnoreCase("false")) {
	    encryptMessage = false;
	} else {
	    throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.WSI_LOG023));
	}
	String responseSymmetricKeyAlias = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_SYMMETRICKEY_ALIAS);
	String responseSymmetricKeyValue = properties.getProperty(TSAServiceInvokerConstants.WS_RESPONSE_SYMMETRICKEY_VALUE);

	handler.setEncryptMessage(encryptMessage);
	handler.setResponseSymmetricKeyAlias(responseSymmetricKeyAlias);
	handler.setResponseSymmetricKeyValue(responseSymmetricKeyValue);
	return handler;
    }

    /**
     * Method that obtains the previous time-stamp from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the previous time-stamp.
     * @param soapBody Parameter thtat represents the body of the time-stamp renovation request.
     * @throws TSAServiceInvokerException If the previous time-stamp cannot be retrieved.
     */
    private void setPreviousTimestampFromRequest(Map<String, Object> inParams, org.apache.axiom.soap.SOAPBody soapBody) throws TSAServiceInvokerException {
	try {
	    OMElement previousTimestampElement = UtilsAxis.findElementByTagName(soapBody, IXMLConstants.ELEMENT_PREVIOUS_TIMESTAMP);
	    Element timestampElement = XMLUtils.toDOM(UtilsAxis.findElementByTagName(previousTimestampElement, IXMLConstants.ELEMENT_TIMESTAMP));
	    Element childTimestampElement = (Element) timestampElement.getFirstChild();

	    String timestampTypeKey = null;
	    if (childTimestampElement.getLocalName().equals(IXMLConstants.ELEMENT_RFC3161_TIMESTAMPTOKEN)) {
		// Sello de tiempo previo RFC 3161
		timestampTypeKey = DSSTagsRequest.TIMESTAMP_RFC3161_TIMESTAMPTOKEN;
		inParams.put(timestampTypeKey, childTimestampElement.getTextContent());
	    } else if (childTimestampElement.getLocalName().equals(IXMLConstants.ELEMENT_SIGNATURE)) {
		// Sello de tiempo previo XML
		timestampTypeKey = DSSTagsRequest.TIMESTAMP_XML_TIMESTAMPTOKEN;

		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(childTimestampElement), new StreamResult(writer));
		inParams.put(timestampTypeKey, writer.getBuffer().toString());
	    }
	} catch (Exception e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	}
    }

    /**
     * Method that obtains the input document of type Document from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the input document.
     * @param document Parameter that represents the input document of type Document.
     * @throws TSAServiceInvokerException If the input document cannot be retrieved.
     */
    private void setDocumentFromRequest(Map<String, Object> inParams, Element document) throws TSAServiceInvokerException {
	// Document de tipo Base64XML
	if (document.getLocalName().equals(IXMLConstants.ELEMENT_BASE64_XML)) {
	    inParams.put(DSSTagsRequest.BASE64XML, document.getTextContent());
	}
	// Document de tipo InlineXML
	else if (document.getLocalName().equals(IXMLConstants.ELEMENT_INLINE_XML)) {
	    try {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(document.getFirstChild()), new StreamResult(writer));
		inParams.put(DSSTagsRequest.INLINEXML, writer.getBuffer().toString());
	    } catch (Exception e) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG064), e);
	    }
	}
	// Document de tipo EscapedXML
	else if (document.getLocalName().equals(IXMLConstants.ELEMENT_ESCAPED_XML)) {
	    inParams.put(DSSTagsRequest.ESCAPEDXML, document.getTextContent());
	}
	// Document de tipo Base64Data
	else if (document.getLocalName().equals(IXMLConstants.ELEMENT_BASE64_DATA)) {
	    // Obtenemos el valor del elemento
	    inParams.put(DSSTagsRequest.BASE64DATA, document.getTextContent());
	} else {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG064));
	}
    }

    /**
     * Method that obtains the input document of type DocumentHash from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the input document.
     * @param inputDocument Parameter that represents the input document of type DocumentHash.
     * @throws TSAServiceInvokerException If the input document cannot be retrieved.
     */
    private void setDocumentHashFromRequest(Map<String, Object> inParams, Element inputDocument) throws TSAServiceInvokerException {
	// Obtenemos el algoritmo de hash
	NodeList digestMethodNodeList = inputDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_METHOD);
	if (digestMethodNodeList.getLength() > 0) {
	    Element digestMethodElement = (Element) digestMethodNodeList.item(0);
	    inParams.put(DSSTagsRequest.DIGEST_METHOD_ATR_ALGORITHM, digestMethodElement.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM));
	} else {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_DIGEST_METHOD }));
	}
	// Obtenemos el valor del digest
	NodeList digestValueNodeList = inputDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_DIGEST_VALUE);
	if (digestValueNodeList.getLength() > 0) {
	    Element digestValueElement = (Element) digestValueNodeList.item(0);
	    inParams.put(DSSTagsRequest.DIGEST_VALUE, digestValueElement.getTextContent());
	} else {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_DIGEST_VALUE }));
	}
	// Obtenemos el valor de la transformada, en caso de existir
	NodeList transformsNodeList = inputDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORMS);
	if (transformsNodeList.getLength() > 0) {
	    Element transformsElement = (Element) transformsNodeList.item(0);
	    NodeList transformNodeList = transformsElement.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORM);
	    if (transformNodeList.getLength() > 0) {
		Element transformElement = (Element) transformNodeList.item(0);
		inParams.put(DSSTagsRequest.DOCUMENT_HASH_TRANSFORM_ATR_ALGORITHM, transformElement.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM));
	    }
	}
    }

    /**
     * Method that obtains the input document of type TransformedData from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the input document.
     * @param inputDocument Parameter that represents the input document of type TransformedData.
     * @throws TSAServiceInvokerException If the input document cannot be retrieved.
     */
    private void setTransformedDataFromRequest(Map<String, Object> inParams, Element inputDocument) throws TSAServiceInvokerException {
	// Obtenemos el valor de la transformada
	NodeList transformsNodeList = inputDocument.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORMS);
	if (transformsNodeList.getLength() > 0) {
	    Element transformsElement = (Element) transformsNodeList.item(0);
	    NodeList transformNodeList = transformsElement.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_TRANSFORM);
	    if (transformNodeList.getLength() > 0) {
		Element transformElement = (Element) transformNodeList.item(0);
		inParams.put(DSSTagsRequest.TRANSFORMED_DATA_TRANSFORM_ATR_ALGORITHM, transformElement.getAttribute(IXMLConstants.ATTRIBUTE_ALGORITHM));
	    } else {
		throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_TRANSFORM }));
	    }
	} else {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_TRANSFORMS }));
	}
	// Obtenemos el valor codificado en Base64
	NodeList base64DataNodeList = inputDocument.getElementsByTagNameNS(IXMLConstants.DSS_NAMESPACE, IXMLConstants.ELEMENT_BASE64_DATA);
	if (base64DataNodeList.getLength() > 0) {
	    Element base64DataElement = (Element) base64DataNodeList.item(0);
	    inParams.put(DSSTagsRequest.TRANSFORMED_DATA_BASE64DATA, base64DataElement.getTextContent());
	} else {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG065, new Object[ ] { IXMLConstants.ELEMENT_BASE64_DATA }));
	}
    }

    /**
     * Method that obtains the input document from a time-stamp renovation request.
     * @param inParams Map with the input parameters related to the XML request of the web service to update with the value of the input document.
     * @param soapBody Parameter that represents the body of the time-stamp renovation request.
     * @throws TSAServiceInvokerException If the input document cannot be retrieved.
     */
    private void setInputDocumentFromRequest(Map<String, Object> inParams, org.apache.axiom.soap.SOAPBody soapBody) throws TSAServiceInvokerException {
	Element inputDocumentsElement;
	try {
	    inputDocumentsElement = XMLUtils.toDOM(UtilsAxis.findElementByTagName(soapBody, IXMLConstants.ELEMENT_INPUT_DOCUMENTS));
	    Element inputDocument = (Element) inputDocumentsElement.getFirstChild();
	    // InputDocument de tipo Document
	    if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_DOCUMENT)) {
		Element documentType = (Element) inputDocument.getFirstChild();
		setDocumentFromRequest(inParams, documentType);
	    }
	    // InputDocument de tipo DocumentHash
	    else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_DOCUMENT_HASH)) {
		setDocumentHashFromRequest(inParams, inputDocument);
	    }
	    // InputDocument de tipo TransformedData
	    else if (inputDocument.getLocalName().equals(IXMLConstants.ELEMENT_TRANSFORMED_DATA)) {
		setTransformedDataFromRequest(inParams, inputDocument);
	    } else {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG064));
	    }

	} catch (Exception e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG064));
	}
    }

    /**
     * Method that validates the previous time-stamp via TS@ DSS web service.
     * @param se Parameter that represents the time-stamp renovation request.
     * @param idClient client identifier of WS invocation.
     * @throws TSAServiceInvokerException If the validation fails.
     */
    private void validatePreviousTimestampViaTSA(SOAPEnvelope se, String idClient) throws TSAServiceInvokerException {
	try {
	    org.apache.xml.security.Init.init();
	    org.apache.axiom.soap.SOAPBody soapBody = se.getBody();

	    // Definimos el mapa con los parámetros de entrada para la petición
	    // de validación del sello de tiempo
	    Map<String, Object> inParams = new HashMap<String, Object>();

	    // Obtenemos el identificador de aplicación
	    String idApplication = UtilsAxis.findElementByTagName(soapBody, TSAServiceInvokerConstants.SOAPElements.ID_APPLICATION).getText();
	    inParams.put(DSSTagsRequest.CLAIMED_IDENTITY_TSA, idApplication);

	    // Obtenemos el sello de tiempo previo
	    setPreviousTimestampFromRequest(inParams, soapBody);

	    // Obtenemos el InputDocument
	    setInputDocumentFromRequest(inParams, soapBody);

	    // Construímos el XML de petición para validar el sello de tiempo
	    String xmlInput = null;
	    try {
		xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);
	    } catch (TransformersException e) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG066), e);
	    }

	    // Invocamos al servicio de validación de sello de tiempo de TS@
	    String xmlOutput = TSAServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, idApplication, idClient);

	    try {
		// Obtenemos el resultado de la inovación al servicio
		Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_TSA_REQUEST, GeneralConstants.TSA_TIMESTAMP_VALIDATION_SERVICE, TransformersConstants.VERSION_10);

		// Si el resultado obtenido no es correcto, lanzamos una
		// excepción
		String resultMayor = (String) propertiesResult.get("dss:Result/dss:ResultMajor");
		if (!resultMayor.equals(ResultProcessIds.SUCESS)) {
		    // Accedemos al mensaje de error
		    String resultMessage = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue(TSAServiceInvokerConstants.SOAPElements.RESULT_MESSAGE));
		    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG068, new Object[ ] { resultMessage }));
		}
	    } catch (TransformersException e) {
		throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG067), e);
	    }

	} catch (Exception e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG060), e);
	}
    }

    /**
     * Method that checks if the input document indicated on the time-stamp renovation request is valid or not.
     * @param se Parameter that represents the time-stamp renovation request.
     * @throws TSAServiceInvokerException If the validation fails.
     */
    private void validatePreviousTimestampStructurally(SOAPEnvelope se) throws TSAServiceInvokerException {
	try {
	    org.apache.xml.security.Init.init();
	    org.apache.axiom.soap.SOAPBody soapBody = se.getBody();

	    // Accedemos al elemento dss:InputDocuments
	    OMElement inputDocuments = UtilsAxis.findElementByTagName(soapBody, TSAServiceInvokerConstants.SOAPElements.INPUT_DOCUMENTS);

	    // Accedemos al sello de tiempo previo
	    OMElement previousTimestamp = UtilsAxis.findElementByTagName(soapBody, IXMLConstants.ELEMENT_RENEW_TIMESTAMP).getFirstElement().getFirstElement().getFirstElement();

	    // Si el sello de tiempo previo es de tipo RFC3161TimeStampToken
	    if (previousTimestamp.getLocalName().equals(IXMLConstants.ELEMENT_RFC3161_TIMESTAMPTOKEN)) {
		// Obtenemos el objeto java que representa el sello de
		// tiempo
		TimeStampToken tst = new TimeStampToken(new CMSSignedData(Base64.decode(previousTimestamp.getText())));
		// Validamos la integridad del sello de tiempo
		UtilsTimestampWS.checkInputDocumentRFC3161TimeStamp(XMLUtils.toDOM(inputDocuments), tst);
	    }
	    // Si el sello de tiempo previo es de tipo XMLTimeStampToken
	    else if (previousTimestamp.getLocalName().equals(IXMLConstants.ELEMENT_SIGNATURE)) {
		// Validamos la integridad del sello de tiempo
		UtilsTimestampWS.checkInputDocumentXMLTimeStamp(XMLUtils.toDOM(inputDocuments), XMLUtils.toDOM(previousTimestamp));
	    }
	} catch (DOMException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	} catch (TSPException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	} catch (IOException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	} catch (CMSException e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG061), e);
	} catch (Exception e) {
	    throw new TSAServiceInvokerException(Language.getResIntegra(ILogConstantKeys.TWSI_LOG060), e);
	}
    }

    /**
     * Method that obtains the validation mode of the time-stamp to send to renew time-stamp service of the TS@.
     * @param serviceName Parameter that represents the name of the TS@ called service.
     * @return the validation mode of the time-stamp to send to renew time-stamp service of the TS@.
     * @throws TSAServiceInvokerException If the method fails.
     */
    private int processValidationRenewTimestampService(String serviceName) throws TSAServiceInvokerException {
	int result = 0;
	// Comprobamos si el servicio solicitado es el de renovación de sello de
	// tiempo
	if (serviceName.equals(GeneralConstants.TSA_RETIMESTAMP_SERVICE)) {
	    // Rescatamos del archivo de propiedades la propiedad que indica el
	    // modo de validación que aplicar sobre el sello de tiempo previo a
	    // ser renovado
	    String renewTimestampValidationModeStr = properties.getProperty(TSAServiceInvokerConstants.WS_RENEW_TIMESTAMP_WS_VALIDATION_LEVEL_PROPERTY);
	    checkSvcInvokerParams(TSAServiceInvokerConstants.WS_RENEW_TIMESTAMP_WS_VALIDATION_LEVEL_PROPERTY, renewTimestampValidationModeStr);
	    // Comprobamos que dicha propiedad tiene un valor válido
	    Integer renewTimestampValidationMode = null;
	    try {
		renewTimestampValidationMode = Integer.valueOf(renewTimestampValidationModeStr);
	    } catch (NumberFormatException e) {
		throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG054, new Object[ ] { renewTimestampValidationModeStr }), e);
	    }
	    if (renewTimestampValidationMode == VALIDATION_MODE_RENEW_TIMESTAMP_NONE) {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TWSI_LOG055));
		result = 0;
	    } else if (renewTimestampValidationMode == VALIDATION_MODE_RENEW_TIMESTAMP_SIMPLE) {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TWSI_LOG056));
		result = 1;
	    } else if (renewTimestampValidationMode == VALIDATION_MODE_RENEW_TIMESTAMP_COMPLETE) {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.TWSI_LOG057));
		result = 2;
	    } else {
		throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG054, new Object[ ] { renewTimestampValidationModeStr }));
	    }
	}
	return result;
    }

    /**
     * Method that verifies if a value is not empty and not null.
     * @param parameterName Parameter that represents the name of the element to check.
     * @param parameterValue Parameter that represents the value to check.
     * @throws TSAServiceInvokerException If the value is empty or null.
     */
    private void checkSvcInvokerParams(String parameterName, String parameterValue) throws TSAServiceInvokerException {
	if (!GenericUtilsCommons.assertStringValue(parameterValue)) {
	    throw new TSAServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG008, new Object[ ] { parameterName, properties.getProperty(TSAServiceInvokerConstants.APPLICATION_NAME) }));
	}
    }

    /**
     * Method that obtains the properties related to the trusted keystore from {@link #properties} and configure it.
     */
    private void configureSSLTrustStore() {
	// Rescatamos la ruta al almacén de confianza
	String trustsorePath = generalProperties.getProperty(TSAServiceInvokerConstants.TRUSTEDSTORE_PATH);
	if (trustsorePath == null && System.getProperty("javax.net.ssl.trustStore") == null) {
	    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.TWSI_LOG009));
	} else if (trustsorePath != null) {
	    // Actualizamos la ruta al almacén de confianza
	    System.setProperty("javax.net.ssl.trustStore", trustsorePath);
	}
	LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.TWSI_LOG010, new Object[ ] { trustsorePath }));

	// Rescatamos la clave del almacén de confianza
	String truststorePassword = generalProperties.getProperty(TSAServiceInvokerConstants.TRUSTEDSTORE_PASSWORD);
	if (truststorePassword == null && System.getProperty("javax.net.ssl.trustStorePassword") == null) {
	    LOGGER.warn(Language.getResIntegra(ILogConstantKeys.TWSI_LOG011));
	} else if (truststorePassword != null) {
	    System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);
	}
    }

}
