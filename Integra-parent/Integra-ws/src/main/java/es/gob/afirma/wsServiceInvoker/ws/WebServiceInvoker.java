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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.ws.WebServiceInvoker.java.</p>
 * <b>Description:</b><p>Class that manages the invoke of @Firma and eVisor web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 26/12/2014.
 */
package es.gob.afirma.wsServiceInvoker.ws;

import java.rmi.RemoteException;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.rpc.ServiceException;

import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerConstants;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that manages the invoke of @Firma and eVisor web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 26/12/2014.
 */
public class WebServiceInvoker {

    /**
     * Constant attribute that identifies not secure communication.
     */
    private static final String NO_SECURE_PROTOCOL = "http";

    /**
     * Constant attribute that identifies secure communication.
     */
    private static final String SECURE_PROTOCOL = "https";

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(WebServiceInvoker.class);

    /**
     * Attribute that represents the properties defined on the configuration file.
     */
    private Properties properties;

    /**
     * Constructor method for the class WebServiceInvoker.java.
     * @param prop Parameter that represents the properties defined on the configuration file.
     */
    public WebServiceInvoker(Properties prop) {
	this.properties = prop;
    }

    /**
     * Method that performs the invocation to a method form @Firma and eVisor web services.
     * @param methodName Parameter that represents the name of the method to invoke.
     * @param params List of parameters related to the method to invoke.
     * @return the response of the web service.
     * @throws WSServiceInvokerException If the method fails.
     */
    final Object performCall(String methodName, Object[ ] params) throws WSServiceInvokerException {
	Call call;
	ClientHandler requestHandler;
	Service service;
	String endPointURL, securityOption, secureMode, timeout, afirmaService, protocol, endPoint, servicePath;
	Object res;

	res = null;
	try {

	    afirmaService = this.properties.getProperty(WSServiceInvokerConstants.AFIRMA_SERVICE);

	    secureMode = this.properties.getProperty(WSServiceInvokerConstants.SECURE_MODE_PROPERTY);

	    // Propiedades de conexión con el repositorio de servicios Web
	    protocol = NO_SECURE_PROTOCOL;
	    if (secureMode != null && secureMode.equals("true")) {
		protocol = SECURE_PROTOCOL;
	    }
	    endPoint = this.properties.getProperty(WSServiceInvokerConstants.WS_ENDPOINT_PROPERTY);
	    checkSvcInvokerParams(WSServiceInvokerConstants.WS_ENDPOINT_PROPERTY, endPoint);
	    servicePath = this.properties.getProperty(WSServiceInvokerConstants.WS_SRV_PATH_PROPERTY);
	    checkSvcInvokerParams(WSServiceInvokerConstants.WS_SRV_PATH_PROPERTY, servicePath);

	    // "https://localhost:8080/afirmaws/services/ValidarCertificado";
	    endPointURL = protocol + "://" + endPoint + "/" + servicePath + "/" + afirmaService;

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG001, new Object[ ] { afirmaService }));
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG002, new Object[ ] { endPointURL }));

	    // Propiedades propias del servicio web a invocar

	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG003));
	    // Creacion del manejador que securizará la petición SOAP
	    // validacionWS.ValidarCertificado.ws.authorizationMethod
	    securityOption = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP);
	    checkSvcInvokerParams(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP, securityOption);
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG004, new Object[ ] { securityOption }));
	    requestHandler = newRequestHandler(securityOption);

	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG005));
	    // Creación del servicio y la llamada al método
	    service = new Service();
	    call = (Call) service.createCall();
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG006));

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG007, new Object[ ] { methodName }));
	    // Configuración de la llamada
	    call.setTargetEndpointAddress(endPointURL);

	    call.setOperationName(new QName("http://soapinterop.org/", methodName));
	    timeout = this.properties.getProperty(WSServiceInvokerConstants.WS_CALL_TIMEOUT_PROP);
	    checkSvcInvokerParams(WSServiceInvokerConstants.WS_CALL_TIMEOUT_PROP, timeout);
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG008, new Object[ ] { timeout }));
	    call.setTimeout(Integer.valueOf(timeout));

	    // incluimos los manejadores de entrada (cabecera de seguridad en
	    // las peticiones)
	    // y los manejadores de salida (validación de las respuestas
	    // firmadas de los servicios @firma)
	    call.setClientHandlers(requestHandler, newResponseHandler());

	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG009));
	    // Llamada al metodo del servicio web

	    if (params == null) {
		res = call.invoke(new Object[0]);
	    } else {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG010, new Object[ ] { params[0] }));
		res = call.invoke(params);
	    }
	} catch (RemoteException e) {
	    throw new WSServiceInvokerException(e);
	} catch (ServiceException e) {
	    throw new WSServiceInvokerException(e);
	}

	Object result = "Null.";
	if (res != null) {
	    result = res;
	}
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG011, new Object[ ] { result }));

	return res;
    }

    /**
     * Method that verifies if a value is not empty and not null.
     * @param parameterName Parameter that represents the name of the element to check.
     * @param parameterValue Parameter that represents the value to check.
     * @throws WSServiceInvokerException If the value is empty or null.
     */
    private void checkSvcInvokerParams(String parameterName, String parameterValue) throws WSServiceInvokerException {
	if (!GenericUtilsCommons.assertStringValue(parameterValue)) {
	    throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG012, new Object[ ] { parameterName, properties.getProperty(WSServiceInvokerConstants.APPLICATION_NAME) }));
	}
    }

    /**
     * Method that creates a new instance of {@link ClientHandler}.
     * @param securityOption Parameter that represents the security options.
     * @return the created instance of {@link ClientHandler}.
     * @throws WSServiceInvokerException If the method fails.
     */
    private ClientHandler newRequestHandler(String securityOption) throws WSServiceInvokerException {
	String autUser, autPassword, autPassType, keystorePath, keystorePass, keystoreType;
	autUser = "";
	autPassword = "";
	autPassType = "";
	keystorePath = "";
	keystorePass = "";
	keystoreType = "";
	String securityOpt = securityOption;
	if (securityOpt != null) {
	    if (!securityOpt.equals(ClientHandler.NONEOPTION)) {
		autUser = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZ_METHOD_USER_PROP);
		autPassword = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PASS_PROP);
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG013, new Object[ ] { autUser }));
		if (securityOpt.equals(ClientHandler.USERNAMEOPTION)) {
		    autPassType = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PASS_TYPE_PROP);
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG014, new Object[ ] { autPassType }));
		} else if (securityOpt.equals(ClientHandler.CERTIFICATEOPTION)) {
		    keystorePath = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_USERKEYSTORE_PROP);
		    keystorePass = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_USERKEYSTORE_PASS_PROP);
		    keystoreType = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_USERKEYSTORE_TYPE_PROP);
		    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG015, new Object[ ] { keystorePath, keystoreType }));
		}
	    }
	} else {
	    securityOpt = ClientHandler.NONEOPTION;
	}
	ClientHandler sender = new ClientHandler(securityOpt);
	sender.setUserAlias(autUser);
	sender.setPassword(autPassword);
	// Este parametro solo tiene sentido si la autorizacion se realiza
	// mediante el tag de seguridad UserNameToken
	sender.setPasswordType(autPassType);
	// Propiedades para binarySecurityToken
	sender.setUserKeystore(keystorePath);
	sender.setUserKeystorePass(keystorePass);
	sender.setUserKeystoreType(keystoreType);
	return sender;
    }

    /**
     * Method that creates a new instance of {@link ResponseHandler}.
     * @return the created instance of {@link ResponseHandler}.
     */
    private ResponseHandler newResponseHandler() {
	if (Boolean.valueOf(this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.RESPONSE_VALIDATE_PROPERTY))) {
	    String keystorePath = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_USERKEYSTORE_PROP);
	    String keystorePass = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_USERKEYSTORE_PASS_PROP);
	    String keystoreType = this.properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_USERKEYSTORE_TYPE_PROP);
	    String autUser = this.properties.getProperty(WSServiceInvokerConstants.PREFIX_RESPONSE_PROPERTY + "." + WSServiceInvokerConstants.RESPONSE_ALIAS_CERT_PROPERTY);
	    String autPassword = properties.getProperty(WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PROP + "." + WSServiceInvokerConstants.WS_AUTHORIZATION_METHOD_PASS_PROP);
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.WSI_LOG016, new Object[ ] { keystorePath, keystoreType, autUser }));
	    return new ResponseHandler(keystorePath, keystorePass, keystoreType, autUser, autPassword);
	} else {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.WSI_LOG017));
	    return null;
	}
    }

    /**
     * Gets the value of the attribute {@link #properties}.
     * @return the value of the attribute {@link #properties}.
     */
    public final Properties getWSCallerProperties() {
	return this.properties;
    }

    /**
     * Sets the value of the attribute {@link #properties}.
     * @param wsProperties The value for the attribute {@link #properties}.
     */
    public final void setWSCallerProperties(Properties wsProperties) {
	this.properties = wsProperties == null ? new Properties() : wsProperties;
    }

}
