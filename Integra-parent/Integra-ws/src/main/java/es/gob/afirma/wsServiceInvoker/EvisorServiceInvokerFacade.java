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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.EvisorServiceInvokerFacade.java.</p>
 * <b>Description:</b><p>Class that represents the facade for the invocation of the web services of eVisor.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>16/03/2011.</p>
 * @author Gobierno de España.
 * @version 1.1, 17/03/2020.
 */
package es.gob.afirma.wsServiceInvoker;

import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that represents the facade for the invocation of the web services of eVisor.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 17/03/2020.
 */
public final class EvisorServiceInvokerFacade {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(EvisorServiceInvokerFacade.class);

    /**
     * Attribute that represents the instance of the class.
     */
    private static EvisorServiceInvokerFacade instance;

    /**
     * Gets a class instance.
     * @return  a class instance.
     */
    public static EvisorServiceInvokerFacade getInstance() {
	if (instance == null) {
	    instance = new EvisorServiceInvokerFacade();
	}
	return instance;
    }

    /**
     * Constructor method for the class EvisorServiceInvokerFacade.java.
     */
    private EvisorServiceInvokerFacade() {
    }

    /**
     * Invokes a eVisor service.
     * @param xmlInput input parameter of published eVisor services.
     * @param service service name to invoke.
     * @param method method name of invoked service.
     * @param applicationName customer application name.
     * @param idClient client identifier of ws invocation.
     * @return String with xml format with invocation service result.
     * @throws WSServiceInvokerException if an error happens (connection, not avalaible service, not valid input parameters)
     */
    public String invokeService(String xmlInput, String service, String method, String applicationName, String idClient) throws WSServiceInvokerException {

	if (!GenericUtilsCommons.assertStringValue(xmlInput) || !GenericUtilsCommons.assertStringValue(service) || !GenericUtilsCommons.assertStringValue(method) || !GenericUtilsCommons.assertStringValue(applicationName)) {
	    throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.ASIF_LOG001));
	}
	return invoke(xmlInput, service, method, applicationName, null, idClient);
    }

    /**
     * Invokes a eVisor service.
     * @param xmlInput input parameter of published eVisor services.
     * @param service service name to invoke.
     * @param method method name of invoked service.
     * @param applicationName customer application name.
     * @return String with xml format with invocation service result.
     * @throws WSServiceInvokerException if an error happens (connection, not avalaible service, not valid input parameters)
     */
    public String invokeService(String xmlInput, String service, String method, String applicationName) throws WSServiceInvokerException {

	return invokeService(xmlInput, service, method, applicationName, null);
    }

    /**
     * Invokes a eVisor service, it sets a collections of properties aren't in the configuration file of component.
     * @param xmlInput input parameter of published eVisor services.
     * @param service service name to invoke.
     * @param method method name of invoked service.
     * @param serviceProperties collection of configuration settings to invoke service.
     * @param idClient client identifier of ws invocation.
     * @return String with xml format with invocation service result.
     * @throws WSServiceInvokerException if an error happens (connection, not avalaible service, not valid input parameters)
     */
    public String invokeService(String xmlInput, String service, String method, Properties serviceProperties, String idClient) throws WSServiceInvokerException {

	if (!GenericUtilsCommons.assertStringValue(xmlInput) || !GenericUtilsCommons.assertStringValue(service) || !GenericUtilsCommons.assertStringValue(method) || serviceProperties.isEmpty()) {
	    throw new WSServiceInvokerException(Language.getResIntegra(ILogConstantKeys.ASIF_LOG001));
	}

	return invoke(xmlInput, service, method, null, serviceProperties, idClient);
    }

    /**
     * Invokes a eVisor service, it sets a collections of properties aren't in the configuration file of component.
     * @param xmlInput input parameter of published eVisor services.
     * @param service service name to invoke.
     * @param method method name of invoked service.
     * @param serviceProperties collection of configuration settings to invoke service.
     * @return String with xml format with invocation service result.
     * @throws WSServiceInvokerException if an error happens (connection, not avalaible service, not valid input parameters)
     */
    public String invokeService(String xmlInput, String service, String method, Properties serviceProperties) throws WSServiceInvokerException {
	return invokeService(xmlInput, service, method, serviceProperties, null);
    }

    /**
     * Method that invokes a eVisor service.
     * @param xmlInput Parameter that represents the input XML.
     * @param service Parameter that represents the name of the service to invoke.
     * @param method Parameter that represents the name of the method to invoke.
     * @param applicationName Parameter that represents the customer application name.
     * @param serviceProperties Parameter that represents the collection of configuration settings to invoke the service.
     * @param idClient Parameter that represents the client application identifier.
     * @return a XML with the invocation service result.
     * @throws WSServiceInvokerException If the method fails.
     */
    private String invoke(String xmlInput, String service, String method, String applicationName, Properties serviceProperties, String idClient) throws WSServiceInvokerException {
	AbstractWSServiceInvoker eVisorInvoker;
	Object[ ] serviceInParam;
	String res = null;
	try {
	    serviceInParam = new Object[1];
	    serviceInParam[0] = xmlInput.replace("\n", "").replace("\r", "");

	    eVisorInvoker = getEvisorInvokerInstance(service, applicationName, serviceProperties, idClient);
	    res = eVisorInvoker.invokeService(method, serviceInParam);

	} catch (Exception e) {
	    LOGGER.error(e);
	    throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.ASIF_LOG002, new Object[ ] { service }), e);
	}
	return res;
    }

    /**
     * Method that obtains an instance of {@link AbstractWSServiceInvoker}.
     * @param service Parameter that represents the name of the service to invoke.
     * @param applicationName Parameter that represents the customer application name.
     * @param serviceProperties Parameter that represents the collection of configuration settings to invoke the service.
     * @return an instance of {@link AbstractWSServiceInvoker}.
     * @param idClient Parameter that represents the client application identifier.
     * @throws WSServiceInvokerException If the method fails.
     */
    private AbstractWSServiceInvoker getEvisorInvokerInstance(String service, String applicationName, Properties serviceProperties, String idClient) throws WSServiceInvokerException {
	if (serviceProperties == null) {
	    return EvisorServiceInvokerFactory.getEvisorServiceInvoker(applicationName, service, idClient);
	} else {
	    return EvisorServiceInvokerFactory.getEvisorServiceInvoker(service, serviceProperties);
	}
    }

}
