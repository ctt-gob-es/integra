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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerFactory.java.</p>
 * <b>Description:</b><p>Class that represents a factory to invoke web services published by eVisor.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 26/12/2014.
 */
package es.gob.afirma.wsServiceInvoker;

import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;
import es.gob.afirma.wsServiceInvoker.ws.EvisorWebServiceInvoker;

/**
 * <p>Class that represents a factory to invoke web services published by eVisor.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 26/12/2014.
 */
public final class EvisorServiceInvokerFactory {

    /**
     * Constructor method for the class Afirma5ServiceInvokerFactory.java.
     */
    private EvisorServiceInvokerFactory() {
    }

    /**
     * Attribute that represents the class logger.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(EvisorServiceInvokerFactory.class);

    /**
     * Method that obtains the class used to invoke a eVisor web service.
     * @param service Parameter that represents the name of the web service.
     * @return the class used to invoke a eVisor web service.
     * @throws WSServiceInvokerException if the method fails.
     */
    public static AbstractWSServiceInvoker getEvisorServiceInvoker(String service) throws WSServiceInvokerException {
	AbstractWSServiceInvoker res = new EvisorWebServiceInvoker(service);
	String className = "";
	if (res != null) {
	    className = res.getClass().getName();
	}
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASF_LOG001, new Object[ ] { service, className }));
	return res;
    }

    /**
     * Method that obtains the class used to invoke a eVisor web service.
     * @param service Parameter that represents the name of the web service.
     * @param serviceInvocationProperties Set of properties defined to invoke the web service.
     * @return the class used to invoke a eVisor web service.
     * @throws WSServiceInvokerException if the method fails.
     */
    public static AbstractWSServiceInvoker getEvisorServiceInvoker(String service, Properties serviceInvocationProperties) throws WSServiceInvokerException {
	AbstractWSServiceInvoker res = new EvisorWebServiceInvoker(service, serviceInvocationProperties);
	String className = "";
	if (res != null) {
	    className = res.getClass().getName();
	}
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASF_LOG001, new Object[ ] { service, className }));
	return res;
    }

    /**
     * Method that obtains the class used to invoke a eVisor web service.
     * @param applicationName Parameter that represents the name of the client application.
     * @param service Parameter that represents the name of the web service.
     * @param idClient Parameter that represents the client application identifier.
     * @return the class used to invoke a eVisor web service.
     * @throws WSServiceInvokerException if the method fails.
     */
    public static AbstractWSServiceInvoker getEvisorServiceInvoker(String applicationName, String service, String idClient) throws WSServiceInvokerException {
	AbstractWSServiceInvoker res = new EvisorWebServiceInvoker(applicationName, service, idClient);
	String className = "";
	if (res != null) {
	    className = res.getClass().getName();
	}
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASF_LOG001, new Object[ ] { service, className }));
	return res;
    }

}
