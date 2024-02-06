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
// https://eupl.eu/1.1/es/
/**
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerFactory.java.</p>
 * <b>Description:</b><p>Class that represents a factory to invoke web services published by @Firma and eVisor.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.wsServiceInvoker;

import java.util.Properties;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.wsServiceInvoker.ws.Afirma5WebServiceInvoker;

/**
 * <p>Class that represents a factory to invoke web services published by @Firma and eVisor.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public final class Afirma5ServiceInvokerFactory {

    /**
     * Constructor method for the class Afirma5ServiceInvokerFactory.java.
     */
    private Afirma5ServiceInvokerFactory() {
    }

    /**
     * Attribute that represents the class logger.
     */
    private static final Logger LOGGER = Logger.getLogger(Afirma5ServiceInvokerFactory.class);

    /**
     * Method that obtains the class used to invoke a @Firma or eVisor web service.
     * @param service Parameter that represents the name of the web service.
     * @return the class used to invoke a @Firma or eVisor web service.
     * @throws WSServiceInvokerException if the method fails.
     */
    public static AbstractWSServiceInvoker getAfirma5ServiceInvoker(String service) throws WSServiceInvokerException {
	AbstractWSServiceInvoker res = new Afirma5WebServiceInvoker(service);
	String className = "";
	if (res != null) {
	    className = res.getClass().getName();
	}
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASF_LOG001, new Object[ ] { service, className }));
	return res;
    }

    /**
     * Method that obtains the class used to invoke a @Firma or eVisor web service.
     * @param service Parameter that represents the name of the web service.
     * @param serviceInvocationProperties Set of properties defined to invoke the web service.
     * @return the class used to invoke a @Firma or eVisor web service.
     * @throws WSServiceInvokerException if the method fails.
     */
    public static AbstractWSServiceInvoker getAfirma5ServiceInvoker(String service, Properties serviceInvocationProperties) throws WSServiceInvokerException {
	AbstractWSServiceInvoker res = new Afirma5WebServiceInvoker(service, serviceInvocationProperties);
	String className = "";
	if (res != null) {
	    className = res.getClass().getName();
	}
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASF_LOG001, new Object[ ] { service, className }));
	return res;
    }

    /**
     * Method that obtains the class used to invoke a @Firma or eVisor web service.
     * @param applicationName Parameter that represents the name of the client application.
     * @param service Parameter that represents the name of the web service.
     * @param idClient Parameter that represents the client application identifier.
     * @return the class used to invoke a @Firma or eVisor web service.
     * @throws WSServiceInvokerException if the method fails.
     */
    public static AbstractWSServiceInvoker getAfirma5ServiceInvoker(String applicationName, String service, String idClient) throws WSServiceInvokerException {
	AbstractWSServiceInvoker res = new Afirma5WebServiceInvoker(applicationName, service, idClient);
	String className = "";
	if (res != null) {
	    className = res.getClass().getName();
	}
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASF_LOG001, new Object[ ] { service, className }));
	return res;
    }

}
