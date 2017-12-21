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
 * <b>File:</b><p>es.gob.afirma.WSServiceInvoker.ws.EvisorWebServiceInvoker.java.</p>
 * <b>Description:</b><p>Class that represents the facade used to invoke the web services of @Firma and eVisor.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 26/12/2014.
 */
package es.gob.afirma.wsServiceInvoker.ws;

import java.util.Properties;

import es.gob.afirma.wsServiceInvoker.AbstractWSServiceInvoker;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that represents the facade used to invoke the web services of @Firma and eVisor.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 26/12/2014.
 */
public class EvisorWebServiceInvoker extends AbstractWSServiceInvoker {

    /**
     * Constructor method for the class EvisorWebServiceInvoker.java.
     * @param service Parameter that represents the name of the web service to invoke.
     */
    public EvisorWebServiceInvoker(String service) {
	super(service);
    }

    /**
     * Constructor method for the class EvisorWebServiceInvoker.java.
     * @param service Parameter that represents the name of the web service to invoke.
     * @param serviceInvocationProperties Parameter that represents the set of properties related to the web service to invoke.
     */
    public EvisorWebServiceInvoker(String service, Properties serviceInvocationProperties) {
	super(service, serviceInvocationProperties);
    }

    /**
     * Constructor method for the class EvisorWebServiceInvoker.java.
     * @param applicationName Parameter that represents the name of application which invokes the web service.
     * @param service Parameter that represents the name of the web service to invoke.
     * @param idClient Parameter that represents the client application identifier.
     */
    public EvisorWebServiceInvoker(String applicationName, String service, String idClient) {
	super(applicationName, service, idClient, true);
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.wsServiceInvoker.AbstractWSServiceInvoker#invokeService(java.lang.String, java.lang.Object[])
     */
    public final String invokeService(String methodName, Object[ ] parameters) throws WSServiceInvokerException {
	WebServiceInvoker wsInvoker = new WebServiceInvoker(this.getServiceInvocationProperties());

	return (String) wsInvoker.performCall(methodName, parameters);

    }

}
