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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.AbstractAfirma5ServiceInvoker.java.</p>
 * <b>Description:</b><p>Class that defines the common functionality for all the classes which allow to invoke the web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/12/2014.
 */
package es.gob.afirma.wsServiceInvoker;

import java.util.Properties;

import es.gob.afirma.properties.Afirma5ServiceInvokerProperties;
import es.gob.afirma.properties.EvisorServiceInvokerProperties;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerConstants;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 * <p>Class that defines the common functionality for all the classes which allow to invoke the web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/12/2014.
 */
public abstract class AbstractWSServiceInvoker {

	/**
	 * Attribute that represents the set of configuration parameters of the service to invoke.
	 */
	private Properties serviceInvocationProperties;

	/**
	 * Attribute that represents the name of the service to invoke.
	 */
	private String service;

	    /**
     * Attribute that represents the name of the application which invokes the service. This name is used to access to the configuration properties when
     * the properties are defined into a properties file. In another case, this value must be <code>null</code>.
     */
    private String applicationName;

	/**
	 * Constructor method for the class AbstractAfirma5ServiceInvoker.java.
	 * @param svc Parameter that represents the name of the service to invoke.
	 */
	public AbstractWSServiceInvoker(String svc) {
		this.applicationName = null;
		this.service = svc;
		this.serviceInvocationProperties = new Properties();
		this.serviceInvocationProperties.setProperty(WSServiceInvokerConstants.AFIRMA_SERVICE, this.service);
	}

	/**
	 * Constructor method for the class AbstractAfirma5ServiceInvoker.java.
	 * @param svc Parameter that represents the name of the service to invoke.
	 * @param svcInvProperties Parameter that represents the set of configuration parameters of the service to invoke.
	 */
	public AbstractWSServiceInvoker(String svc, Properties svcInvProperties) {
		this.applicationName = null;
		this.service = svc;
		this.serviceInvocationProperties = new Properties(svcInvProperties);
		this.serviceInvocationProperties.setProperty(WSServiceInvokerConstants.AFIRMA_SERVICE, this.service);
	}

	/**
	 * Constructor method for the class AbstractAfirma5ServiceInvoker.java.
	 * @param appName Parameter that represents the name of the application which invokes the service.
	 * @param svc Parameter that represents the name of the service to invoke.
	 * @param idClient Parameter that represents the client application identifier.
	 * @param isEvisor Parameter that represents if is a eVisor invocation.
	 */
	public AbstractWSServiceInvoker(String appName, String svc, String idClient, boolean isEvisor) {
		this.applicationName = appName;
		this.service = svc;
		initializeProperties(idClient, isEvisor);
	}

	/**
	 * Method that initializes the general parameters of the API to invoke the @Firma web services from the associated configuration file.
	 * @param idClient Parameter that represents the client application identifier.
	 * @param isEvisor Parameter that represents if is a eVisor invocation.
	 */
	private void initializeProperties(String idClient, boolean isEvisor) {
		if (isEvisor) {
			this.serviceInvocationProperties = new EvisorServiceInvokerProperties().getEvisorServiceProperties(idClient, this.applicationName);
			this.serviceInvocationProperties.setProperty(WSServiceInvokerConstants.APPLICATION_NAME, this.applicationName);
			this.serviceInvocationProperties.setProperty(WSServiceInvokerConstants.AFIRMA_SERVICE, this.service);
		} else {
			this.serviceInvocationProperties = new Afirma5ServiceInvokerProperties().getAfirma5ServiceProperties(idClient, this.applicationName);
			this.serviceInvocationProperties.setProperty(WSServiceInvokerConstants.APPLICATION_NAME, this.applicationName);
			this.serviceInvocationProperties.setProperty(WSServiceInvokerConstants.AFIRMA_SERVICE, this.service);
		}
	}

	/**
	 * Method that invokes a web service published by @Firma.
	 * @param methodName Parameter that represents the name of the methof to invoke.
	 * @param parameters Parameter that represents the list of inputs.
	 * @return the result of the invocation on XML format.
	 * @throws WSServiceInvokerException If the method fails.
	 */
	public abstract String invokeService(String methodName, Object[ ] parameters) throws WSServiceInvokerException;

	/**
	 * Gets the value of the attribute {@link #service}.
	 * @return the value of the attribute {@link #service}.
	 */
	public final String getService() {
		return this.service;
	}

	/**
	 * Gets the value of the attribute {@link #applicationName}.
	 * @return the value of the attribute {@link #applicationName}.
	 */
	public final String getApplicationName() {
		return this.applicationName;
	}

	/**
	 * Gets the value of the attribute {@link #serviceInvocationProperties}.
	 * @return the value of the attribute {@link #serviceInvocationProperties}.
	 */
	public final Properties getServiceInvocationProperties() {
		return this.serviceInvocationProperties;
	}

	/**
	 * Sets the value of the attribute {@link #serviceInvocationProperties}.
	 * @param srvInvokeProp The value for the attribute {@link #serviceInvocationProperties}.
	 */
	public final void setServiceInvocationProperties(Properties srvInvokeProp) {
		this.serviceInvocationProperties = srvInvokeProp == null ? new Properties() : new Properties(srvInvokeProp);
		this.serviceInvocationProperties.setProperty(WSServiceInvokerConstants.AFIRMA_SERVICE, this.service);
	}
}
