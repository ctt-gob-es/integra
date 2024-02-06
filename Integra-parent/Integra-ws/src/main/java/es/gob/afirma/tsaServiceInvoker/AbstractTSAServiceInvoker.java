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
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.AbstractTSAServiceInvoker.java.</p>
 * <b>Description:</b><p>Class that defines the common functionality for all the classes which allow to invoke the web services of TS@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>09/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 09/01/2014.
 */
package es.gob.afirma.tsaServiceInvoker;

import java.util.Properties;

import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.properties.TSAServiceInvokerProperties;

/**
 * <p>Class that defines the common functionality for all the classes which allow to invoke the web services of TS@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 09/01/2014.
 */
public abstract class AbstractTSAServiceInvoker {

    /**
     * Attribute that represents the set of configuration parameters of the service to invoke.
     */
    private Properties serviceInvocationProperties;

    /**
     * Attribute that represents the general set of configuration parameters of the service to invoke.
     */
    private Properties generalProperties;

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
     * Constructor method for the class AbstractTSAServiceInvoker.java.
     * @param serviceParam Parameter that represents the name of the service to invoke.
     */
    public AbstractTSAServiceInvoker(String serviceParam) {
	applicationName = null;
	service = serviceParam;
	serviceInvocationProperties = new Properties();
	serviceInvocationProperties.setProperty(TSAServiceInvokerConstants.TSA_SERVICE, service);
    }

    /**
     * Constructor method for the class AbstractTSAServiceInvoker.java.
     * @param serviceInvocationPropertiesParam Parameter that represents the set of configuration parameters of the service to invoke.
     * @param serviceParam Parameter that represents the name of the service to invoke.
     */
    public AbstractTSAServiceInvoker(Properties serviceInvocationPropertiesParam, String serviceParam) {
	applicationName = null;
	service = serviceParam;
	serviceInvocationProperties = new Properties(serviceInvocationPropertiesParam);
	serviceInvocationProperties.setProperty(TSAServiceInvokerConstants.TSA_SERVICE, service);
    }

    /**
     * Constructor method for the class AbstractTSAServiceInvoker.java.
     * @param serviceParam Parameter that represents the name of the service to invoke.
     * @param applicationNameParam Parameter that represents the name of the application which invokes the service.
     * @param idClient Parameter that represents the client application identifier.
     */
    public AbstractTSAServiceInvoker(String serviceParam, String applicationNameParam, String idClient) {
	applicationName = applicationNameParam;
	service = serviceParam;
	initializeProperties(idClient);
    }

    /**
     * Constructor method for the class AbstractTSAServiceInvoker.java.
     * @param serviceParam Parameter that represents the name of the service to invoke.
     * @param applicationNameParam Parameter that represents the name of the application which invokes the service.
     */
    public AbstractTSAServiceInvoker(String serviceParam, String applicationNameParam) {
	applicationName = applicationNameParam;
	service = serviceParam;
	initializeProperties(null);
    }

    /**
     * Method that initializes the general parameters of the API to invoke the TS@ web services from the associated configuration file.
     * @param idClient Parameter that represents the client application identifier.
     */
    private void initializeProperties(String idClient) {
	this.generalProperties = new IntegraProperties().getIntegraProperties(idClient);
	this.serviceInvocationProperties = new TSAServiceInvokerProperties().getTsaServiceInvokerProperties(idClient, this.applicationName);
	this.serviceInvocationProperties.setProperty(TSAServiceInvokerConstants.APPLICATION_NAME, this.applicationName);
	this.serviceInvocationProperties.setProperty(TSAServiceInvokerConstants.TSA_SERVICE, service);
    }

    /**
     * Gets the value of the attribute {@link #serviceInvocationProperties}.
     * @return the value of the attribute {@link #serviceInvocationProperties}.
     */
    public final Properties getServiceInvocationProperties() {
	return serviceInvocationProperties;
    }

    /**
     * Gets the value of the attribute {@link #generalProperties}.
     * @return the value of the attribute {@link #generalProperties}.
     */
    public final Properties getGeneralProperties() {
	return generalProperties;
    }

    /**
     * Method that invokes a web service published by TS@.
     * @param parameters Parameter that represents the list of inputs.
     * @param idClient client identifier of ws invocation.
     * @return the result of the invocation on XML format.
     * @throws TSAServiceInvokerException if the method fails.
     */
    public abstract String invokeService(Object[ ] parameters, String idClient) throws TSAServiceInvokerException;

    /**
     * Gets the value of the attribute {@link #service}.
     * @return the value of the attribute {@link #service}.
     */
    public final String getService() {
	return service;
    }

}
