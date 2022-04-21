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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerProperties.java.</p>
 * <b>Description:</b><p>Class that allows to access to the properties defined inside of the configuration file for invoking the web services of
 * @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.tsl.properties;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Date;
import java.util.Properties;

import es.gob.afirma.tsl.i18n.ILogConstantKeys;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.logger.Logger;
import es.gob.afirma.tsl.utils.GenericUtilsCommons;
import es.gob.afirma.tsl.utils.UtilsResourcesCommons;
import es.gob.afirma.tsl.wsServiceInvoker.WSServiceInvokerConstants;



/**
 * <p>Class that allows to access to the properties defined inside of the configuration file for invoking the web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public final class Afirma5ServiceInvokerProperties {

    /**
     * Constructor method for the class Afirma5ServiceInvokerProperties.java.
     */
    public Afirma5ServiceInvokerProperties() {
    }

    /**
     * Attribute that represents the class logger.
     */
    private Logger LOGGER = Logger.getLogger(Afirma5ServiceInvokerProperties.class);

    /**
     * Attribute that represents the time that the file {@link #afirma5ServiceInvokerProperties} was last modified.
     */
    private long propsFileLastUpdate = -1;

    /**
     * Attribute that represents the time that the truststore was last modified.
     */
    private long truststoreLastUpdate = -1;

    /**
     * Attribute that represents the set of properties defined inside of the configuration file for invoking the web services of @Firma.
     */
    private Properties afirma5ServiceInvokerProperties = new Properties();

    /**
     * Constant attribute that identifies the class name of the truststore.
     */
    private final String TRUSTSTORE_CLASSNAME = "javax.net.ssl.trustStore";

    /**
     * Gets the value of the attribute {@link #afirma5ServiceInvokerProperties}.
     * @param idClient Parameter that represents the client application identifier.
     * @param applicationName Parameter that represents the customer application name.
     * @return the value of the attribute {@link #afirma5ServiceInvokerProperties}.
     */
    public Properties getAfirma5ServiceProperties(String idClient, String applicationName) {

	init(idClient, applicationName);
	return afirma5ServiceInvokerProperties;
    }

    /**
     * Sets the value of the attribute WS_CERTIFICATES_CACHE_USE_PROP of {@link #afirma5ServiceInvokerProperties}.
     * @param newValue New value for chache enabled propertie.
     */
    public void setCacheEnabled(String newValue) {
	afirma5ServiceInvokerProperties.setProperty(WSServiceInvokerConstants.WS_CERTIFICATES_CACHE_USE_PROP, newValue);
    }

    /**
     * Method that initializes {@link #afirma5ServiceInvokerProperties} with all the related properties.
     * @param idClientParam Parameter that represents the client application identifier.
     * @param applicationName Parameter that represents the customer application name.
     */
    private void init(String idClientParam, String applicationName) {
	File file;
	InputStream in = null;

	try {
	    String idClient = "";
	    if (idClientParam != null) {
		idClient = idClientParam;
	    }
	    file = UtilsResourcesCommons.getPropertiesResource(UtilsResourcesCommons.getPropertiesName("afirma" + idClient + applicationName));

	    if (propsFileLastUpdate != file.lastModified()) {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.ASIP_LOG001));
		afirma5ServiceInvokerProperties = new Properties();
		in = new FileInputStream(file);
		afirma5ServiceInvokerProperties.load(in);
		propsFileLastUpdate = file.lastModified();

		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASIP_LOG002, new Object[ ] { afirma5ServiceInvokerProperties }));
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASIP_LOG003, new Object[ ] { new Date(propsFileLastUpdate) }));

		// Establecemos el nuevo valor de la propiedad que indica el
		// almacen de confianza usado
		// en conexiones seguras, en el caso de que existan.
		String propertyValue = afirma5ServiceInvokerProperties.getProperty(WSServiceInvokerConstants.SECURE_MODE_PROPERTY);
		if (propertyValue != null && propertyValue.trim().equalsIgnoreCase("true")) {

		    Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);
		    setTruststore(integraProperties.getProperty(WSServiceInvokerConstants.COM_PROPERTIE_HEADER + "." + WSServiceInvokerConstants.WS_TRUSTED_STORE_PROP), integraProperties.getProperty(WSServiceInvokerConstants.COM_PROPERTIE_HEADER + "." + WSServiceInvokerConstants.WS_TRUSTED_STOREPASS_PROP));

		}
	    }
	} catch (Exception e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.ASIP_LOG004, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }), e);
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(in);
	}
    }

    /**
     * Method that updates the system properties used to define the truststore for the secure connections.
     * @param truststorePath Parameter that represents the path to the truststore.
     * @param truststorePass Parameter that represents the password of the truststore.
     */
    private void setTruststore(String truststorePath, String truststorePass) {
	boolean isChanged;
	File truststoreFile;

	isChanged = false;
	truststoreFile = new File(truststorePath);

	if (truststorePath != null && !truststorePath.trim().equals("") && System.getProperty(TRUSTSTORE_CLASSNAME) != null && !System.getProperty(TRUSTSTORE_CLASSNAME).equals(truststorePath)) {
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASIP_LOG006, new Object[ ] { System.getProperty(TRUSTSTORE_CLASSNAME), truststorePath }));
	    isChanged = true;
	} else if (!GenericUtilsCommons.checkNullValues(truststorePass, System.getProperty("javax.net.ssl.trustStorePassword")) && !truststorePass.trim().equals("") && !System.getProperty("javax.net.ssl.trustStorePassword").equals(truststorePass)) {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.ASIP_LOG007));
	    isChanged = true;
	} else if (truststoreLastUpdate != truststoreFile.lastModified()) {
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.ASIP_LOG008));
	    isChanged = true;
	}

	if (isChanged) {
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.ASIP_LOG009, new Object[ ] { afirma5ServiceInvokerProperties.getProperty(WSServiceInvokerConstants.COM_PROPERTIE_HEADER + "." + WSServiceInvokerConstants.WS_TRUSTED_STORE_PROP) }));
	    System.setProperty(TRUSTSTORE_CLASSNAME, truststorePath);
	    System.setProperty("javax.net.ssl.trustStorePassword", truststorePass);
	    truststoreLastUpdate = truststoreFile.lastModified();
	}
    }
}
