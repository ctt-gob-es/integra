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
 * <b>File:</b><p>es.gob.afirma.hsm.HSMProperties.java.</p>
 * <b>Description:</b><p>Class that allows to access to the properties defined inside of the configuration file for managing HSMs.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/12/2014.
 */
package es.gob.afirma.properties;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.hsm.IHSMConstants;
import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.utils.UtilsResourcesCommons;

/**
 * <p>Class that allows to access to the properties defined inside of the configuration file for managing HSMs.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/12/2014.
 */
public final class HSMProperties {

    /**
     * Constructor method for the class HSMProperties.java.
     */
    private HSMProperties() {
    }

    /**
     * Attribute that represents the class logger.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(HSMProperties.class);

    /**
     * Attribute that represents the set of properties defined inside of the configuration file for managing HSMs.
     */
    private static Properties hsmProperties = new Properties();

    /**
     * Gets the value of the attribute {@link #hsmProperties}.
     * @return the value of the attribute {@link #hsmProperties}.
     */
    public static Properties getHSMProperties() {
	// Accedemos al archivo de propiedades relacionadas con el acceso a HSM
	URL url = HSMProperties.class.getClassLoader().getResource(IHSMConstants.HSM_PROPERTIES);
	URI uri = null;
	if (url == null) {
	    if (System.getProperty("integra.config") != null) {
		uri = new File(System.getProperty("integra.config") + File.separator + IHSMConstants.HSM_PROPERTIES).toURI();
	    } else {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.HSMP_LOG001, new Object[ ] { IHSMConstants.HSM_PROPERTIES }));
	    }
	}
	    
	InputStream in = null;
	try {
	    if (uri == null) {
		uri = new URI(url.toString());
	    }
	    hsmProperties = new Properties();
	   
	    in = new FileInputStream(new File(uri));
	   
	    hsmProperties.load(in);
	 } catch (Exception e) {
	     LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.HSMP_LOG002, new Object[ ] { IHSMConstants.HSM_PROPERTIES }));
	 } finally {
	     UtilsResourcesCommons.safeCloseInputStream(in);
	 }
	
	return hsmProperties;
    }

}
