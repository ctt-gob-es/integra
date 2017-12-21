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
 * <b>File:</b><p>es.gob.afirma.properties.IntegraProperties.java.</p>
 * <b>Description:</b><p>Class that allows to access to the properties defined inside of the configuration file <code>integraxxxxxx.properties</code>.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/03/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/03/2016.
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
 * <p>Class that allows to access to the properties defined inside of the configuration file <code>integraxxxxxx.properties</code>.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/03/2016.
 */
public final class IntegraProperties {

    /**
    * Attribute that represents the class logger.
    */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(IntegraProperties.class);

    /**
     * Attribute that represents the set of properties defined inside of the configuration file <code>integraxxxxx.properties</code>.
     */
    private Properties integraProperties = new Properties();

    /**
     * Constructor method for the class IntegraProperties.java. 
     */
    public IntegraProperties() {
    }

    /**
     * Gets the value of the attribute {@link #integraProperties}.
     * @param idClientParam Parameter that represents the client application identifier.
     * @return the value of the attribute {@link #integraProperties}.
     */
    public Properties getIntegraProperties(String idClientParam) {
	// Accedemos al archivo de propiedades asociados a la fachada de
	// servicios de Integr@
	String idClient = "";
	if (idClientParam != null) {
	    idClient = idClientParam;
	}
	String propertiesName = UtilsResourcesCommons.getPropertiesName("integra" + idClient);
	URL url = IntegraProperties.class.getClassLoader().getResource(propertiesName);
	URI uri = null;
	if (url == null) {
	    if (System.getProperty("integra.config") != null) {
		
		uri = new File(System.getProperty("integra.config") + File.separator + propertiesName).toURI();
		
	    } else {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFP_LOG001, new Object[ ] { propertiesName }));
	    }
	}
	    
	InputStream in = null;
	try {
	    if (uri == null) {
		uri = new URI(url.toString());
	    }
	    integraProperties = new Properties();
	   
	    in = new FileInputStream(new File(uri));
	   
	    integraProperties.load(in);
	 } catch (Exception e) {
	     LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFP_LOG002, new Object[ ] { propertiesName }));
	 } finally {
	     UtilsResourcesCommons.safeCloseInputStream(in);
	 }
	
	return integraProperties;
    }
}
