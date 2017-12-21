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
 * <b>File:</b><p>es.gob.afirma.transformers.ParserParameterProperties.java.</p>
 * <b>Description:</b><p>Class that allows to access to the properties defined inside of the configuration file with the shortcuts of the nodes contained
 * inside of the XML responses.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>16/03/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 16/03/2011.
 */
package es.gob.afirma.transformers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.utils.UtilsResourcesCommons;

/**
 * <p>Class that allows to access to the properties defined inside of the configuration file with the shortcuts of the nodes contained
 * inside of the XML responses.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 16/03/2011.
 */
public final class ParserParameterProperties {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(ParserParameterProperties.class);

    /**
     * Attribute that represents the time that the file {@link #properties} was last modified.
     */
    private static long propsFileLastUpdate = -1;

    /**
     * Attribute that represents the set of properties defined inside of the configuration file with the shortcuts of the nodes contained inside of
     * the XML responses.
     */
    private static Properties properties = new Properties();

    /**
     * Constructor method for the class ParserParameterProperties.java.
     */
    private ParserParameterProperties() {
    }

    static {
	init();
    }

    /**
     * Gets the value of the attribute {@link #properties}.
     * @return the value of the attribute {@link #properties}.
     */
    public static Properties getParserParametersProperties() {
	init();
	return properties;
    }

    /**
     * Method that initializes {@link #properties} with all the related properties.
     */
    private static synchronized void init() {
	File file;
	FileInputStream fis = null;
	try {
	    file = getPropertiesResource();

	    if (propsFileLastUpdate != file.lastModified()) {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.PPP_LOG001));
		properties = new Properties();
		fis = new FileInputStream(file);
		properties.load(fis);
		propsFileLastUpdate = file.lastModified();

		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.PPP_LOG002, new Object[ ] { properties }));
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.PPP_LOG003, new Object[ ] { new Date(propsFileLastUpdate) }));
	    }
	} catch (URISyntaxException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.PPP_LOG004, new Object[ ] { TransformersConstants.PARSED_PARAMETERS_FILE }), e);
	    properties = new Properties();
	} catch (IOException e) {
	    LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.PPP_LOG004, new Object[ ] { TransformersConstants.PARSED_PARAMETERS_FILE }), e);
	    properties = new Properties();
	} finally {
	    if (fis != null) {
		try {
		    fis.close();
		} catch (IOException e) {
		    // Vacío intencionadamente
		}
	    }
	}
    }

    /**
     * Method that obtains {@link #properties} as a file.
     * @return {@link #properties} as a file
     * @throws URISyntaxException If the method fails.
     */
    private static File getPropertiesResource() throws URISyntaxException {
	File res = null;
	URL url;
	URI uri;

	if (System.getProperty("integra.config") != null) {
	    res = new File(System.getProperty("integra.config") + File.separator + TransformersConstants.PARSED_PARAMETERS_FILE);
	    InputStream in = null;
	    try {
		in = new FileInputStream(res);
	    } catch (FileNotFoundException e) {
		res = null;
	    } finally {
		UtilsResourcesCommons.safeCloseInputStream(in);
	    }
	}
	if (res == null) {
	    url = ParserParameterProperties.class.getClassLoader().getResource(TransformersConstants.PARSED_PARAMETERS_FILE);
	    if (url == null) {
		throw new URISyntaxException("Error", Language.getFormatResIntegra(ILogConstantKeys.PPP_LOG005, new Object[ ] { TransformersConstants.PARSED_PARAMETERS_FILE }));
	    }
	    uri = new URI(url.toString());
	    res = new File(uri);
	}
	return res;
    }

}
