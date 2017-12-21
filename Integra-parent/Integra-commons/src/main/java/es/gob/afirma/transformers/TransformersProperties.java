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
 * <b>File:</b><p>es.gob.afirma.transformers.TransformersProperties.java.</p>
 * <b>Description:</b><p>Class that allows to access to the properties defined inside of the configuration file with the elements related to
 * the transformation of the request and response messages of @Firma, eVisor and TS@ platforms.</p>
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
import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.utils.UtilsResourcesCommons;

/**
 * <p>Class that allows to access to the properties defined inside of the configuration file with the elements related to
 * the transformation of the request and response messages of @Firma, eVisor and TS@ platforms.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 16/03/2011.
 */
public final class TransformersProperties {

    /**
     * Constructor method for the class TransformersProperties.java.
     */
    private TransformersProperties() {
    }

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static Logger logger = IntegraLogger.getInstance().getLogger(TransformersProperties.class);

    /**
     * Attribute that represents the time that the file {@link #properties} was last modified.
     */
    private static long propsFileLastUpdate = -1;

    /**
     * Attribute that represents the set of properties defined inside of the configuration file with the elements related to the transformation
     * of the request and response messages of @Firma, eVisor and TS@ platforms.
     */
    private static Properties properties = new Properties();

    static {
	init();
    }

    /**
     * Gets the value of the attribute {@link #properties}.
     * @return the value of the attribute {@link #properties}.
     */
    public static Properties getTransformersProperties() {
	init();
	return properties;
    }

    /**
     * Method that initializes {@link #properties} with all the related properties.
     */
    private static synchronized void init() {
	File file;
	InputStream in = null;

	try {
	    file = getPropertiesResource();

	    if (propsFileLastUpdate != file.lastModified()) {
		logger.debug(Language.getResIntegra(ILogConstantKeys.TP_LOG001));
		properties = new Properties();
		in = new FileInputStream(file);
		properties.load(in);
		propsFileLastUpdate = file.lastModified();

		logger.debug(Language.getFormatResIntegra(ILogConstantKeys.TP_LOG002, new Object[ ] { properties }));
		logger.debug(Language.getFormatResIntegra(ILogConstantKeys.TP_LOG003, new Object[ ] { new Date(propsFileLastUpdate) }));
	    }
	} catch (URISyntaxException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TP_LOG004, new Object[ ] { TransformersConstants.TRANSFORMERS_FILE_PROPERTIES });
	    logger.error(errorMsg, e);
	    properties = new Properties();
	} catch (IOException e) {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TP_LOG004, new Object[ ] { TransformersConstants.TRANSFORMERS_FILE_PROPERTIES });
	    logger.error(errorMsg, e);
	    properties = new Properties();
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(in);
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
	    res = new File(System.getProperty("integra.config") + File.separator + TransformersConstants.TRANSFORMERS_FILE_PROPERTIES);
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
	    url = TransformersProperties.class.getClassLoader().getResource(TransformersConstants.TRANSFORMERS_FILE_PROPERTIES);
	    if (url == null) {
		throw new URISyntaxException("Error", Language.getFormatResIntegra(ILogConstantKeys.TP_LOG005, new Object[ ] { TransformersConstants.TRANSFORMERS_FILE_PROPERTIES }));
	    }
	    uri = new URI(url.toString());
	    res = new File(uri);
	}
	return res;
    }

    /**
     * Method that obtains the properties related to the transform of request messages.
     * @param serviceName Parameter that represents the name of the web service defined to obtain the related properties.
     * @param method Parameter that represents the name of the method.
     * @param version Parameter that represents the version of the web service.
     * @return the set of related properties.
     */
    public static Properties getMethodRequestTransformersProperties(String serviceName, String method, String version) {
	Properties res;

	logger.debug(Language.getFormatResIntegra(ILogConstantKeys.TP_LOG006, new Object[ ] { serviceName }));

	res = getMethodTransformersProperties(serviceName, method, version, TransformersConstants.REQUEST_CTE);

	return res;
    }

    /**
     * Method that obtains the properties related to the transform of response messages.
     * @param serviceName Parameter that represents the name of the web service defined to obtain the related properties.
     * @param method Parameter that represents the name of the method.
     * @param version Parameter that represents the version of the web service.
     * @return the set of related properties.
     */
    public static Properties getMethodResponseTransformersProperties(String serviceName, String method, String version) {
	Properties res;

	logger.debug(Language.getFormatResIntegra(ILogConstantKeys.TP_LOG007, new Object[ ] { serviceName }));

	res = getMethodTransformersProperties(serviceName, method, version, TransformersConstants.RESPONSE_CTE);

	return res;
    }

    /**
     * Method that obtains the properties related to the parser of request and response messages.
     * @param serviceName Parameter that represents the name of the web service defined to obtain the related properties.
     * @param method Parameter that represents the name of the method.
     * @param version Parameter that represents the version of the web service.
     * @return the set of related properties.
     */
    public static Properties getMethodParseTransformersProperties(String serviceName, String method, String version) {
	Properties res;

	logger.debug(Language.getFormatResIntegra(ILogConstantKeys.TP_LOG008, new Object[ ] { serviceName }));

	res = getMethodTransformersProperties(serviceName, method, version, TransformersConstants.PARSER_CTE);

	return res;
    }

    /**
     * Method that obtains the properties related to the transformation of XML parameters for a web service.
     * @param serviceName Parameter that represents the name of the web service defined to obtain the related properties.
     * @param method Parameter that represents the name of the method.
     * @param version Parameter that represents the version of the web service.
     * @return the set of related properties.
     */
    public static Properties getMethodTransformersProperties(String serviceName, String method, String version) {
	Properties res;

	logger.debug(Language.getFormatResIntegra(ILogConstantKeys.TP_LOG008, new Object[ ] { serviceName }));

	res = getMethodTransformersProperties(serviceName, method, version, null);

	return res;
    }

    /**
     * Method that obtains the properties related to the input parameters.
     * @param serviceName Parameter that represents the name of the web service defined to obtain the related properties.
     * @param method Parameter that represents the name of the method.
     * @param version Parameter that represents the version of the web service.
     * @param type Parameter that represents the type of the elements to include on the properties to retrieve.
     * @return the set of related properties.
     */
    private static Properties getMethodTransformersProperties(String serviceName, String method, String version, String type) {
	Enumeration<?> enumeration;
	Properties res;
	String header, key;

	res = new Properties();
	header = serviceName + "." + method + "." + version + "." + (type == null ? "" : type);
	enumeration = getTransformersProperties().propertyNames();

	while (enumeration.hasMoreElements()) {
	    key = (String) enumeration.nextElement();

	    if (key.startsWith(header)) {
		res.put(key, properties.getProperty(key));
	    }
	}

	logger.debug(Language.getFormatResIntegra(ILogConstantKeys.TP_LOG002, new Object[ ] { res }));

	return res;
    }
}
