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
 * <b>File:</b><p>es.gob.afirma.transformers.parseTransformers.ParseTransformersFactory.java.</p>
 * <b>Description:</b><p>Class that generates parsers for output parameters related to the web services of @Firma, eVisor and TS@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2014.
 */
package es.gob.afirma.transformers.parseTransformers;

import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersProperties;
import es.gob.afirma.utils.GenericUtilsCommons;

/**
 * <p>Class that generates parsers for output parameters related to the web services of @Firma, eVisor and TS@.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 19/11/2014.
 */
public final class ParseTransformersFactory {

    /**
     * Constructor method for the class ParseTransformersFactory.java.
     */
    private ParseTransformersFactory() {
    }

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static Logger logger = IntegraLogger.getInstance().getLogger(ParseTransformersFactory.class);

    /**
     * Method that obtains the class used to parse the XML response from a web service.
     * @param serviceReq Parameter that represents the name of the service.
     * @param method Parameter that represents the name of the method.
     * @param version Parameter that represents the version.
     * @return the class used to parse the XML response.
     * @throws TransformersException If the method fails.
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static Class<Object> getParseTransformer(String serviceReq, String method, String version) throws TransformersException {
	boolean found;
	Class res, c;
	Class<Object>[ ] interfaces;
	int i;
	String transformerClass;

	res = null;

	try {
	    if (!GenericUtilsCommons.assertStringValue(serviceReq) || !GenericUtilsCommons.assertStringValue(method)) {
		throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.PTF_LOG001, new Object[ ] { serviceReq, version }));
	    }
	    transformerClass = getTransformerClassName(serviceReq, method, version);
	    if (transformerClass == null) {
		throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.PTF_LOG002, new Object[ ] { serviceReq, method, version }));
	    }
	    res = Class.forName(transformerClass);

	    interfaces = res.getInterfaces();
	    i = 0;
	    found = false;
	    while (i < interfaces.length && !found) {
		c = interfaces[i];
		if (c.getName().equals(IParseTransformer.class.getName())) {
		    found = true;
		}
		i++;
	    }

	    if (!found) {
		res = null;
		throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.PTF_LOG003, new Object[ ] { transformerClass, IParseTransformer.class.getName() }));
	    }
	    logger.debug(Language.getFormatResIntegra(ILogConstantKeys.PTF_LOG004, new Object[ ] { transformerClass }));
	} catch (ClassNotFoundException e) {
	    logger.error(e);
	    throw new TransformersException(e.getMessage(), e);
	}

	return res;
    }

    /**
     * Method that obtains the name of the class used to parse the XML response from a web service.
     * @param serviceReq Parameter that represents the name of the service.
     * @param method Parameter that represents the name of the method.
     * @param version Parameter that represents the version.
     * @return the name of the class.
     */
    private static String getTransformerClassName(String serviceReq, String method, String version) {
	Properties properties;
	String res;

	properties = TransformersProperties.getMethodParseTransformersProperties(serviceReq, method, version);
	res = properties.getProperty(serviceReq + "." + method + "." + version + "." + TransformersConstants.PARSER_CTE + "." + TransformersConstants.TRANSFORMER_CLASS_CTE);

	return res;
    }
}
