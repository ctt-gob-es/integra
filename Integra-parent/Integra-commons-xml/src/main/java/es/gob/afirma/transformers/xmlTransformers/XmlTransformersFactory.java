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
 * <b>File:</b><p>es.gob.afirma.transformers.xmlTransformers.XmlTransformersFactory.java.</p>
 * <b>Description:</b><p>Class that represents a factory of generators for input and output parameters for web services of @Firma, eVisor and TS@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/02/2011.</p>
 * @author Gobierno de España
 * @version 1.0, 04/02/2011.
 */
package es.gob.afirma.transformers.xmlTransformers;

import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersProperties;

/**
 * <p>Class that represents a factory of generators for input and output parameters for web services of @Firma, eVisor and TS@.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 04/02/2011.
 */
public final class XmlTransformersFactory {

    /**
     * Constructor method for the class XmlTransformersFactory.java.
     */
    private XmlTransformersFactory() {
    }

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static Logger logger = IntegraLogger.getInstance().getLogger(XmlTransformersFactory.class);

    /**
     * Method that obtains the class used to generate the input or output parameter used for a web service.
     * @param serviceReq Parameter that represents the name of the web service.
     * @param method Parameter that represents the name of the method of the web service.
     * @param type Parameter that represents the type or parameter. The allowed values are:
     * <ul>
     * <li>request: For input parameter.</li>
     * <li>response: For output parameter.</li>
     * </ul>
     * @param version Parameter that represents the version of the service.
     * @return the generated class.
     * @throws TransformersException If the method fails.
     */
    @SuppressWarnings("rawtypes")
    public static Class<?> getXmlTransformer(String serviceReq, String method, String type, String version) throws TransformersException {
	boolean found;
	Class<?> res, c;
	Class<?>[ ] interfaces;
	int i;
	String transformerClass;

	res = null;

	try {
	    if (serviceReq == null || method == null || version == null) {
		throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.XTF_LOG001, new Object[ ] { serviceReq, method, version }));
	    }
	    transformerClass = getTransformerClassName(serviceReq, method, type, version);
	    if (transformerClass == null) {
		throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.XTF_LOG002, new Object[ ] { serviceReq, method, version }));
	    }
	    res = (Class) Class.forName(transformerClass);

	    interfaces = res.getInterfaces();
	    i = 0;
	    found = false;
	    while (i < interfaces.length && !found) {
		c = interfaces[i];
		if (c.getName().equals(IXmlTransformer.class.getName())) {
		    found = true;
		}
		i++;
	    }

	    if (!found) {
		res = null;
		throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.XTF_LOG003, new Object[ ] { transformerClass, IXmlTransformer.class.getName() }));
	    }

	    logger.debug(Language.getFormatResIntegra(ILogConstantKeys.XTF_LOG004, new Object[ ] { transformerClass }));
	} catch (ClassNotFoundException e) {
	    logger.error(e);
	    throw new TransformersException(e.getMessage(), e);
	}

	return res;
    }

    /**
     * Method that obtains the name of the class used to generate the input or output parameter used for a web service.
     * @param serviceReq Parameter that represents the name of the web service.
     * @param method Parameter that represents the name of the method of the web service.
     * @param type Parameter that represents the type or parameter. The allowed values are:
     * <ul>
     * <li>request: For input parameter.</li>
     * <li>response: For output parameter.</li>
     * </ul>
     * @param version Parameter that represents the version of the service.
     * @return the name of the class.
     */
    private static String getTransformerClassName(String serviceReq, String method, String type, String version) {
	Properties properties;
	String res;

	properties = new Properties();

	if (type.equals(TransformersConstants.REQUEST_CTE)) {
	    properties = TransformersProperties.getMethodRequestTransformersProperties(serviceReq, method, version);
	} else if (type.equals(TransformersConstants.RESPONSE_CTE)) {
	    properties = TransformersProperties.getMethodResponseTransformersProperties(serviceReq, method, version);
	}
	StringBuffer transfClassName = new StringBuffer(serviceReq).append(".");
	transfClassName.append(method).append(".");
	transfClassName.append(version).append(".");
	transfClassName.append(type).append(".");
	transfClassName.append(TransformersConstants.TRANSFORMER_CLASS_CTE);

	res = properties.getProperty(transfClassName.toString());

	return res;
    }
}
