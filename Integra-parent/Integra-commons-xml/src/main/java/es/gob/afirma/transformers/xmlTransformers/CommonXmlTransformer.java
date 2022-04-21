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
 * <b>File:</b><p>es.gob.afirma.transformers.xmlTransformers.DSSXmlTransformer.java.</p>
 * <b>Description:</b><p>Class that transforms input parameters to a XML request for the native web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/02/2011.</p>
 * @author Gobierno de España
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.transformers.xmlTransformers;

import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.transformers.TransformersProperties;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.UtilsXML;

/**
 * <p>Class that transforms input parameters to a XML request for the native web services of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public class CommonXmlTransformer implements IXmlTransformer {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static Logger logger = Logger.getLogger(CommonXmlTransformer.class);

    /**
     * Attribute that represents the native service name.
     */
    private String service = null;

    /**
     * Attribute that represents the type.
     */
    private String type = null;

    /**
     * Attribute that represents the message version.
     */
    private String messageVersion = null;

    /**
     * Attribute that represents the method of web service.
     */
    private String method;

    /**
     * Constructor method for the class CommonXmlTransformer.java.
     */
    public CommonXmlTransformer() {
	this(null, null, null, null);
    }

    /**
     * Constructor method for the class CommonXmlTransformer.java.
     * @param svc Parameter that represents the native service name.
     * @param methodParam Parameter that represents the method of web service.
     * @param typ Parameter that represents the type.
     * @param msgVersion Parameter that represents the message version.
     */
    public CommonXmlTransformer(String svc, String methodParam, String typ, String msgVersion) {
	service = svc;
	method = methodParam;
	type = typ;
	messageVersion = msgVersion;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.xmlTransformers.IXmlTransformer#getService()
     */
    public final String getService() {
	return service;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.xmlTransformers.IXmlTransformer#getType()
     */
    public final String getType() {
	return type;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.xmlTransformers.IXmlTransformer#getMessageVersion()
     */
    public final String getMessageVersion() {
	return messageVersion;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.xmlTransformers.IXmlTransformer#transform(java.lang.Object)
     */
    public final Object transform(Object params) throws TransformersException {
	Document doc;
	Object res = null;

	if (messageVersion.equals(TransformersConstants.VERSION_10)) {
	    doc = TransformersFacade.getInstance().getXmlRequestFileByRequestType(service, method, type, messageVersion);
	    logger.debug(Language.getFormatResIntegra(ILogConstantKeys.CXT_LOG001, new Object[ ] { service, messageVersion }));

	    res = transformGenericVersion10((Map<?, ?>) params, doc);
	} else {
	    String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.CXT_LOG002, new Object[ ] { messageVersion, service });
	    logger.error(errorMsg);
	    throw new TransformersException(errorMsg);
	}

	return res;
    }

    /**
     * Method that generates a XML (generic version 1) by a map of parameters.
     * @param parameters Map of parameters.
     * @param docRequest Parameter that represents the entire XML document.
     * @return the generated XML.
     * @throws TransformersException If the method fails.
     */
    private Object transformGenericVersion10(Map<?, ?> parameters, Document docRequest) throws TransformersException {
	Element rootElement, aux;
	Iterator<?> iterator;
	Properties serviceProps;
	String key, value, res, schemaLocation;
	res = null;

	checkInputParameters(parameters, docRequest);

	rootElement = docRequest.getDocumentElement();
	serviceProps = TransformersProperties.getMethodTransformersProperties(service, method, messageVersion);
	schemaLocation = rootElement.getAttribute("xsi:SchemaLocation");

	// Establecimiento de la localizacion del esquema XSD que define el
	// parametro
	if (schemaLocation != null) {
	    if (serviceProps.getProperty(service + "." + messageVersion + "." + type + "." + TransformersConstants.SCHEMA_LOCATION_ADDRESS_PROP) != null) {
		schemaLocation = schemaLocation.replaceFirst(TransformersConstants.SCH_LOC_ADD_SEP, serviceProps.getProperty(service + "." + messageVersion + "." + type + "." + TransformersConstants.SCHEMA_LOCATION_ADDRESS_PROP));
	    }
	    rootElement.setAttribute("xsi:SchemaLocation", schemaLocation);
	}

	iterator = parameters.keySet().iterator();

	// Procesamos los parametros y los colocamos en el parametro de entrada
	logger.debug(Language.getResIntegra(ILogConstantKeys.CXT_LOG003));
	while (iterator.hasNext()) {
	    key = (String) iterator.next();
	    // data = key.split(TransformersConstants.paramSeparator);

	    aux = null;
	    if (parameters.get(key) instanceof String) {
		value = (String) parameters.get(key);

		logger.debug(Language.getFormatResIntegra(ILogConstantKeys.CXT_LOG004, new Object[ ] { key, value }));
		// if(data[1].equals(TransformersConstants.binaryValue)) {
		// aux =
		// UtilsXML.sustituyeElementoValorCDATA(rootElement,data[0],value);
		// } else if(data[1].equals(TransformersConstants.textValue)) {
		aux = UtilsXML.replaceElementValue(rootElement, key, value);
		// }

		if (aux == null) {
		    throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.CXT_LOG005, new Object[ ] { key }));
		}
	    }
	}

	try {
	    res = UtilsXML.transformDOMtoString(docRequest);
	} catch (Exception e) {
	    logger.error(e);
	    throw new TransformersException(e.getMessage(), e);
	}
	logger.debug(Language.getResIntegra(ILogConstantKeys.CXT_LOG006));

	return res;
    }

    /**
     * Method that checks the input parameters.
     * @param parameters Parameters to check.
     * @param docRequest Parameter that represents the request to the web service.
     * @throws TransformersException whether the input parameters aren't valid.
     */
    private void checkInputParameters(Map<?, ?> parameters, Document docRequest) throws TransformersException {
	if (GenericUtilsCommons.checkNullValues(parameters, docRequest) || parameters.size() == 0) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CXT_LOG007));
	}
	Element rootElement = docRequest.getDocumentElement();

	if (type.equals(TransformersConstants.REQUEST_CTE)) {
	    if (!rootElement.getTagName().equals("mensajeEntrada") && !rootElement.getTagName().equals("inputMessage")) {
		// el elemento raiz es "mensajeEntrada"
		throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CXT_LOG008));
	    }
	} else if (type.equals(TransformersConstants.RESPONSE_CTE)) {
	    if (!rootElement.getTagName().equals("mensajeSalida") && !rootElement.getTagName().equals("outputMessage")) {
		// el elemento raiz es "mensajeSalida"
		throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CXT_LOG009));
	    }

	} else {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CXT_LOG010));
	}
    }

    /**
     * Sets the value of the attribute {@link #messageVersion}.
     * @param msgVersion The value for the attribute {@link #messageVersion}.
     */
    public final void setMessageVersion(String msgVersion) {
	messageVersion = msgVersion;
    }

    /**
     * Sets the value of the attribute {@link #service}.
     * @param svc The value for the attribute {@link #service}.
     */
    public final void setService(String svc) {
	service = svc;
    }

    /**
     * Sets the value of the attribute {@link #type}.
     * @param typ The value for the attribute {@link #type}.
     */
    public final void setType(String typ) {
	type = typ;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.xmlTransformers.IXmlTransformer#getMethod()
     */
    public final String getMethod() {
	return method;
    }

}
