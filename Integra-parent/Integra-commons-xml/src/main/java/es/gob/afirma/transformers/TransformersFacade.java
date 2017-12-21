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
 * <b>File:</b><p>es.gob.afirma.transformers.TransformersFacade.java.</p>
 * <b>Description:</b><p>Class that provides methods for transform input and output parameters related to @Firma, TS@ and eVisor web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>16/03/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 16/03/2011.
 */
package es.gob.afirma.transformers;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.transformers.parseTransformers.ParseTransformersFactory;
import es.gob.afirma.transformers.xmlTransformers.XmlTransformersFactory;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.NumberConstants;
import es.gob.afirma.utils.UtilsXML;

/**
 * <p>Class that provides methods for transform input and output parameters related to @Firma, TS@ and eVisor web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 16/03/2011.
 */
public final class TransformersFacade {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TransformersFacade.class);

    /**
     * Attribute that represents the unique instance of the class. 
     */
    private static TransformersFacade instance;

    /**
     * Attribute that represents the properties for published web services.
     */
    private Properties transformersProperties;

    /**
     * Attribute that represents parser parameters properties.
     */
    private Properties parserParamsProp;

    /**
     * Attribute that represents parameters number.
     */
    private static final int PARAM_NUMBERS = 4;

    /**
     * Method that obtains the unique instance of the class.
     * @return the unique instance of the class.
     */
    public static TransformersFacade getInstance() {
	instance = new TransformersFacade();
	return instance;
    }

    /**
     * Constructor method for the class TransformersFacade.java.
     */
    private TransformersFacade() {
	transformersProperties = TransformersProperties.getTransformersProperties();
	parserParamsProp = ParserParameterProperties.getParserParametersProperties();
    }

    /**
     * Method that obtains a XML document with the template of a request or a response of a web service.
     * @param serviceReq Parameter that represents the web service name.
     * @param method Parameter that represents the name of the method associated to the web service.
     * @param type Parameter that represents the template type. The allowed values are:
     * <ul>
     * <li>request: Request template.</li>
     * <li>response: Response template.</li>
     * </ul>
     * @param version Parameter that represents the version of the web service.
     * @return the generated XML document.
     * @throws TransformersException If the method fails.
     */
    public Document getXmlRequestFileByRequestType(String serviceReq, String method, String type, String version) throws TransformersException {
	File xmlFile;
	String fileName, xmlTemplateFolder;
	Document res = null;
	if (!GenericUtilsCommons.assertStringValue(serviceReq) || !GenericUtilsCommons.assertStringValue(type) || !GenericUtilsCommons.assertStringValue(version) || !GenericUtilsCommons.assertStringValue(method)) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG003);
	    LOGGER.error(errorMsg);
	    throw new TransformersException(errorMsg);
	}
	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TF_LOG004, new Object[ ] { serviceReq, method, type, version }));

	try {
	    StringBuffer templateName = new StringBuffer(serviceReq).append(".");
	    templateName.append(method).append(".");
	    templateName.append(version).append(".");
	    templateName.append(type).append(".");
	    templateName.append(TransformersConstants.TEMPLATE_CTE);

	    fileName = transformersProperties.getProperty(templateName.toString());
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TF_LOG005, new Object[ ] { fileName }));

	    xmlTemplateFolder = transformersProperties.getProperty(TransformersConstants.TRANSFORMERS_TEMPLATES_PATH_PROPERTIES) + "/xmlTemplates";

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TF_LOG007, new Object[ ] { xmlTemplateFolder }));
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TF_LOG008));

	    xmlFile = new File(xmlTemplateFolder, fileName);
	    res = UtilsXML.parseDocument(new FileReader(xmlFile));

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TF_LOG006, new Object[ ] { res.getDocumentElement().getTagName() }));
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG002);
	    LOGGER.error(errorMsg, e);
	    throw new TransformersException(errorMsg, e);
	} catch (Exception e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG003);
	    LOGGER.error(errorMsg, e);
	    throw new TransformersException(errorMsg, e);
	}

	return res;
    }

    /**
     * Method that obtains a XML document with the template of the parser for a response of a web service.
     * @param serviceReq Parameter that represents the web service name.
     * @param method Parameter that represents the name of the method associated to the web service.
     * @param version Parameter that represents the version of the web service.
     * @return the generated XML document.
     * @throws TransformersException If the method fails.
     */
    public Document getParserTemplateByRequestType(String serviceReq, String method, String version) throws TransformersException {
	File xmlFile;
	String fileName, xmlTemplateFolder;
	Document res = null;

	LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TF_LOG009, new Object[ ] { serviceReq, method, TransformersConstants.PARSER_CTE, version }));

	try {
	    fileName = transformersProperties.getProperty(serviceReq + "." + method + "." + version + "." + TransformersConstants.PARSER_CTE + "." + TransformersConstants.TEMPLATE_CTE);
	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TF_LOG005, new Object[ ] { fileName }));

	    xmlTemplateFolder = transformersProperties.getProperty(TransformersConstants.TRANSFORMERS_TEMPLATES_PATH_PROPERTIES) + "/parserTemplates";

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TF_LOG010, new Object[ ] { xmlTemplateFolder }));
	    LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TF_LOG008));

	    xmlFile = new File(xmlTemplateFolder, fileName);
	    res = UtilsXML.parseDocument(new FileReader(xmlFile));

	    LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.TF_LOG006, new Object[ ] { res.getDocumentElement().getTagName() }));
	} catch (IOException e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG002);
	    LOGGER.error(errorMsg, e);
	    throw new TransformersException(errorMsg, e);
	} catch (Exception e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG003);
	    LOGGER.error(errorMsg, e);
	    throw new TransformersException(errorMsg, e);
	}

	return res;
    }

    /**
     * Method that obtains a String with XML format used to invoke a web service from a map of parameters.
     * @param parameters Map with the input parameters related to the XML request of the web service.
     * @param service Parameter that represents the web service name.
     * @param version Parameter that represents the version of the web service.
     * @return the generated XML String.
     * @throws TransformersException If the method fails.
     */
    public String generateXml(Map<String, Object> parameters, String service, String version) throws TransformersException {
	return generateXml(parameters, service, getMethodName(service), version);
    }

    /**
     * Method that obtains the method associated to a web service.
     * @param service Parameter that represents the web service name.
     * @return the method name.
     */
    private String getMethodName(String service) {
	if (GeneralConstants.DSS_AFIRMA_SIGN_REQUEST.equals(service)) {
	    return GeneralConstants.DSS_AFIRMA_SIGN_METHOD;
	} else if (GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST.equals(service)) {
	    return GeneralConstants.DSS_AFIRMA_VERIFY_METHOD;
	} else if (GeneralConstants.DSS_AFIRMA_VERIFY_REQUEST.equals(service)) {
	    return GeneralConstants.DSS_AFIRMA_VERIFY_METHOD;
	} else if (GeneralConstants.DSS_BATCH_VERIFY_SIGNATURE_REQUESTS.equals(service)) {
	    return GeneralConstants.DSS_AFIRMA_VERIFY_SIGNATURES_METHOD;
	} else if (GeneralConstants.DSS_BATCH_VERIFY_CERTIFICATE_REQUEST.equals(service)) {
	    return GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATES_METHOD;
	} else if (GeneralConstants.DSS_ASYNC_REQUEST_STATUS.equals(service)) {
	    return GeneralConstants.DSS_ASYNC_REQUEST_STATUS_METHOD;
	} else {
	    return service;
	}
    }

    /**
     * Method that obtains a String with XML format used to invoke a web service from a map of parameters.
     * @param parameters Map with the input parameters related to the XML request of the web service.
     * @param service Parameter that represents the web service name.
     * @param method Parameter that represents the name of the method associated to the web service.
     * @param version Parameter that represents the version of the web service.
     * @return the generated XML String.
     * @throws TransformersException If the method fails.
     */
    public String generateXml(Map<String, Object> parameters, String service, String method, String version) throws TransformersException {
	Class<?> transformerClass;
	if (parameters == null || !GenericUtilsCommons.assertStringValue(service) || !GenericUtilsCommons.assertStringValue(version) || !GenericUtilsCommons.assertStringValue(method)) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG003);
	    LOGGER.error(errorMsg);
	    throw new TransformersException(errorMsg);
	}
	String res = null;
	try {
	    // Obtenemos la clase que creara la cadena xml que contiene el
	    // parametro esperado por @firma
	    transformerClass = XmlTransformersFactory.getXmlTransformer(service, method, TransformersConstants.REQUEST_CTE, version);
	    res = (String) invokeCommonXmlTransf(transformerClass, parameters, service, method, TransformersConstants.REQUEST_CTE, version);
	} catch (Exception e) {
	    LOGGER.error(e);
	    throw new TransformersException(e);
	}
	return res;
    }

    /**
     * Method that processes a XML response to generate a map with the contained elements.
     * @param response Parameter that represents the XML response of a web service.
     * @param service Parameter that represents the web service name.
     * @param version Parameter that represents the version of the web service.
     * @return a map from the elements defined inside of the XML response.
     * @throws TransformersException If the method fails.
     */
    public Map<String, Object> parseResponse(String response, String service, String version) throws TransformersException {
	return parseResponse(response, service, getMethodName(service), version);
    }

    /**
     * Method that processes a XML response to generate a map with the contained elements.
     * @param response Parameter that represents the XML response of a web service.
     * @param service Parameter that represents the web service name.
     * @param method Parameter that represents the name of the method associated to the web service.
     * @param version Parameter that represents the version of the web service.
     * @return a map from the elements defined inside of the XML response.
     * @throws TransformersException If the method fails.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Map<String, Object> parseResponse(String response, String service, String method, String version) throws TransformersException {
	Class<Object> transformerClass;
	Map<String, Object> res;

	res = null;
	if (!GenericUtilsCommons.assertStringValue(response) || !GenericUtilsCommons.assertStringValue(service) || !GenericUtilsCommons.assertStringValue(version) || !GenericUtilsCommons.assertStringValue(method)) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG003);
	    LOGGER.error(errorMsg);
	    throw new TransformersException(errorMsg);
	}
	try {
	    // Obtenemos la clase que creara la estructura que contiene una
	    // respuesta generada
	    // por la plataforma
	    transformerClass = ParseTransformersFactory.getParseTransformer(service, method, version);
	    res = (Map) invokeParseTransf(response, transformerClass, service, method, version);
	} catch (Exception e) {
	    LOGGER.error(e);
	    throw new TransformersException(e);
	}
	return res;
    }

    /**
     * Method that generates a request XML or a response XML from a map of parameters.
     * @param transformerClass Parameter that represents the class of the element which makes the generation of the request.
     * @param parameters Map with the input parameters related to the XML request of the web service.
     * @param service Parameter that represents the web service name.
     * @param methodWS Parameter that represents the name of the method associated to the web service.
     * @param type Parameter that represents the type of the XML to generate. The allowed values are:
     * <ul>
     * <li>request: Request XML.</li>
     * <li>response: Response XML.</li>
     * </ul>
     * @param version Parameter that represents the version of the web service.
     * @return the generated XML message.
     * @throws TransformersException If the method fails.
     */
    private Object invokeCommonXmlTransf(Class<?> transformerClass, Map<String, Object> parameters, String service, String methodWS, String type, String version) throws TransformersException {
	Class<?>[ ] constrParamClasses, methodParamClasses;
	Constructor<?> constructor;
	Method method;
	Object object;
	Object[ ] constrParamObjects, methodParamObjects;
	String res;

	res = null;

	try {
	    // Instanciamos un objeto transformardor
	    constrParamClasses = new Class[PARAM_NUMBERS];
	    constrParamClasses[0] = Class.forName(String.class.getName());
	    constrParamClasses[1] = Class.forName(String.class.getName());
	    constrParamClasses[2] = Class.forName(String.class.getName());
	    constrParamClasses[NumberConstants.INT_3] = Class.forName(String.class.getName());

	    constructor = transformerClass.getConstructor(constrParamClasses);
	    constrParamObjects = new Object[PARAM_NUMBERS];
	    constrParamObjects[0] = service;
	    constrParamObjects[1] = methodWS;
	    constrParamObjects[2] = type;
	    constrParamObjects[NumberConstants.INT_3] = version;
	    object = constructor.newInstance(constrParamObjects);

	    // Obtenemos el método que creara la cadena xml que contiene el
	    // parametro esperado por @firma
	    methodParamClasses = new Class[1];
	    methodParamClasses[0] = Class.forName("java.lang.Object");
	    method = transformerClass.getMethod("transform", methodParamClasses);

	    // Invocamos el método transformador
	    methodParamObjects = new Object[1];
	    methodParamObjects[0] = parameters;

	    res = (String) method.invoke(object, methodParamObjects);
	} catch (Exception e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG001);
	    LOGGER.error(errorMsg, e);
	    throw new TransformersException(errorMsg, e);
	}

	return res;
    }

    /**
     * Method that generates a map with the elements contained inside of a response of a web service.
     * @param response Parameter that represents a response XML from the web service.
     * @param transformerClass Parameter that represents the class of the element which makes the generation of the parser.
     * @param service Parameter that represents the web service name.
     * @param methodParam Parameter that represents the name of the method associated to the web service.
     * @param version Parameter that represents the version of the web service.
     * @return the generated map.
     * @throws TransformersException If the method fails.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private Object invokeParseTransf(String response, Class<Object> transformerClass, String service, String methodParam, String version) throws TransformersException {
	Class<Object>[ ] constrParamClasses, methodParamClasses;
	Constructor<Object> constructor;
	Map<String, Object> res;
	Method method;
	Object object;
	Object[ ] constrParamObjects, methodParamObjects;

	res = null;

	try {
	    // Instanciamos un objeto transformardor
	    constrParamClasses = new Class[NumberConstants.INT_3];
	    Class<Object> stringClass = (Class<Object>) Class.forName("java.lang.String");
	    constrParamClasses[0] = stringClass;
	    constrParamClasses[1] = stringClass;
	    constrParamClasses[2] = stringClass;

	    constructor = transformerClass.getConstructor(constrParamClasses);
	    constrParamObjects = new Object[NumberConstants.INT_3];
	    constrParamObjects[0] = service;
	    constrParamObjects[1] = methodParam;
	    constrParamObjects[2] = version;
	    object = constructor.newInstance(constrParamObjects);

	    // Obtenemos el método que creara la cadena xml que contiene el
	    // parametro esperado por @firma
	    methodParamClasses = new Class[1];
	    methodParamClasses[0] = stringClass;
	    method = transformerClass.getMethod("transform", methodParamClasses);

	    // Invocamos el método transformador
	    methodParamObjects = new Object[1];
	    methodParamObjects[0] = response;
	    res = (Map) method.invoke(object, methodParamObjects);
	} catch (Exception e) {
	    String errorMsg = Language.getResIntegra(ILogConstantKeys.TF_LOG001);
	    LOGGER.error(errorMsg, e);
	    throw new TransformersException(errorMsg, e);
	}

	return res;
    }

    /**
     * Method that obtains the value of a element defined of <code>parserParameters.properties</code> file.
     * @param parameterName Parameter that represents the key of the element to obtain.
     * @return the value of the element by the key.
     */
    public String getParserParameterValue(String parameterName) {
	String result = null;
	if (GenericUtilsCommons.assertStringValue(parameterName)) {
	    Object tmp = parserParamsProp.get(parameterName);
	    result = tmp == null ? null : tmp.toString();
	}
	return result;
    }
}
