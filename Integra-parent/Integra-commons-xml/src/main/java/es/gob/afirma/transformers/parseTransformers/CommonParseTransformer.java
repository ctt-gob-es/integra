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
 * <b>File:</b><p>es.gob.afirma.transformers.parseTransformers.CommonParseTransformer.java.</p>
 * <b>Description:</b><p>Class that transforms the responses of web services from @Firma, eVisor and TS@ of only one level and without nodes with
 * repeated names.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.transformers.parseTransformers;

import java.io.StringReader;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersProperties;
import es.gob.afirma.utils.UtilsXML;

/**
 * <p>Class that transforms the responses of web services from @Firma, eVisor and TS@ of only one level and without nodes with
 * repeated names.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.1, 18/04/2022.
 */
public class CommonParseTransformer implements IParseTransformer {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static Logger logger = Logger.getLogger(CommonParseTransformer.class);

    /**
     * Attribute that represents the request.
     */
    private String request = null;

    /**
     * Attribute that represents the version of the message.
     */
    private String messageVersion = null;

    /**
     * Attribute that represents method name.
     */
    private String method = null;

    /**
     * Constructor method for the class CommonParseTransformer.java.
     * @param req Parameter that represents the request.
     * @param methodParam Parameter that represents method name.
     * @param msgVersion Parameter that represents the version of the message.
     */
    public CommonParseTransformer(String req, String methodParam, String msgVersion) {
	request = req;
	method = methodParam;
	messageVersion = msgVersion;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#getRequest()
     */
    public final String getRequest() {
	return request;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#getMessageVersion()
     */
    public final String getMessageVersion() {
	return messageVersion;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#transform(java.lang.String)
     */
    @SuppressWarnings("unchecked")
    public final Object transform(String xmlResponse) throws TransformersException {
	Map<String, Object> xmlData, res;
	String xpathRespElement;

	res = null;
	xpathRespElement = getXpathRespElement();
	logger.debug(Language.getFormatResIntegra(ILogConstantKeys.CPT_LOG002, new Object[ ] { xpathRespElement }));
	if (xpathRespElement == null) {
	    throw new TransformersException(Language.getFormatResIntegra(ILogConstantKeys.CPT_LOG001, new Object[ ] { TransformersConstants.RESP_ROOT_ELEMENT_CTE, request, messageVersion }));
	}

	xmlData = readResponse(xmlResponse, xpathRespElement);
	res = (Map<String, Object>) xmlData.get(ParseTransformerConstants.ERROR_KEY);

	if (res == null) {
	    res = (Map<String, Object>) xmlData.get(ParseTransformerConstants.OK_KEY);
	}

	return res;
    }

    /**
     * Method that retrieves the information obtained as the result of a web service. This information can describe an exception or the result of the service.
     * @param xmlResponse Parameter that represents the response XML message.
     * @param xpathRespElement Parameter that represents the name of the response element.
     * @return a map with the information of the generated error or the result of the service.
     * @throws TransformersException If there's an error reading the XML message.
     */
    private Map<String, Object> readResponse(String xmlResponse, String xpathRespElement) throws TransformersException {
	Document doc;
	Element rootElement;
	Map<String, Object> res, aux = null;

	res = null;

	try {
	    doc = UtilsXML.parseDocument(new StringReader(xmlResponse));
	} catch (Exception e) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CPT_LOG003), e);
	}

	if (doc != null) {
	    // Leemos los datos de la respuesta
	    rootElement = doc.getDocumentElement();
	    if (!rootElement.getTagName().equals("mensajeSalida") && !rootElement.getTagName().equals("outputMessage")) {// el
		// elemento
		// raiz
		// es
		// "mensajeSalida"
		throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CPT_LOG004));
	    }

	    res = new Hashtable<String, Object>();
	    // Comprobamos si se ha producido algún error.
	    Element errorElem = UtilsXML.getElement(rootElement, ParseTransformerConstants.RESPONSE_ELEMENT_SP + "/" + ParseTransformerConstants.EXCEPTION_ELEMENT_SP);
	    if (errorElem == null) {
		errorElem = UtilsXML.getElement(rootElement, ParseTransformerConstants.RESPONSE_ELEMENT + "/" + ParseTransformerConstants.EXCEPTION_ELEMENT);
	    }
	    if (errorElem != null) {
		aux = readErrorResponse(errorElem);
	    }

	    if (aux == null) {
		// No se produjo ningún error, leemos el mensaje SOAP OK
		aux = readOKResponse(UtilsXML.getElement(rootElement, xpathRespElement));
		if (aux == null) {
		    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.CPT_LOG005));
		}
		res.put(ParseTransformerConstants.OK_KEY, aux);
	    } else {
		// Mensaje de error
		res.put(ParseTransformerConstants.ERROR_KEY, aux);
	    }
	}

	return res;
    }

    /**
     * Method that processes a response error from the XML response of a validation web service.
     * @param exceptionElement Parameter that represents the element <code>Excepcion</code>.
     * @return a map with the values contained inside of the element <code>Excepcion</code>.
     */
    private Map<String, Object> readErrorResponse(Element exceptionElement) {
	List<?> exceptionData;
	Node aux;
	Map<String, Object> res = null;
	String nodeValue;

	if (exceptionElement != null) {
	    // Se ha producido una excepcion al validar el certificado que no
	    // ha permitido realizar la validación completamente.
	    res = new Hashtable<String, Object>();

	    exceptionData = UtilsXML.searchChildElements(exceptionElement);
	    for (int i = 0; i < exceptionData.size(); i++) {
		aux = (Node) exceptionData.get(i);
		if (aux.getNodeType() == Node.ELEMENT_NODE) {
		    // Los tags posibles son: codigoError, descripcion y
		    // excepcionAsociada
		    nodeValue = UtilsXML.getElementValue((Element) aux);
		    res.put(((Element) aux).getTagName(), nodeValue != null ? nodeValue : "");
		}
	    }
	}

	return res;
    }

    /**
     * Method that retrieves the information from a response of signature validation or server signature.
     * @param upperRespElement Parameter that represents the element <code>Respuesta</code>.
     * @return a map with the values contained inside of the element <code>Respuesta</code>.
     */
    private Map<String, Object> readOKResponse(Element upperRespElement) {
	Map<String, Object> res;
	List<Element> auxV;

	res = null;

	if (upperRespElement != null) {
	    // Obtenemos la información de respuesta
	    auxV = UtilsXML.searchChildElements(upperRespElement);
	    res = readOKResponseRec(auxV, 0);
	}
	return res;
    }

    /**
     * Method that reads the content of a correct response.
     * @param elementChilds Parameter that represents the child elements of the node with the correct response.
     * @param index Parameter that represents the index of the list of elements where to start the process.
     * @return a map with the processed elements.
     */
    private Map<String, Object> readOKResponseRec(List<Element> elementChilds, int index) {
	Map<String, Object> res;
	List<Element> auxV;
	Node auxN;
	String nodeValue;

	res = new Hashtable<String, Object>();

	if (elementChilds != null && index < elementChilds.size()) {
	    auxN = (Node) elementChilds.get(index);
	    // Obtenemos los elementos estado y descripcion
	    if (auxN.getNodeType() == Node.ELEMENT_NODE) {
		auxV = UtilsXML.searchChildElements((Element) auxN);
		if (auxV != null && auxV.size() > 0) {
		    res.put(auxN.getNodeName(), readOKResponseRec(auxV, 0));
		} else {
		    nodeValue = UtilsXML.getElementValue((Element) auxN);
		    res.put(((Element) auxN).getTagName(), nodeValue != null ? nodeValue : "");
		    for (int i = 1; i < elementChilds.size(); i++) {
			res.putAll(readOKResponseRec(elementChilds, index + i));
		    }
		}
	    }
	}
	return res;
    }

    /**
     * Method that obtains the XPath of certain element.
     * @return the XPath of certain element.
     */
    private String getXpathRespElement() {
	Properties properties;
	String res;

	properties = TransformersProperties.getMethodParseTransformersProperties(request, method, messageVersion);
	res = properties.getProperty(request + "." + method + "." + messageVersion + "." + TransformersConstants.PARSER_CTE + "." + TransformersConstants.RESP_ROOT_ELEMENT_CTE);

	return res;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#getMethod()
     */
    public final String getMethod() {
	return method;
    }

}
