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
 * <b>File:</b><p>es.gob.afirma.transformers.parseTransformers.DSSParseTransformer.java.</p>
 * <b>Description:</b><p>Method that parses the XML response from the DSS web wervices of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/02/2011.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.transformers.parseTransformers;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.UtilsXML;

/**
 * <p>Method that parses the XML response from the DSS web wervices of @Firma.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public class DSSParseTransformer implements IParseTransformer {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(DSSParseTransformer.class);

    /**
     * Attribute that represents request service name.
     */
    private String request = null;

    /**
     * Attribute that represents message version.
     */
    private String messageVersion = null;

    /**
     * Attribute that represents method of WS.
     */
    private String method = null;

    /**
     * Constructor method for the class DSSParseTransformer.java.
     * @param req Parameter that represents the request.
     * @param methodParam Parameter that represents method name.
     * @param msgVersion Parameter that represents the version of the message.
     */
    public DSSParseTransformer(String req, String methodParam, String msgVersion) {
	super();
	request = req;
	messageVersion = msgVersion;
	method = methodParam;
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
    public final Object transform(String xmlResponse) throws TransformersException {
	Document docTemplate, docResp;
	Map<String, Object> result = null, nodesToParser = null;
	try {
	    // parseamos el xml recibido y la plantilla-guía de parseo
	    docResp = UtilsXML.parseDocument(new StringReader(xmlResponse));
	} catch (Exception e) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.DPT_LOG001), e);
	}
	docTemplate = TransformersFacade.getInstance().getParserTemplateByRequestType(request, method, messageVersion);
	if (docTemplate != null && docResp != null) {
	    // obtenemos los datos (nodos y atributos) de la plantilla que se
	    // extraerán del xml respuesta
	    nodesToParser = getDSSNodesToParser(UtilsXML.searchChildElements(docTemplate.getDocumentElement()));
	    // extraemos información del xml de respuesta
	    result = parseDSSNodes(nodesToParser, docResp.getDocumentElement());
	}
	return result;
    }

    /**
     * Method that retrieves nodes and types for parser XML response by the XML given nodes.
     * @param childNodes Parameter that represents the collection of XML nodes to read.
     * @return a structure of type Map(String/Object) with information for parser XML response.
     */
    private Map<String, Object> getDSSNodesToParser(List<Element> childNodes) {
	Map<String, Object> result = new HashMap<String, Object>();
	for (Element element: childNodes) {
	    // comprobamos si el nodo o sus atributos se añaden
	    if (element.getNodeType() == Node.ELEMENT_NODE && element.getAttributeNode(TransformersConstants.ATTR_XML_NODE_TYPE) != null) {
		String nodeType = element.getAttribute(TransformersConstants.ATTR_XML_NODE_TYPE);
		// comprobamos el tipo del nodo
		if (TransformersConstants.ANODE_TYPE_ATTRIBUTE.equals(nodeType) || TransformersConstants.ANODE_TYPE_ATTR_TEXT.equals(nodeType)) {
		    // Para cada uno de los atributos (separados por coma)
		    // creamos un registro.
		    result.put(UtilsXML.getNodeXPath(element), nodeType + TransformersConstants.TYPES_VALUES_SEPARATOR + element.getAttribute(TransformersConstants.ATTRIBUTES_TO_RETRIEVE));
		} else if (TransformersConstants.ANODE_TYPE_MAP_FIELDS.equals(nodeType)) {
		    // DSSMapNode mapNod = new
		    // DSSMapNode(UtilsXML.getNodeXPath(element));
		    // buscamos los rutas y/o nombres de los nodos empleados
		    // para la clave y el valor del mapa.
		    getMapFields(element, result);
		    continue;
		} else if (TransformersConstants.ANODE_TYPE_SERVERAL.equals(nodeType)) {
		    // si el nodo está repetido (tipo múltiple) se incluye como
		    // clave la ruta completa al mismo, y como valor, se incluye
		    // un mapa de todos sus hijos
		    if (element.getAttributeNode(TransformersConstants.ATTR_XML_OCURRENCE_NAMES) != null) {
			getOcurrenceNodes(element, result);
			continue;
		    }
		} else {
		    result.put(UtilsXML.getNodeXPath(element), nodeType);
		}
	    }
	    // verificamos si tiene hijos
	    if (!UtilsXML.searchChildElements(element).isEmpty()) {
		result.putAll(getDSSNodesToParser(UtilsXML.searchChildElements(element)));
	    }
	}

	return result;
    }

    /**
     * Method that transforms XML nodes with multiple ocurrences (same name) to a map.
     * @param element Parameter that represents the XML element to read.
     * @param result Parameter that represents the map to update.
     */
    private void getOcurrenceNodes(Element element, Map<String, Object> result) {
	String severalNodeNames = element.getAttribute(TransformersConstants.ATTR_XML_OCURRENCE_NAMES);
	List<String> ocurrenceNames = Arrays.asList(severalNodeNames.split(TransformersConstants.SEVERAL_SEPARATOR));
	if (!UtilsXML.searchChildElements(element).isEmpty()) {
	    List<Element> childs = UtilsXML.searchChildElements(element);
	    for (Element child: childs) {
		List<Element> tmpList = new ArrayList<Element>();
		// si el nodo es de tipo repetido
		if (ocurrenceNames.contains(child.getNodeName())) {
		    Element occurrenceNode = UtilsXML.searchChild(element, child.getNodeName());
		    tmpList.add(occurrenceNode);
		    result.put(UtilsXML.getNodeXPath(child), getDSSNodesToParser(tmpList));
		    // si es un nodo de otro tipo
		} else {
		    tmpList.add(child);
		    result.putAll(getDSSNodesToParser(tmpList));
		}

	    }
	}
    }

    /**
     * Method that transforms xml nodes of type mapFields to a map.
     * @param element Parameter that represents the XML element to read.
     * @param result Parameter that represents the map to update.
     */
    private void getMapFields(Element element, Map<String, Object> result) {
	NodeList nl = UtilsXML.getFirstElementNode(element).getChildNodes();
	String key = null, value = null;
	for (int i = 0; nl != null && i < nl.getLength(); i++) {
	    Node tmpNode = nl.item(i);
	    if (tmpNode != null && tmpNode.getNodeType() == Node.ELEMENT_NODE) {
		String attrTmp = ((Element) tmpNode).getAttribute(TransformersConstants.ATTR_XML_NODE_TYPE);
		if (attrTmp != null && attrTmp.equals(TransformersConstants.ANODE_TYPE_FIELD_KEY)) {
		    key = tmpNode.getNodeName();
		} else if (attrTmp != null && attrTmp.equals(TransformersConstants.ANODE_TYPE_FIELD_VALUE)) {
		    value = tmpNode.getNodeName();
		}
	    }
	}
	if (!GenericUtilsCommons.checkNullValues(key, value)) {
	    result.put(UtilsXML.getNodeXPath(element), TransformersConstants.ANODE_TYPE_MAP_FIELDS + TransformersConstants.TYPES_VALUES_SEPARATOR + key + TransformersConstants.SEVERAL_SEPARATOR + value);
	}
    }

    /**
     * Method that parses all nodes given from a XML element.
     * @param nodesToParser Parameter that represents a map with all nodes and types to parser.
     * @param elResponse Parameter that represents the XML element to parse.
     * @return a map with obtained values in the parser process.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> parseDSSNodes(Map<String, Object> nodesToParser, Element elResponse) {
	Map<String, Object> result = new HashMap<String, Object>();
	if (nodesToParser != null && elResponse != null) {

	    // comprobamos si el nodo padre tiene atributos que parsear
	    String attribPath = UtilsXML.getNodeXPath(elResponse);
	    if (nodesToParser.containsKey(attribPath)) {
		setAttributesValuesToMap(elResponse, nodesToParser.get(attribPath).toString(), result);

	    }

	    // exploramos y parseamos los subnodos
	    List<Element> childs = UtilsXML.searchChildElements(elResponse);
	    for (Element element: childs) {
		String nodeXPath = UtilsXML.getNodeXPath(element);
		if (nodesToParser.containsKey(nodeXPath)) {
		    Object nodeType = nodesToParser.get(nodeXPath);
		    if (nodeType instanceof Map) {
			readMapNode((Map<String, Object>) nodeType, nodeXPath, element, result);
		    } else if (nodeType instanceof String) {
			readValueOfNode(nodeType.toString(), nodeXPath, element, result);
		    }
		}
		// exploramos si tiene nodos hijos
		if (!UtilsXML.searchChildElements(element).isEmpty()) {
		    result.putAll(parseDSSNodes(nodesToParser, element));
		}
	    }
	}
	return result;
    }

    /**
     * Method that reads values from a XML node and transforms it to a map.
     * @param nodeType Parameter that represents the type of node to read.
     * @param nodeXPath Parameter that represents the path of the node to find.
     * @param element Parameter that represents the XML element.
     * @param result Parameter that represents the map to update.
     */
    @SuppressWarnings("unchecked")
    private void readMapNode(Map<String, Object> nodeType, String nodeXPath, Element element, Map<String, Object> result) {
	// si es un nodo de tipo múltiple
	List<Object> childrens = UtilsXML.searchListChilds((Element) element.getParentNode(), element.getNodeName());
	if (childrens != null && childrens.size() > 0) {
	    Map<String, Object>[ ] multipleNodes = new HashMap[childrens.size()];
	    for (int i = 0; childrens.size() > i; i++) {
		multipleNodes[i] = parseDSSNodes(nodeType, (Element) childrens.get(i));
	    }
	    result.put(nodeXPath, multipleNodes);
	}
    }

    /**
     * Method that reads values from a XML string node and transforms it to a map.
     * @param nodeType Parameter that represents the type of node to read.
     * @param nodeXPath Parameter that represents the path of the node to find.
     * @param element Parameter that represents the XML element.
     * @param result Parameter that represents the map to update.
     */
    private void readValueOfNode(String nodeType, String nodeXPath, Element element, Map<String, Object> result) {
	// si es un nodo de tipo texto
	if (nodeType.startsWith(TransformersConstants.ANODE_TYPE_TEXT)) {
	    String textValue = UtilsXML.getElementValue(element);
	    result.put(nodeXPath, textValue);
	} else if (nodeType.startsWith(TransformersConstants.ANODE_TYPE_ATTRIBUTE) || nodeType.startsWith(TransformersConstants.ANODE_TYPE_ATTR_TEXT)) {
	    // o es de tipo atributo
	    setAttributesValuesToMap(element, nodeType, result);

	    // si incluye texto además
	    if (nodeType.startsWith(TransformersConstants.ANODE_TYPE_ATTR_TEXT)) {
		String textValue = UtilsXML.getElementValue(element);
		result.put(nodeXPath, textValue);
	    }
	} else if (nodeType.startsWith(TransformersConstants.ANODE_TYPE_MAP_FIELDS)) {
	    // si es un nodo de tipo mapa de campos
	    int index = nodeType.indexOf(TransformersConstants.TYPES_VALUES_SEPARATOR);
	    // extraemos el nombre de la clave y valor del mapa
	    if (index >= 0) {
		String[ ] data = nodeType.substring(index + 1).split(TransformersConstants.SEVERAL_SEPARATOR);
		if (data.length == 2) {
		    String keyTagName = data[0];
		    String valueTagName = data[1];
		    List<Element> elementFields = UtilsXML.searchChildElements(element);
		    Map<String, String> mapFields = new HashMap<String, String>();
		    for (Element tmpField: elementFields) {
			// obtenemos el par de campos identidad-valor
			mapFields.put(UtilsXML.getElementValue(tmpField, keyTagName), UtilsXML.getElementValue(tmpField, valueTagName));
		    }
		    result.put(nodeXPath, mapFields);
		}
	    }
	} else if (nodeType.startsWith(TransformersConstants.ANODE_TYPE_XML)) {
	    result.put(nodeXPath, readXmlContent(nodeXPath, element));
	}
    }

    /**
     * Method that reads the XML content of a node.
     * @param nodeXPath Parameter that represents the path of the node to find.
     * @param element Parameter that represents the XML element.
     * @return the content of the XML element.
     */
    private String readXmlContent(String nodeXPath, Element element) {
	try {
	    return UtilsXML.transformDOMtoString(element, true);
	} catch (TransformersException e) {
	    LOGGER.warn(Language.getFormatResIntegra(ILogConstantKeys.DPT_LOG002, new Object[ ] { nodeXPath }), e);
	    return UtilsXML.getElementValue(element);
	}

    }

    /**
     * Method that adds element attributes to response map.
     * @param element Parameter that represents the XML element.
     * @param attrKeys Parameter that represents the names of the attributes separated with a coma.
     * @param nodesValues Parameter that represents the map with the values of the nodes of the response.
     */
    private void setAttributesValuesToMap(Element element, String attrKeys, Map<String, Object> nodesValues) {
	if (attrKeys != null && nodesValues != null) {

	    int index = attrKeys.indexOf(TransformersConstants.TYPES_VALUES_SEPARATOR);
	    // extraemos todos los atributos y, por cada uno, creamos un
	    // registro (clave-valor)
	    if (index >= 0) {
		String attributeNames = attrKeys.substring(index + 1);
		String[ ] data = attributeNames.split(TransformersConstants.SEVERAL_SEPARATOR);
		for (String attName: data) {
		    String attributeValue = UtilsXML.getAttributeValue(element, attName);
		    if (attributeValue != null && attributeValue.trim().length() > 0) {
			nodesValues.put(UtilsXML.getNodeXPath(element) + TransformersConstants.ATTRIBUTE_SEPARATOR + attName, attributeValue);
		    }
		}
	    }
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.transformers.parseTransformers.IParseTransformer#getMethod()
     */
    public final String getMethod() {
	return method;
    }

}
