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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsXML.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of XML elements.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 09/02/2011.
 */
package es.gob.afirma.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xml.utils.DefaultErrorHandler;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;

/**
 * <p>Class that contains methods related to the manage of XML elements.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 09/02/2011.
 */
public final class UtilsXML {

	/**
	 *  Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsXML.class);

	/**
	 * Attribute that represents a factory API to obtain a parser that produces DOM object trees from XML documents.
	 */
	private static DocumentBuilderFactory dbf = null;

	static {
		try {
			dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			dbf.setIgnoringComments(true);
		} catch (Exception e) {}
	}

	/**
	 * Constructor method for the class UtilsXML.java.
	 */
	private UtilsXML() {
	}

	/**
	 * Method that obtains a XML document from an input stream.
	 * @param input Parameter that represents the input stream.
	 * @return an object that represents the XML document.
	 * @throws TransformersException If the method fails.
	 */
	public static Document parseDocument(Reader input) throws TransformersException {
		// obtiene el DOM parser y un resolver y document builder
		// asociado
		DOMParser parser = new DOMParser();
		// parsear
		try {
			parser.parse(new InputSource(input));
		} catch (SAXException e) {
			throw new TransformersException(e);
		} catch (IOException e) {
			throw new TransformersException(e);
		}

		// devuelve el documento parseado
		return parser.getDocument();
	}

	/**
	 * Method that obtains the value of a XML element.
	 * @param e Parameter that represents the XML element.
	 * @return the value of the XML element, or <code>null</code> if the XML element hasn't any value.
	 */
	public static String getElementValue(Element e) {
		String result;
		if (e == null || e.getFirstChild() == null) {
			result = null;
		} else if (e.getFirstChild().getNodeType() == Node.TEXT_NODE || e.getFirstChild().getNodeType() == Node.CDATA_SECTION_NODE) {
			result = e.getFirstChild().getNodeValue(); // getFirstChild debería
			// ser el #text#
		} else {
			result = null;
		}
		return result;
	}

	/**
	 * Method that obtains the value of a child element from a parent element. The child element must be localized on the first level of the hierarchical
	 * child structure.
	 * @param e Parameter that represents the parent element.
	 * @param elementName Parameter that represents the name of the child element.
	 * @return the value of the child element or <code>null</code> if the element hasn't any value or the child element doesn't exist.
	 */
	public static String getElementValue(Element e, String elementName) {
		String v;
		try {
			// Separamos por '/' y vamos buscando descendientes
			StringTokenizer stk = new StringTokenizer(elementName, GeneralConstants.PATH_DELIMITER);
			Element eAux = e;
			while (eAux != null && stk.hasMoreElements()) {
				String nombreNodo = (String) stk.nextElement();
				NodeList nl = eAux.getChildNodes();
				int i = 0;
				boolean encontrado = false;
				Node nodo = null;
				Node nodoAux = null;
				while (!encontrado && i < nl.getLength()) {
					nodoAux = nl.item(i);
					if (nodoAux.getNodeType() == Node.ELEMENT_NODE && ((Element) nodoAux).getTagName().equals(nombreNodo)) {
						encontrado = true;
						nodo = nodoAux;
					}
					i++;
				}
				if (nodo == null) {
					eAux = null;
				} else {
					// Next node
					eAux = (Element) nodo;
				}
			}
			v = getElementValue(eAux);
		} catch (NoSuchElementException ex) {
			v = null;
		}
		return v;
	}

	/**
	 * Method that obtains the child element from a parent element. The child element must be localized on the first level of the hierarchical
	 * child structure.
	 * @param element Parameter that represents the parent element.
	 * @param elementName Parameter that represents the name of the child element.
	 * @return the child element or <code>null</code> if the child element doesn't exist.
	 */
	public static Element getElement(Element element, String elementName) {
		try {
			Element e = element;
			// Separamos por '/' y vamos buscando descendientes
			StringTokenizer stk = new StringTokenizer(elementName, GeneralConstants.PATH_DELIMITER);
			while (e != null && stk.hasMoreElements()) {
				NodeList nl = e.getElementsByTagName((String) stk.nextElement());
				if (nl == null || nl.getLength() < 1) {
					e = null;
				} else {
					// Next node
					e = (Element) nl.item(0);
				}
			}
			return e;
		} catch (NoSuchElementException ex) {
			return null;
		}
	}

	/**
	 * Method that searches a child element from a parent element.
	 * @param e Parameter that represents the parent element.
	 * @param childName Parameter that represents the name of the child element to find.
	 * @return the child element or <code>null</code> if the child element doesn't exist.
	 */
	public static Element searchChild(Element e, String childName) {
		Element encontrado;
		Element eAux = e;
		try {
			// Separamos por '/' y vamos buscando descendientes
			StringTokenizer stk = new StringTokenizer(childName, GeneralConstants.PATH_DELIMITER);
			while (eAux != null && stk.hasMoreElements()) {
				NodeList nl = eAux.getElementsByTagName((String) stk.nextElement());
				if (nl == null || nl.getLength() < 1) {
					eAux = null;
				} else {
					// Next node
					eAux = (Element) nl.item(0);
				}
			}
			encontrado = eAux;
		} catch (NoSuchElementException ex) {
			encontrado = null;
		}
		return encontrado;
	}

	/**
	 * Method that obtains a list with the child elements localized on the first level of the hierarchical child structure from a parent element.
	 * @param e Parameter that represents the parent element.
	 * @param childElementName Parameter that represents the name of the child elements to find.
	 * @return the list with the found child elements.
	 */
	public static List<Object> searchListChilds(Element e, String childElementName) {
		List<Object> v = null;
		try {
			// if(v==null) {
			// v = new ArrayList<Object>();
			// }
			v = new ArrayList<Object>();
			// Vemos si es un elemento terminal buscando una /
			int posicion = childElementName.indexOf('/');
			if (posicion == -1) {
				// Es un nodo terminal
				NodeList nl = e.getChildNodes();
				int i = 0;
				// boolean encontrado = false;
				Node nodo = null;
				while (i < nl.getLength()) {
					nodo = nl.item(i);
					if (nodo.getNodeType() == Node.ELEMENT_NODE && ((Element) nodo).getTagName().equals(childElementName)) {
						v.add(nodo);
					}
					i++;
				}
			} else {
				// No es un nodo terminal
				String nombreNodo = childElementName.substring(0, posicion);
				NodeList nl = e.getChildNodes();
				int i = 0;
				Node nodo = null;
				// Node nodoAux = null;
				while (i < nl.getLength()) {
					nodo = nl.item(i);
					if (nodo.getNodeType() == Node.ELEMENT_NODE && ((Element) nodo).getTagName().equals(nombreNodo)) {
						v.addAll(searchListChilds((Element) nodo, childElementName.substring(posicion + 1)));
					}
					i++;
				}
			}
		} catch (NoSuchElementException ex) {
			// nada para que no de error;
		}
		return v;
	}

	/**
	 * Method that obtains a list with the child elements from a parent element.
	 * @param e Parameter that represents the parent element.
	 * @return the list with the found child elements.
	 */
	public static List<Element> searchChildElements(Element e) {
		List<Element> v = new ArrayList<Element>();
		try {
			// Es un nodo terminal
			NodeList nl = e.getChildNodes();
			int indice = 0;
			while (indice < nl.getLength()) {
				if (nl.item(indice) instanceof Element) {
					v.add((Element) nl.item(indice));
				}
				indice++;
			}
		} catch (NoSuchElementException ex) {
			// nada para que no de error;
		}
		return v;
	}

	/**
	 * Method that creates a child element from a parent element.
	 * @param e Parameter that represents the parent element.
	 * @param childName Parameter that represents the name of the element to create.
	 * @return the new child element.
	 */
	public static Element createChild(Element e, String childName) {
		Element nuevoE = null;
		if (childName != null) {
			nuevoE = e.getOwnerDocument().createElement(childName);
			nuevoE = (Element) e.appendChild(nuevoE);
		}
		return nuevoE;
	}

	/**
	 * Method that checks if a element exists from a parent element.
	 * @param e Parameter that represents the parent element.
	 * @param elementName Parameter that represents the name of the element to check.
	 * @return a boolean that indicates if the element exists (true) or not (false).
	 */
	public static boolean existsElement(Element e, String elementName) {
		Element elem = e;
		if (elementName == null) {
			return false;
		}
		if (elem == null) {
			return false;
		}
		try {
			// Separamos por '/' y vamos buscando descendientes
			StringTokenizer stk = new StringTokenizer(elementName, GeneralConstants.PATH_DELIMITER);
			while (elem != null && stk.hasMoreElements()) {
				NodeList nl = elem.getElementsByTagName((String) stk.nextElement());
				if (nl == null || nl.getLength() < 1) {
					return false;
				} else {
					elem = (Element) nl.item(0);
				}
			}
			return elem != null;
		} catch (NoSuchElementException ex) {}
		return false;
	}

	/**
	 * Method that deletes a child element from a parent element.
	 * @param e Parameter that represents the parent element.
	 * @param elementName Parameter that represents the name of the element to remove.
	 * @return the removed element, or <code>null</code> if the element cannot be removed.
	 */
	public static Element removeElement(Element e, String elementName) {
		if (elementName == null) {
			return null;
		}
		if (e == null) {
			return null;
		}
		Element removed = null;
		Element originalElement = e;
		Element eAux = e;
		try {
			// Separamos por '/' y vamos buscando descendientes
			StringTokenizer stk = new StringTokenizer(elementName, GeneralConstants.PATH_DELIMITER);
			while (eAux != null && stk.hasMoreElements()) {
				NodeList nl = eAux.getElementsByTagName((String) stk.nextElement());
				if (nl == null || nl.getLength() < 1) {
					return null;
				} else {
					originalElement = eAux;
					eAux = (Element) nl.item(0);
				}
			}
			removed = (Element) originalElement.removeChild(eAux);
		} catch (NoSuchElementException ex) {
			removed = null;
		}
		return removed;
	}

	/**
	 * Method that replaces an element with a new value. If the element doesn't exist previously, the method creates it.
	 * @param e Parameter that represents the parent element.
	 * @param elementName Parameter that represents the name of the element to replace.
	 * @param elementValue Parameter that represents the new value of the element.
	 * @return the parent element with the new child element.
	 */
	public static Element replaceElementValue(Element e, String elementName, String elementValue) {
		Element elementoInsertado = null;

		if (existsElement(e, elementName)) {
			removeElement(e, elementName);
		}

		elementoInsertado = createElementValue(e, elementName, elementValue);

		return elementoInsertado;
	}

	/**
	 * Method that creates a new element as a child of a parent element.
	 * @param e Parameter that represents the parent element.
	 * @param elementName Parameter that represents the name of the element to create.
	 * @param elementValue Parameter that represents the value of the element to create.
	 * @return the parent element with the new child element.
	 */
	public static Element createElementValue(Element e, String elementName, String elementValue) {
		if (GenericUtilsCommons.checkNullValues(elementName, e)) {
			return null;
		}
		Element eAux = e;
		try {
			// Separamos por '/' y vamos buscando descendientes
			StringTokenizer stk = new StringTokenizer(elementName, GeneralConstants.PATH_DELIMITER);
			while (eAux != null && stk.hasMoreElements()) {
				String name = (String) stk.nextElement();
				NodeList nl = eAux.getElementsByTagName(name);
				if (nl == null || nl.getLength() < 1) {
					createChild(eAux, name);// Creo el hijo si es necesario
					nl = eAux.getElementsByTagName(name);// Vuelvo a buscar
					if (nl == null || nl.getLength() < 1) {
						return null;// No se introdujo el elemento por alguna
						// razon
					}
					// e=eAux;
					eAux = (Element) nl.item(0);
				} else {
					// e=eAux;
					eAux = (Element) nl.item(0);
				}
			}
			if (elementValue != null) {
				Node tx = eAux.getOwnerDocument().createTextNode(elementValue);
				eAux.appendChild(tx);
			}
			return eAux;
		} catch (NoSuchElementException ex) {}
		return null;
	}

	/**
	 * Method that obtains a string with the values of a XML element.
	 * @param xmlElement Parameter that represents the XML element.
	 * @param rootName Parameter that represents the name of the root element. It cannot be <code>null</code>.
	 * @param asAttributes Parameter that indicates if the values of the XML element must be defined as attributes (true) or as elements (false).
	 * @return the generated string.
	 * @throws TransformersException If the method fails.
	 */
	public static String toXMLString(Object xmlElement, String rootName, boolean asAttributes) throws TransformersException {
		StringBuffer resultado = new StringBuffer();
		if (xmlElement != null) {
			// Comienzo de documento
			if (asAttributes) {
				resultado.append("<");
				resultado.append(rootName);
			} else {
				resultado.append("<");
				resultado.append(rootName);
				resultado.append(">");
			}
			// Sacamos todos los campos
			StringBuffer camposNoSimples = extractFields(xmlElement, resultado, asAttributes);
			if (camposNoSimples != null) {
				if (asAttributes) {
					resultado.append(">");// Se cierra el padre
				}
				resultado.append(camposNoSimples);// Se incluyen los campos no
				// simples
			}
			// Fin de documento
			if (asAttributes && camposNoSimples == null) {
				resultado.append(" />");
			} else {
				resultado.append("</" + rootName + ">");
			}
		}
		return resultado.toString();
	}

	/**
	 * Method that obtains the fields from a XML element to obtains a string.
	 * @param xmlElement Parameter that represents the XML element.
	 * @param result Parameter that represents the representation of the XML element as a string.
	 * @param asAttributes Parameter that indicates if the values of the XML element must be defined as attributes (true) or as elements (false).
	 * @return the fields of the XML element as a string.
	 * @throws TransformersException If the method fails.
	 */
	private static StringBuffer extractFields(Object xmlElement, StringBuffer result, boolean asAttributes) throws TransformersException {
		Class<? extends Object> clase = xmlElement.getClass();
		// Se prepara para formatear números
		DecimalFormatSymbols dfs = new DecimalFormatSymbols();
		dfs.setDecimalSeparator(',');
		dfs.setGroupingSeparator('.');
		DecimalFormat dfImporte = new DecimalFormat("#,##0.00", dfs);
		StringBuffer camposNoSimples = null;
		Object valor = null;
		String nombre = null;
		try {
			Field[ ] campos = clase.getFields();
			for (int i = 0; i < campos.length; i++) {
				if (!Modifier.isStatic(campos[i].getModifiers())) {
					// No se meten los static por ser constantes.
					valor = campos[i].get(xmlElement);
					nombre = campos[i].getName();
					if (valor != null) {
						if (esCampoSimple(campos[i].getType().getName())) {
							if (asAttributes) {
								result.append(" " + nombre + "=\"");
							} else {
								result.append("<" + nombre + ">");
							}
							result.append(valorCampo(xmlElement, campos[i], valor, dfImporte));
							if (asAttributes) {
								result.append("\"");
							} else {
								result.append("</" + nombre + ">");
							}
						} else {
							if (camposNoSimples == null) {
								camposNoSimples = new StringBuffer();
							}
							camposNoSimples.append(toXMLString(valor, nombre, asAttributes));
						}
					}
				}
			}
		} catch (IllegalAccessException e) {
			throw new TransformersException(e);
		}
		return camposNoSimples;
	}

	/**
	 * Method that obtains the XML representation of an attribute.
	 * @param objeto Parameter that represents the XML element.
	 * @param campo Parameter that represents the field of the XML element.
	 * @param valor Parameter that represents the value of the XML element.
	 * @param dfImporte Parameter that represents the format for decimal values.
	 * @return the XML representation
	 * @throws TransformersException If the method fails.
	 */
	private static String valorCampo(Object objeto, Field campo, Object valor, DecimalFormat dfImporte) throws TransformersException {

		String resultado = "";
		try {
			if (campo != null && valor != null) {
				String nombreTipo = campo.getType().getName();
				if (nombreTipo.equals("double")) {
					resultado = dfImporte.format(campo.getDouble(objeto));
				} else {
					resultado = String.valueOf(valor);
				}
			}
		} catch (IllegalAccessException e) {
			throw new TransformersException(e);
		}
		return resultado;
	}

	/**
	 * Method that indicates if a field has a simple type (true) or it has to be decomposed (false).
	 * @param nombreTipo Parameter that represents the name of the field type.
	 * @return a boolean that indicates if a field has a simple type (true) or it has to be decomposed (false).
	 */
	private static boolean esCampoSimple(String nombreTipo) {
		if (nombreTipo.equals("double") || nombreTipo.equals("short") || nombreTipo.equals("int") || nombreTipo.equals("long")) {
			return true;
		} else if (nombreTipo.equals("boolean") || nombreTipo.equals("java.lang.Short") || nombreTipo.equals("java.lang.Integer")) {
			return true;
		} else if (nombreTipo.equals("java.lang.Double") || nombreTipo.equals("java.lang.String")) {
			return true;
		}
		return false;

	}

	/**
	 * Method that generates a string with XML format from a DOM tree structure.
	 * @param xmlElement Parameter that represents the XML element to process.
	 * @param omitXmlDeclaration Parameter that specifies whether the XSLT processor should output an XML declaration (true) or not (false).
	 * @return the generated string.
	 * @throws TransformersException If the method fails.
	 */
	public static String transformDOMtoString(Element xmlElement, boolean omitXmlDeclaration) throws TransformersException {
		String res;
		try {
			StringWriter strWtr = new StringWriter();
			StreamResult strResult = new StreamResult(strWtr);
			TransformerFactory tfac = TransformerFactory.newInstance();

			Transformer trans = tfac.newTransformer();
			trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, omitXmlDeclaration ? "yes" : "no");
			trans.transform(new DOMSource(xmlElement), strResult);
			res = strResult.getWriter().toString();
		} catch (Exception e) {
			throw new TransformersException(Language.getResIntegra(ILogConstantKeys.UXML_LOG001), e);
		}
		return res;
	}

	/**
	 * Method that generates a string with XML format from a XML document.
	 * @param doc Parameter that represents the XML document.
	 * @return the generated string.
	 * @throws TransformersException If the method fails.
	 */
	public static String transformDOMtoString(Document doc) throws TransformersException {
		return transformDOMtoString(doc.getDocumentElement(), false);
	}

	/**
	 * Method that removes all the nodes and tags not used from a parent XML element. The method find all <code>afirmaNodeType</code> nodes and deletes them
	 * whether the type is equal than one of the indicated types.
	 * @param xmlNode Parameter that represents the parent XML element.
	 * @param optionalNodeTypes Parameter that represents the array with the types of the nodes to remove.
	 */
	public static void deleteNodesNotUsed(Element xmlNode, String[ ] optionalNodeTypes) {
		if (xmlNode == null) {
			return;
		}
		NodeList nodelist = xmlNode.getChildNodes();
		// buscamos todos los elementos hijos de tipo NODO o etiqueta
		for (int index = 0; index < nodelist.getLength(); index++) {
			Node node = nodelist.item(index);
			if (Node.ELEMENT_NODE != node.getNodeType()) {
				continue;
			}
			boolean eraseNode = false;
			// buscamos los atributos de cada etiqueta
			if (node.hasAttributes()) {
				NamedNodeMap nNMap = node.getAttributes();
				for (int i = 0; i < nNMap.getLength(); i++) {
					Node attribute = nNMap.item(i);
					// localizamos tipo de atributo para determinar si se borra
					// el nodo
					if (isDeletedNode(attribute, optionalNodeTypes)) {
						eraseNode = true;
					}
				}
			}
			if (eraseNode) {
				node.getParentNode().removeChild(node);
			} else {
				if (node.hasChildNodes()) {
					deleteNodesNotUsed((Element) node, optionalNodeTypes);
				}
			}

		}
	}

	/**
	 * Method that indicates whether a node has been deleted.
	 * @param attribute Parameter that represents the node to delete.
	 * @param optionalNodeTypes Parameter that represents the array with the types of the nodes to delete.
	 * @return a boolean that indicates whether the nodes has been removed (true) or not (false).
	 */
	private static boolean isDeletedNode(Node attribute, String[ ] optionalNodeTypes) {
		if (Node.ATTRIBUTE_NODE == attribute.getNodeType() && TransformersConstants.ATTR_XML_NODE_TYPE.equals(attribute.getNodeName())) {
			for (String type: optionalNodeTypes) {
				if (attribute.getNodeValue() != null && attribute.getNodeValue().equals(type)) {
					return true;
				}
			}
			// eliminamos el tipo de atributo @firma innecesario para el xml
			// resultante
			// ((Element)
			// attribute.getParentNode()).removeAttribute(attribute.getNodeName());
			((Attr) attribute).getOwnerElement().removeAttribute(attribute.getNodeName());
		}
		return false;
	}

	/**
	 * Method that removes the all <code>afirmaNodeType</code> nodes from a parent XML element.
	 * @param element Parameter that represents the parent XML element.
	 */
	public static void removeAfirmaAttribute(Element element) {
		if (element != null && element.hasAttributes()) {
			NamedNodeMap nNMap = element.getAttributes();
			for (int i = 0; i < nNMap.getLength(); i++) {
				Node attribute = nNMap.item(i);
				if (Node.ATTRIBUTE_NODE == attribute.getNodeType() && TransformersConstants.ATTR_XML_NODE_TYPE.equals(attribute.getNodeName())) {
					element.removeAttribute(attribute.getNodeName());
				}
			}
		}
	}

	/**
	 * Method that adds an attribute to certain node.
	 * @param xmlNode Parameter that represents the node.
	 * @param attributePath Parameter that represents the path of the attribute name.
	 * @param value Parameter that represents the value of the attribute.
	 * @return the updated XML element.
	 */
	public static Element insertAttributeValue(Element xmlNode, String attributePath, String value) {
		if (GenericUtilsCommons.checkNullValues(xmlNode, attributePath, value) || attributePath.trim().length() == 0 || value.trim().length() == 0) {
			return null;
		}
		// obtenemos el atributo a buscar.
		String[ ] data = attributePath.split(TransformersConstants.ATTRIBUTE_SEPARATOR);
		if (data.length < 2) {
			LOGGER.warn(Language.getFormatResIntegra(ILogConstantKeys.UXML_LOG002, new Object[ ] { attributePath, xmlNode.getNodeName() }));
			return null;
		}
		String nodePath = data[0];
		String attributeName = data[1];

		Element eAux = findNode(nodePath, xmlNode);
		if (eAux != null) {
			eAux.setAttribute(attributeName, value);
			removeAfirmaAttribute(eAux);
		}
		return eAux;

	}

	/**
	 * Method that searchs a node from a parent element by XPath path.
	 * @param nodePath Parameter that represents the XPath path.
	 * @param xmlNode Parameter that represents the parent element.
	 * @return the found element.
	 */
	private static Element findNode(String nodePath, Element xmlNode) {
		StringTokenizer stk = new StringTokenizer(nodePath, GeneralConstants.PATH_DELIMITER);
		Element eAux = xmlNode;
		while (eAux != null && stk.hasMoreElements()) {
			removeAfirmaAttribute(eAux);
			String tagName = (String) stk.nextElement();
			NodeList nl = eAux.getElementsByTagName(tagName);

			if (nl == null || nl.getLength() < 1) {
				createChild(eAux, tagName);// Creo el hijo si es necesario
				nl = eAux.getElementsByTagName(tagName);// Vuelvo a buscar
				if (nl == null || nl.getLength() < 1) {
					return null;// No se introdujo el elemento por alguna razon
				}
				// xmlNode = eAux;
				eAux = (Element) nl.item(0);

			} else {
				eAux = (Element) nl.item(0);
			}
		}
		return eAux;
	}

	/**
	 * Method that inserts a element as a child into a XML element.
	 * @param element Parameter that represents the parent XML element.
	 * @param elementName Parameter that represents the name of the element to insert.
	 * @param value Parameter that represents the value of the element to insert.
	 * @return the parent XML element with the new child element.
	 */
	public static Element insertValueElement(Element element, String elementName, String value) {
		if (GenericUtilsCommons.checkNullValues(element, elementName, value)) {
			return null;
		}
		Element eAux = element;
		// Separamos por '/' y vamos buscando descendientes
		StringTokenizer stk = new StringTokenizer(elementName, GeneralConstants.PATH_DELIMITER);
		while (eAux != null && stk.hasMoreElements()) {
			removeAfirmaAttribute(eAux);
			String name = (String) stk.nextElement();
			NodeList nl = eAux.getElementsByTagName(name);
			if (nl == null || nl.getLength() < 1) {
				createChild(eAux, name);// Creo el hijo si es necesario
				nl = eAux.getElementsByTagName(name);// Vuelvo a buscar
				if (nl == null || nl.getLength() < 1) {
					return null;// No se introdujo el elemento por alguna razon
				}
				// elementSrc = eAux;
				eAux = (Element) nl.item(0);
			} else {
				// elementSrc = eAux;
				eAux = (Element) nl.item(0);
			}
		}
		if (eAux != null) {
			Node newNode;
			// Se comprueba si es un documento XML
			Document xmlDoc = UtilsXML.parseXMLDocument(value);
			if (xmlDoc == null) { // Si no es un documento XML, se incluye como
				// nodo-texto.
				newNode = eAux.getOwnerDocument().createTextNode(value);
			} else { // En caso de ser un documento XML, se incluye como un nodo
				// de tipo Element (un xml dentro de otro).
				newNode = eAux.getOwnerDocument().adoptNode(xmlDoc.getDocumentElement());
			}
			eAux.appendChild(newNode);
			removeAfirmaAttribute(eAux);
		}
		return eAux;
	}

	/**
	 * Method that obtains the value of an attribute of a XML element.
	 * @param element Parameter that represents the parent XML element.
	 * @param elementPath Parameter that represents the XPath path of the element to find.
	 * @param attributeName Parameter that represents the name of the attribute to find.
	 * @return the value of the attribute.
	 */
	public static String getAttributeValue(Element element, String elementPath, String attributeName) {
		String value = null;
		if (element != null && elementPath != null && attributeName != null) {
			Element tmpElement = getElement(element, elementPath);
			value = tmpElement.getAttribute(attributeName);
		}
		return value;
	}

	/**
	 * Method that obtains the value of an attribute of a XML element.
	 * @param element Parameter that represents the parent XML element.
	 * @param attributeName Parameter that represents the name of the attribute to find.
	 * @return the value of the attribute.
	 */
	public static String getAttributeValue(Element element, String attributeName) {
		return getAttributeValue(element, "", attributeName);
	}

	/**
	 * Method that obtains the relative path of a child node from a parent node.
	 * @param nodeChild Parameter that represents the child node.
	 * @param parent Parameter that represents the parent node.
	 * @return the relative path of the child node.
	 */
	public static String getRelativeXPath(Node nodeChild, Node parent) {
		String result = null;
		if (nodeChild != null) {
			result = nodeChild.getNodeName();
			if (nodeChild.getParentNode() != null) {
				Node auxEl = nodeChild.getParentNode();
				while (auxEl.getParentNode() != null && !auxEl.equals(parent)) {
					result = auxEl.getNodeName() + GeneralConstants.PATH_DELIMITER + result;
					auxEl = auxEl.getParentNode();
				}
			}
		}
		return result;
	}

	/**
	 * Method that obtains the absolute path of a node.
	 * @param node Parameter that represents the node.
	 * @return the absolute path of the node.
	 */
	public static String getNodeXPath(Node node) {
		return getRelativeXPath(node, node.getOwnerDocument().getDocumentElement());
	}

	/**
	 * Method that obtains the first child XML element from a parent element.
	 * @param element Parameter that represents the parent element.
	 * @return the found child XML element.
	 */
	public static Element getFirstElementNode(Element element) {
		NodeList nl = element.getChildNodes();
		for (int i = 0; 0 < nl.getLength(); i++) {
			if (Node.ELEMENT_NODE == nl.item(i).getNodeType()) {
				return (Element) nl.item(i);
			}
		}
		return null;
	}

	/**
	 * Method that obtains a {@link Document} object from an input stream.
	 * @param is Parameter that represents the input stream.
	 * @return the {@link Document} object associated.
	 * @throws TransformerException If the method fails.
	 */
	public static Document getDocument(InputStream is) throws TransformerException {
		javax.xml.parsers.DocumentBuilder db = null;

		try {
			db = dbf.newDocumentBuilder();

			return db.parse(is);
		} catch (Exception e) {
			throw new TransformerException(e.getMessage(), e);
		}
	}

	/**
	 * Method that instancies a new {@link Document} object.
	 * @return a new {@link Document} object.
	 * @throws ParserConfigurationException If the method fails.
	 */
	public static Document newDocument() throws ParserConfigurationException {
		javax.xml.parsers.DocumentBuilder db = null;
		db = dbf.newDocumentBuilder();
		return db.newDocument();
	}

	/**
	 * Method that obtains a {@link Document} object from an input stream and validates XML document against an XSD schema.
	 * @param xsdSchema xsd schema definition.
	 * @param xml xml to convert.
	 * @return the {@link Document} object.
	 * @throws TransformersException If the process fails.
	 */
	public static Document getDocumentWithXsdValidation(File xsdSchema, InputStream xml) throws TransformersException {
		// Constantes para validacion de Schemas
		final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
		final String JAXP_SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";
		final String W3C_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";

		// Creamos la factoria e indicamos que hay validacion
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		documentBuilderFactory.setValidating(true);

		try {

			// Configurando el Schema de validacion
			documentBuilderFactory.setAttribute(JAXP_SCHEMA_LANGUAGE, W3C_XML_SCHEMA);
			documentBuilderFactory.setAttribute(JAXP_SCHEMA_SOURCE, xsdSchema);

			// Parseando el documento
			DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
			documentBuilder.setErrorHandler(new DefaultErrorHandler());

			return documentBuilder.parse(xml);

		} catch (SAXException e) {
			throw new TransformersException(e);
		} catch (IOException e) {
			throw new TransformersException(e);
		} catch (ParserConfigurationException e) {
			throw new TransformersException(e);
		}
	}

	/**
	 * Parse a XML Document to a {@link Document} instance.
	 * @param xml string with XML content.
	 * @return a {@link Document document} instance if the string given is a XML document or null otherwise.
	 */
	public static Document parseXMLDocument(String xml) {
		Document result = null;
		if (GenericUtilsCommons.assertStringValue(xml)) {
			String xmlWithoutSpaces = xml.trim();
			if (xmlWithoutSpaces.startsWith("<") && xmlWithoutSpaces.endsWith(">")) {
				try {
					result = UtilsXML.getDocument(new ByteArrayInputStream(xmlWithoutSpaces.getBytes()));
				} catch (TransformerException e) {}
			}
		}
		return result;
	}

	/**
	 * Method that obtains certain element as a child of a parent element.
	 * @param parentElement Parameter that represents the parent element.
	 * @param childElementName Parameter that represents the name of the element to find.
	 * @param signatureId Parameter that represents the <code>Id</code> attribute of the signature.
	 * @param isRequired Parameter that indicates whether the elements is required (true) or not (false).
	 * @return an object that represents the found element, or <code>null</code>.
	 */
	public static Element getChildElement(Element parentElement, String childElementName, String signatureId, boolean isRequired) throws SigningException {
		Element result = null;

		// Si se han indicado el elemento padre y el nombre del elemento hijo
		// que obtener
		if (parentElement != null && childElementName != null) {
			// Obtenemos todos los elementos hijos del elemento padre
			NodeList childNodes = parentElement.getChildNodes();

			// Recorremos la lista de elementos hijos hasta encontrar el
			// solicitado
			int i = 0;
			while (i < childNodes.getLength() && result == null) {
				// Accedemos al elemento hijo
				Node childNode = childNodes.item(i);

				// Comprobamos si es el elemento buscado
				if (childNode.getNodeType() == Node.ELEMENT_NODE && childNode.getLocalName().equals(childElementName)) {
					result = (Element) childNode;
				}
				i++;
			}
			if (result == null && isRequired) {
				String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.UXML_LOG003, new Object[ ] { signatureId, parentElement.getLocalName(), childElementName });
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg);
			}
		}

		return result;
	}

	/**
	 * Method that obtains certain elements as childs of a parent element.
	 * @param parentElement Parameter that represents the parent element.
	 * @param childElementName Parameter that represents the name of the element to find.
	 * @return a list with the found elements.
	 */
	public static List<Element> getChildElements(Element parentElement, String childElementName) {
		List<Element> result = new ArrayList<Element>();

		// Si se han indicado el elemento padre y el nombre de los elementos
		// hijos que obtener
		if (parentElement != null && childElementName != null) {
			// Obtenemos todos los elementos hijos del elemento padre
			NodeList childNodes = parentElement.getChildNodes();

			// Recorremos la lista de elementos hijos buscando los elementos
			// solicitados
			for (int i = 0; i < childNodes.getLength(); i++) {
				// Accedemos al elemento hijo
				Node childNode = childNodes.item(i);

				// Comprobamos si es uno de los elementos buscado
				if (childNode.getNodeType() == Node.ELEMENT_NODE && childNode.getLocalName().equals(childElementName)) {
					result.add((Element) childNode);
				}
			}
		}

		return result;
	}

	/**
	 * Method that obtains a list with the child elements localized in certain <code>local-name</code> path for certain root element.
	 * @param element Parameter that represents the root element.
	 * @param path Parameter that represents the path.
	 * @return a list with the child elements localized in the <code>local-name</code> path for the root element.
	 * @throws XPathExpressionException If some expression cannot be evaluated
	 */
	public static NodeList getChildNodesByLocalNames(Node element, String path) throws XPathExpressionException {
		String[ ] localNames = path.split("/");
		String xpath = ".";
		for (int i = 0; i < localNames.length; i++) {
			xpath = xpath + "/*[local-name()='" + localNames[i] + "']";
		}
		XPath x = XPathFactory.newInstance().newXPath();
		return (NodeList) x.evaluate(xpath, element, XPathConstants.NODESET);
	}
}
