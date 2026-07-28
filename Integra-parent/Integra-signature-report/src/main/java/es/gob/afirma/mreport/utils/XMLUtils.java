// Copyright (C) 2018, Gobierno de España
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
 * <b>File:</b><p>es.gob.signaturereport.tools.XMLUtils.java.</p>
 * <b>Description:</b><p>Class contains utilities for processing XML.</p>
 * <b>Project:</b><p>Horizontal platform to generation signature reports in legible format.</p>
 * <b>Date:</b><p>10/02/2011.</p>
 * @author Spanish Government.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.mreport.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import es.gob.afirma.mreport.logger.Logger;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.CDATASection;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;

import es.gob.afirma.mreport.exceptions.UtilsException;
import es.gob.afirma.mreport.i18.ILogConstantKeys;
import es.gob.afirma.mreport.i18.Language;

/**
 * <p>Class contains utilities for processing XML.</p>
 * <b>Project:</b><p>Horizontal platform to generation signature reports in legible format.</p>
 * @version 1.0, 10/02/2011.
 */
public final class XMLUtils {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(XMLUtils.class);

	/**
	 * Attribute that defines a factory API that enables applications to obtain a
	 * parser that produces DOM object trees from XML documents .
	 */
	private static javax.xml.parsers.DocumentBuilderFactory dbf = null;

	static {
		try {
			dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			dbf.setIgnoringComments(true);
		} catch (Exception e) {
			LOGGER.error(Language.getResSigReport(ILogConstantKeys.UTIL_001), e);
		}
	}

	/**
	 * Constructor method for the class XMLUtils.java.
	 */
	private XMLUtils() {
		super();
	}

	/**
	 * Creates a black document.
	 * @return	A empty DOM document.
	 * @throws UtilsException If an error occurs.
	 */
	public static Document getBlankDocument() throws UtilsException{
		try {
			return dbf.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_001);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.XML_PARSER_ERROR, msg,e);
		}
	}
	/**
	 * Extracts the SOAP message include into {@link SOAPMessage} object.
	 * @param msgSOAP SOAP message.
	 * @return	SOAP message as array of bytes.
	 * @throws UtilsException	If an error occurs.
	 */
	public static byte[] getSOAP(SOAPMessage msgSOAP) throws UtilsException{
		byte[] soap = null;
		
		try (ByteArrayOutputStream stream = new ByteArrayOutputStream();) {
			
			msgSOAP.writeTo(stream);
			soap = stream.toByteArray();
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_039);
			LOGGER.error(msg,e);
			throw new UtilsException(UtilsException.UNKNOWN_ERROR, msg,e);
		}
		return soap;
	}
	/**
	 * Method that returns the XML result of applying the XSL transformation to the data supplied.
	 * @param xml	XML input.
	 * @param xslt	XSL Transform.
	 * @return		the XML result of applying the XSL transformation
	 * @throws UtilsException	There was an error processing the XML.
	 */
	public static byte[ ] xslTransform(byte[ ] xml, byte[ ] xslt) throws UtilsException {
		
		TransformerFactory factory = TransformerFactory.newInstance();
		try (ByteArrayInputStream xsltIn = new ByteArrayInputStream(xslt);
				ByteArrayInputStream xmlIn = new ByteArrayInputStream(xml);
				ByteArrayOutputStream out = new ByteArrayOutputStream();) {
			Transformer transformer = factory.newTransformer(new StreamSource(xsltIn));
			Source src = new StreamSource(xmlIn);
			Result res = new StreamResult(out);
			transformer.transform(src, res);
			return  out.toByteArray();
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_007);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.XSL_TRANSFORM_ERROR, msg,e);
		} 
	}

	/**
	 * Gets a XML as bytes array.
	 * @param xml 	XML document.
	 * @return		XML as bytes array.
	 * @throws UtilsException	There was an error processing the XML.
	 */
	public static byte[ ] getXMLBytes(Node xml) throws UtilsException {
		
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();){

			TransformerFactory tf = TransformerFactory.newInstance();

			Transformer trans = tf.newTransformer();
			
			trans.transform(new DOMSource(xml), new StreamResult(baos));

			byte[ ] eSignatureBytes = baos.toByteArray();

			return eSignatureBytes;
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_001);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.XML_PARSER_ERROR, msg,e);
		} 
	}

	/**
	 * Get the list of nodes that meet the XPath condition provided.
	 * @param xml	Node where to search.
	 * @param xpath	XPath location of node to get.
	 * @return		List of nodes located in XPath supplied.
	 * @throws UtilsException	There was an error processing the XML.
	 */
	public static NodeList getNodes(Node xml, String xpath) throws UtilsException {
		try {
			return XPathAPI.selectNodeList(xml, xpath);
		} catch (TransformerException e) {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_004, new Object[ ] { xpath });
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.XPATH_ERROR, msg,e);
		}
	}

	/**
	 * Get the value of node located in the XPath supplied.
	 * @param xml	Node where to search.
	 * @param xpath	XPath location of node that planning to obtain the value.
	 * @return		Node value. Null if the node is not found.
	 * @throws UtilsException	There was an error processing the XML.
	 */
	public static String getNodeValue(Node xml, String xpath) throws UtilsException {
		try {
			NodeList nl = XPathAPI.selectNodeList(xml, xpath);
			if (nl.getLength() == 1 && nl.item(0).getFirstChild()!=null) {
				return nl.item(0).getFirstChild().getNodeValue();
			}
			return null;
		} catch (TransformerException e) {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_004, new Object[ ] { xpath });
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.XPATH_ERROR, msg,e);
		}
	}

	/**
	 * Gets Document interface that represents the entire HTML or XML document.
	 * @param in	InputStream containing the content to be parsed.
	 * @return Document Result of parsing the InputStream.
	 * @throws UtilsException 	There was an error processing the XML.
	 */
	public static Document getDocument(InputStream in) throws UtilsException {
		try {
			return getDocumentImpl(in);
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_001);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.XML_PARSER_ERROR, msg,e);
		}
	}

	/**
	 * Gets Document interface that represents the entire HTML or XML document.
	 * @param xml	Array of bytes that contain the content to be parsed.
	 * @return	Document result of parsing the bytes.
	 * @throws 	UtilsException There was an error processing the XML.
	 */
	public static Document getDocument(byte[] xml) throws UtilsException {
		Document xmlDoc = null;
		if (xml != null) {
			try (ByteArrayInputStream in = new ByteArrayInputStream(xml);) {
				xmlDoc = getDocument(in);

			} catch (IOException e) {
			}
		}
		return xmlDoc;
	}

	/**
	 * Method that includes a DOM object into the XML supplied and in the indicated path.
	 * @param xml	Document for including of element.
	 * @param xpath	Xpath that locates the node where will be included the element.
	 * @param value	Object that represents the element to be included. Allowed Object:<br>
	 * 			{@link String} - If the object to include is a text node or a cdata section.<br>
	 * 			{@link Node} - If the object to include is a element node.<br>
	 * @param type	Parameter that indicates the type object to be included. Allowed values:<br>
	 * 			{@link Node#TEXT_NODE} - If the object to include is a text node.<br>
	 * 			{@link Node#CDATA_SECTION_NODE} - If the object to include is a cdata section.<br>
	 * 			{@link Node#ELEMENT_NODE} - If the object to include is a element node.<br>
	 * @throws UtilsException	There was an error processing the XML.
	 */
	public static void includeElementValue(Document xml, String xpath, Object value, int type) throws UtilsException {

		NodeList nl = null;
		try {
			nl = XPathAPI.selectNodeList(xml.getDocumentElement(), xpath);
		} catch (TransformerException e) {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_004, new Object[ ] { xpath });
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.XPATH_ERROR, msg,e);
		}

		switch (type) {

			case Node.TEXT_NODE:
				for (int i = 0; i < nl.getLength(); i++) {
					Text text = xml.createTextNode((String) value);
					nl.item(i).appendChild(text);
				}
				break;
			case Node.CDATA_SECTION_NODE:
				for (int i = 0; i < nl.getLength(); i++) {
					CDATASection text = xml.createCDATASection((String) value);
					nl.item(i).appendChild(text);
				}
				break;
			case Node.ELEMENT_NODE:
				for (int i = 0; i < nl.getLength(); i++) {
					Node impNode = xml.importNode(((Node) value).cloneNode(true), true);
					nl.item(i).appendChild(impNode);
				}
			default:
				break;
		}

	}

	/**
	 * This method removes of the XML supplied the nodes indicated.
	 * @param xml	Document for removing the nodes supplied.
	 * @param nodesToRemove	List of XPath that locate the nodes to remove.
	 * @throws UtilsException	There was an error processing the XML.
	 */
	public static void removeNodes(Document xml, ArrayList<String> nodesToRemove) throws UtilsException {
		Iterator<String> it = nodesToRemove.iterator();
		while (it.hasNext()) {
			String xpath = (String) it.next();
			NodeList nl;
			try {
				nl = XPathAPI.selectNodeList(xml.getDocumentElement(), xpath);
			} catch (TransformerException e) {
				String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_004, new Object[ ] { xpath });
				LOGGER.error(msg, e);
				throw new UtilsException(UtilsException.XPATH_ERROR, msg,e);
			}
			for (int i = 0; i < nl.getLength(); i++) {
				removeNode(nl.item(i));
			}
		}
	}

	/**
	 * Remove a XML node.
	 * @param node 	Node to remove.
	 */
	private static void removeNode(Node node) {
		Node parent = node.getParentNode();
		parent.removeChild(node);
		// Eliminamos los espacios en blanco
		while (parent.getParentNode().getNodeType() != Node.DOCUMENT_NODE && getNumChildElement(parent) == 0) {
			Node child = parent;
			parent = parent.getParentNode();
			parent.removeChild(child);
		}
	}

	/**
	 * Methods that returns the number of element or cdata is contained into node supplied.
	 * @param node	Node whose children want to know.
	 * @return		Number of element or cdata is contained into node supplied.
	 */
	private static int getNumChildElement(Node node) {
		int n = 0;
		NodeList l = node.getChildNodes();
		for (int i = 0; i < l.getLength(); i++) {
			if (l.item(i).getNodeType() == Node.ELEMENT_NODE || l.item(i).getNodeType() == Node.CDATA_SECTION_NODE) {
				n++;
			}
		}
		return n;
	}

	/**
	 * Gets Document interface that represents the entire HTML or XML document.
	 * @param in	InputStream containing the content to be parsed.
	 * @return Document Result of parsing the InputStream.
	 * @throws ParserConfigurationException If an error occurs while parsing the document.
	 * @throws IOException If an error occurs while reading the document.
	 * @throws SAXException If an error occurs while processing the document.
	 */
	protected static Document getDocumentImpl(InputStream in) throws ParserConfigurationException, SAXException, IOException  {
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		return db.parse(in);
	}
}
