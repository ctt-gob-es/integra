// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsAxis.java.</p>
 * <b>Description:</b><p>Utilities class that contains auxiliary method related with axis engine.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/03/2020.
 */
package es.gob.afirma.utils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.Calendar;
import java.util.Iterator;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axis2.saaj.SOAPElementImpl;
import org.apache.axis2.saaj.SOAPHeaderElementImpl;
import org.apache.axis2.saaj.TextImplEx;
import org.apache.log4j.Logger;
import org.w3c.dom.NamedNodeMap;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;


/** 
 * <p>Utilities class that contains auxiliary method related with axis engine.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/03/2020.
 */
public final class UtilsAxis {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsAxis.class);
    
    /**
     * Attribute that represents the counter of numbered sequences generated at this loop.
     */
    private static int counter = (int) (getRandomDouble() * NumberConstants.INT_5000);

    /**
     * Attribute that represents the current time milliseconds representation in a string
     * captured for last time.
     */
    private static String currentTimeMillis = String.valueOf(Calendar.getInstance().getTimeInMillis());

    /**
     * Attribute that represents the object to format decimal numbers.
     */
    private static DecimalFormat formatter = new DecimalFormat("0000");

    /**
     * Attribute that represents a virtual number (two ciphers) that represents
     * the IP of the machine for generate unique numbers.
     */
    private static String twoCipherIpRepresentation = null;

    /**
     * Constructor method for the class UtilsAxis.java.
     */
    private UtilsAxis() {
    }

    /**
     * Method that generates a new secure double number.
     * @return a secured double between 0.0 and 1.0.
     */
    private static Double getRandomDouble() {
	try {
	    return SecureRandom.getInstanceStrong().nextDouble();
	} catch (NoSuchAlgorithmException e) {
	    LOGGER.error(Language.getResIntegra(ILogConstantKeys.UA_LOG001), e);
	}
	return null;
    }

    /**
     * Method that transforms a SOAPHeader into a OMElement.
     * 
     * @param headers SOAP header to transform.
     * @return a new OMElement that represents the SOAP header.
     */
    public static OMElement fromSOAPHeaderToOMElement(SOAPHeaderElementImpl headers) {
	OMFactory fac = OMAbstractFactory.getOMFactory();
	
	// Generamos los distintos elementos incluidos en el elemento principal.
	return UtilsAxis.parseElements((SOAPElementImpl<?>) headers, fac);
    }

    /**
     * Method that transform a given set of child elements into a OMElement.
     * 
     * @param sh Child to transform.
     * @param fac Object Model factory.
     * @return a new OMElement object that represents the set of child elements.
     */
    public static OMElement parseElements(SOAPElementImpl<?> sh, OMFactory fac) {
	
	// Creamos el namespace.
	OMNamespace nsMain = fac.createOMNamespace(sh.getNamespaceURI(), sh.getPrefix());
	
	// Creamos el elemento principal.
	OMElement mainElem = fac.createOMElement(sh.getElementQName().getLocalPart(), nsMain);
	
	// Añadimos los atributos.
	NamedNodeMap attrs = sh.getAttributes();
	for (int i = 0; i < attrs.getLength(); i++) {
	    OMAttribute attr = null;
	    attr = fac.createOMAttribute(attrs.item(i).getNodeName(), null, attrs.item(i).getNodeValue());
	    if (attr.getLocalName().split(":")[0].equals("xmlns") && mainElem.getNamespace().getPrefix().equals(attr.getLocalName().split(":")[1])) {
		continue;
	    }
	    mainElem.addAttribute(attr);
	}
	
	// Recorremos los hijos.
	Iterator<?> elements = sh.getChildElements();
	while (elements.hasNext()) {
	    Object o = elements.next();
	    if (o instanceof TextImplEx) {
		mainElem.setText(((TextImplEx) o).getNodeValue());
	    } else {
		mainElem.addChild(parseElements((SOAPElementImpl<?>) o, fac));
	    }
	}
	return mainElem;
    }

    /**
     * Synchronized method that generates a unique identifier builded in characters
     * and a ending number.
     * @return String that represents the generated unique identifier.
     */
    public static synchronized String generateNumbersUniqueId() {

	counter += 1;
	if (counter >= NumberConstants.INT_10000) {
	    counter = (int) (getRandomDouble() * NumberConstants.INT_5000);
	    currentTimeMillis = String.valueOf(Calendar.getInstance().getTimeInMillis());
	}
	String indice = formatter.format(counter);
	return currentTimeMillis + getTwoCipherIpRepresentation() + indice;
    }

    /**
     * Gets an IP representation in two ciphers for this node.
     * @return {@link String} with a IP representation in two ciphers.
     */
    private static String getTwoCipherIpRepresentation() {

	// Si el atributo que determina la representación de la IP en dos cifras
	// aún no ha sido calculado, lo hacemos ahora.
	if (twoCipherIpRepresentation == null || twoCipherIpRepresentation.isEmpty()) {

	    String ipNode = null;
	    int addingResult = -1;
	    try {
		
		// Obtenemos la IP del nodo.
		ipNode = InetAddress.getLocalHost().getHostAddress().toString();
		String[ ] parts = ipNode.split("\\.");
		
		// Calculamos el número resumido.
		int part0 = Integer.parseInt(parts[0]) * NumberConstants.INT_5;
		int part1 = Integer.parseInt(parts[1]) * NumberConstants.INT_3;
		int part2 = Integer.parseInt(parts[2]) * 2;
		int part3 = Integer.parseInt(parts[NumberConstants.INT_3]);
		addingResult = part0 + part1 + part2 + part3;
		while (addingResult >= NumberConstants.INT_100) {
		    int rest = addingResult / NumberConstants.INT_100;
		    addingResult = addingResult % NumberConstants.INT_100;
		    addingResult = addingResult + rest;
		}
	    } catch (UnknownHostException e) {
		
		// Si se produce un error al obtener la IP del nodo, se genera
		// un número aleatorio entre 00 y 99.
		addingResult = (int) (getRandomDouble() * NumberConstants.INT_99);

	    }

	    // Si el número es menor de 10, se le añade un 0 por delante.
	    if (addingResult < NumberConstants.INT_10) {
		twoCipherIpRepresentation = Integer.toString(0) + Integer.toString(addingResult);
	    } else {
		twoCipherIpRepresentation = Integer.toString(addingResult);
	    }
	}

	return twoCipherIpRepresentation;

    }

    /**
     * Method that finds a given element in the OMElement if it exists.
     * @param element XML element to analyze.
     * @param tagName Name of the tag to find. 
     * @return the element if it exists or null in other cases.
     */
    public static OMElement findElementByTagName(OMElement element, String tagName) {
	OMElement res = null;
	OMElement elem = null;
	Iterator<?> it = element.getChildElements();
	String localName;
	while (it.hasNext() && res == null) {
	    elem = (OMElement) it.next();
	    localName = elem.getLocalName();
	    
	    // Si el nombre del elemento coincide con el que buscamos,
	    // terminamos la búsqueda.
	    if (localName.equals(tagName)) {
		res = elem;
		break;
	    }
	    
	    // Si el elemento tiene hijos, los recorremos recursivamente.
	    if (elem.getChildElements().hasNext()) {
		res = findElementByTagName(elem, tagName);
	    }
	}
	return res;
    }

    /**
     * Method that finds a given element in the OMElement if it exists.
     * @param element XML element to analyze.
     * @param tagName Name of the tag to find.
     * @param id Identifier of the element to find.
     * @return the element if it exists or null in other cases.
     */
    public static OMElement findElementByTagNameAndId(OMElement element, String tagName, String id) {
	return findElementByTagNameAndAttribute(element, tagName, TSAServiceInvokerConstants.SOAPElements.ID, id);
    }

    /**
     * Method that finds a given element in the OMElement if it exists.
     * @param element XML element to analyze.
     * @param tagName Name of the tag to find.
     * @param attrName Name of the attribute to find.
     * @param attrValue value of the attribute to find.
     * @return the element if it exists or null in other cases.
     */
    public static OMElement findElementByTagNameAndAttribute(OMElement element, String tagName, String attrName, String attrValue) {
	OMElement res = null;
	OMElement elem = null;
	Iterator<?> it = element.getChildElements();
	String localName;
	boolean exit = false;

	while (it.hasNext() && res == null && !exit) {
	    elem = (OMElement) it.next();
	    localName = elem.getLocalName();
	    
	    // Si el nombre del elemento coincide con el que buscamos,
	    // comparamos el identificador.
	    if (localName.equals(tagName)) {
		String idValue = findAttributeValue(elem, attrName);
		
		// Si el identificador coincide con el solicitado,
		// devolvemos el elemento.
		if (attrValue.equalsIgnoreCase(idValue)) {
		    res = elem;
		    exit = true;
		    break;
		}
	    }
	    
	    // Si el elemento tiene hijos, los recorremos recursivamente.
	    if (elem.getChildElements().hasNext()) {
		res = findElementByTagNameAndAttribute(elem, tagName, attrName, attrValue);
	    }
	}
	return res;
    }

    /**
     * Method that gets the value of an attribute from a given XML element.
     * @param element XML element where to do the search.
     * @param attributeName Name of the attribute to find.
     * @return the attribute value found or null if the attribute was not found.
     */
    public static String findAttributeValue(OMElement element, String attributeName) {
	String res = null;
	OMAttribute attr = null;
	if (element != null) {
	    Iterator<?> attrs = element.getAllAttributes();
	    while (attrs.hasNext()) {
		attr = (OMAttribute) attrs.next();
		if (attr.getLocalName().equals(attributeName)) {
		    return attr.getAttributeValue();
		}
	    }
	}
	return res;
    }

    /**
     * Method that update the current SOAP body with the new generated body.
     * @param body Current SOAP body to update.
     * @param soapBody new SOAP body.
     */
    public static void updateSoapBody(SOAPBody body, javax.xml.soap.SOAPBody soapBody) {
	OMFactory fac = OMAbstractFactory.getOMFactory();
	NamedNodeMap attrs = soapBody.getAttributes();

	// Añadimos los atributos.
	for (int i = 0; i < attrs.getLength(); i++) {
	    OMAttribute attr = null;
	    attr = fac.createOMAttribute(attrs.item(i).getNodeName(), null, attrs.item(i).getNodeValue());
	    body.addAttribute(attr);
	}

	// Añadimos los elementos hijos.
	Iterator<?> it = soapBody.getChildElements();
	while (it.hasNext()) {
	    body.addChild(UtilsAxis.parseElements((SOAPElementImpl<?>) it.next(), fac));
	}
    }
}
