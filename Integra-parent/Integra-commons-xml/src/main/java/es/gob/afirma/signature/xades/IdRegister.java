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
 * <b>File:</b><p>es.gob.afirma.signature.xades.IdResolver.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>27/02/2012.</p>
 * @author Gobierno de España.
 * @version 1.0, 27/02/2012.
 */
package es.gob.afirma.signature.xades;

import org.apache.log4j.Logger;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;

/**
 * <p>Class contains methods that registers the ID attributes in the elements allowing to use <code>Document.getElementById</code> method.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 27/02/2012.
 */
public final class IdRegister {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(IdRegister.class);

    /**
     * Attribute that represents ID-attribute name.
     */
    public static final String ID_ATTRIBUTE_NAME = "Id";

    /**
     * Constructor method for the class IdResolver.java. This method doesn't allow instantiation.
     */
    private IdRegister() {
    }

    /**
     * Method declares "Id" attribute in the element given. This behavior allows to use <code>Document.getElementById</code>.
     *
     * @param element the element with the Id-attribute.
     */
    public static void registerAttrId(Element element) {
	if (element != null && element.getNodeType() == Node.ELEMENT_NODE) {
	    Attr idAttribute = getIdAttr(element);
	    if (idAttribute != null) {
		LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.IR_LOG001, new Object[ ] { idAttribute.toString(), element.getNodeName() }));
		element.setIdAttributeNode(idAttribute, true);
	    }
	}
    }

    /**
     * Gets the attribute with name 'Id' in a element.
     * @param element element for search the attribute.
     * @return the attribute with name 'Id'.
     */
    private static Attr getIdAttr(Element element) {
	Attr idAttr = null;
	NamedNodeMap mapTmp = element.getAttributes();
	for (int i = 0; i < mapTmp.getLength(); i++) {
	    Attr att = (Attr) mapTmp.item(i);
	    String attrName = att.getLocalName() == null ? att.getName() : att.getLocalName();
	    if (ID_ATTRIBUTE_NAME.equalsIgnoreCase(attrName)) {
		return att;
	    }
	}
	return idAttr;
    }

    /**
     * Registers the 'Id' attribute to be a user-determined ID attribute in the node of type element and all its childrens.
     * This behavior allows to use <code>Document.getElementById</code>.
     * 
     * @param xmlNode node of type element.
     */
    public static void registerElements(Node xmlNode) {
	if (xmlNode != null && xmlNode.getNodeType() == Node.ELEMENT_NODE) {
	    registerAttrId((Element) xmlNode);
	    NodeList nl = xmlNode.getChildNodes();
	    for (int i = 0; i < nl.getLength(); i++) {
		Node node = nl.item(i);
		registerElements(node);
	    }
	}
    }

}
