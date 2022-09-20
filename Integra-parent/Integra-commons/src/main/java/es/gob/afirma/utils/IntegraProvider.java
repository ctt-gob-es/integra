// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.utils.IntegraProvider.java.</p>
 * <b>Description:</b><p>Class that implements the XmlSec 1.5 security provider.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/01/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 04/03/2020.
 */
package es.gob.afirma.utils;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.HashMap;

/** 
 * <p>Class that implements the XmlSec 1.5 security provider.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 04/03/2020.
 */
public class IntegraProvider extends Provider {

    /**
     * Attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -3495991770958497647L;

    private static final String INFO = "Apache Santuario XMLDSig (DOM XMLSignatureFactory; DOM KeyInfoFactory; C14N 1.0, C14N 1.1, Exclusive C14N, Base64, Enveloped, XPath, XPath2, XSLT TransformServices)";

    @SuppressWarnings("unchecked")
    public IntegraProvider() {
	super("IntegraXMLDSig", 1.5D, INFO);
	final HashMap<String, String> map = new HashMap<String, String>();
	map.put("XMLSignatureFactory.DOM", "org.apache.jcp.xml.dsig.internal.dom.DOMXMLSignatureFactory");
	map.put("KeyInfoFactory.DOM", "org.apache.jcp.xml.dsig.internal.dom.DOMKeyInfoFactory");
	map.put("TransformService.http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "org.apache.jcp.xml.dsig.internal.dom.DOMCanonicalXMLC14NMethod");
	map.put("Alg.Alias.TransformService.INCLUSIVE", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
	map.put("TransformService.http://www.w3.org/TR/2001/REC-xml-c14n-20010315 MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", "org.apache.jcp.xml.dsig.internal.dom.DOMCanonicalXMLC14NMethod");
	map.put("Alg.Alias.TransformService.INCLUSIVE_WITH_COMMENTS", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
	map.put("TransformService.http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/2006/12/xml-c14n11", "org.apache.jcp.xml.dsig.internal.dom.DOMCanonicalXMLC14N11Method");
	map.put("TransformService.http://www.w3.org/2006/12/xml-c14n11 MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/2006/12/xml-c14n11#WithComments", "org.apache.jcp.xml.dsig.internal.dom.DOMCanonicalXMLC14N11Method");
	map.put("TransformService.http://www.w3.org/2006/12/xml-c14n11#WithComments MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/2001/10/xml-exc-c14n#", "org.apache.jcp.xml.dsig.internal.dom.DOMExcC14NMethod");
	map.put("Alg.Alias.TransformService.EXCLUSIVE", "http://www.w3.org/2001/10/xml-exc-c14n#");
	map.put("TransformService.http://www.w3.org/2001/10/xml-exc-c14n# MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/2001/10/xml-exc-c14n#WithComments", "org.apache.jcp.xml.dsig.internal.dom.DOMExcC14NMethod");
	map.put("Alg.Alias.TransformService.EXCLUSIVE_WITH_COMMENTS", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
	map.put("TransformService.http://www.w3.org/2001/10/xml-exc-c14n#WithComments MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/2000/09/xmldsig#base64", "org.apache.jcp.xml.dsig.internal.dom.DOMBase64Transform");
	map.put("Alg.Alias.TransformService.BASE64", "http://www.w3.org/2000/09/xmldsig#base64");
	map.put("TransformService.http://www.w3.org/2000/09/xmldsig#base64 MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/2000/09/xmldsig#enveloped-signature", "org.apache.jcp.xml.dsig.internal.dom.DOMEnvelopedTransform");
	map.put("Alg.Alias.TransformService.ENVELOPED", "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
	map.put("TransformService.http://www.w3.org/2000/09/xmldsig#enveloped-signature MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/2002/06/xmldsig-filter2", "org.apache.jcp.xml.dsig.internal.dom.DOMXPathFilter2Transform");
	map.put("Alg.Alias.TransformService.XPATH2", "http://www.w3.org/2002/06/xmldsig-filter2");
	map.put("TransformService.http://www.w3.org/2002/06/xmldsig-filter2 MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/TR/1999/REC-xpath-19991116", "org.apache.jcp.xml.dsig.internal.dom.DOMXPathTransform");
	map.put("Alg.Alias.TransformService.XPATH", "http://www.w3.org/TR/1999/REC-xpath-19991116");
	map.put("TransformService.http://www.w3.org/TR/1999/REC-xpath-19991116 MechanismType", "DOM");
	map.put("TransformService.http://www.w3.org/TR/1999/REC-xslt-19991116", "org.apache.jcp.xml.dsig.internal.dom.DOMXSLTTransform");
	map.put("Alg.Alias.TransformService.XSLT", "http://www.w3.org/TR/1999/REC-xslt-19991116");
	map.put("TransformService.http://www.w3.org/TR/1999/REC-xslt-19991116 MechanismType", "DOM");
	AccessController.doPrivileged(new PrivilegedAction() {

	    public Void run() {
		IntegraProvider.this.putAll(map);
		return null;
	    }
	});
    }

}
