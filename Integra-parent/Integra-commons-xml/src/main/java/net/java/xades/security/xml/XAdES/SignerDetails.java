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

/*
 * This file is part of the jXAdES library. 
 * jXAdES is an open implementation for the Java platform of the XAdES standard for advanced XML digital signature. 
 * This library can be consulted and downloaded from http://universitatjaumei.jira.com/browse/JXADES.
 * 
 */
package net.java.xades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 * 
 * @author miro
 */
public class SignerDetails extends XAdESStructure {

    public static final String USERNAME_ATTRIBUTE = "Username";

    public SignerDetails(Document document, SignedSignatureProperties ssp, Signer signer, String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix) {
	super(document, ssp, "SignerDetails", xadesPrefix, xadesNamespace, xmlSignaturePrefix);

	String value = signer.getPersonName();
	if (value == null)
	    throw new IllegalArgumentException("The Signer personal name can not be NULL.");
	setTextContent(value);

	value = signer.getUserId();
	if (value != null)
	    setAttribute(ID_ATTRIBUTE, value);

	value = signer.getUsername();
	if (value != null)
	    setAttribute(USERNAME_ATTRIBUTE, value);
    }

    public SignerDetails(Node node, String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix) {
	super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public Signer getSigner() {
	SignerImpl signer = new SignerImpl();
	signer.setPersonName(getTextContent());
	signer.setUserId(getAttribute(ID_ATTRIBUTE));
	signer.setUsername(getAttribute(USERNAME_ATTRIBUTE));

	return signer;
    }
}
