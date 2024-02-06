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

/*
 * This file is part of the jXAdES library. 
 * jXAdES is an open implementation for the Java platform of the XAdES standard for advanced XML digital signature. 
 * This library can be consulted and downloaded from http://universitatjaumei.jira.com/browse/JXADES.
 * 
 */
package net.java.xades.security.xml.XAdES;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <OCSPRef>
 <OCSPIdentifier URI= >
 <ResponderID>
 <ByName>String of X500Principal Name</ByName>
 or
 <ByKey>base64Binary of PublicKey DER value</ByKey>
 </ResponderID>
 <ProducedAt />
 </OCSPIdentifier>
 <DigestAlgAndValue>
 <DigestMethod Algorithm= />
 <DigestValue />
 </DigestAlgAndValue>
 <ValidationResult />
 </OCSPRef>
 */

/**
 * 
 * @author miro
 */
public class OCSPRef extends XAdESStructure {

    private OCSPIdentifier ocspIdentifier;
    private DigestAlgAndValue digestAlgAndValue;
    private ValidationResult validationResult;

    // public OCSPRef(XAdESStructure parent, XAdESRevocationStatus
    // revocationStatus)
    // throws GeneralSecurityException
    // {
    // super(parent, "OCSPRef");
    //
    // Element thisElement = getElement();
    //
    // OCSPIdentifier ocspIdentifier;
    // OCSPResponse ocspResponse = revocationStatus.getOCSPResponse();
    // URI ocspResponderURI = revocationStatus.getOCSPResponderURI();
    // ocspIdentifier = new OCSPIdentifier(this, ocspResponse,
    // ocspResponderURI);
    //
    // DigestAlgAndValue digestAlgAndValue;
    // digestAlgAndValue = new DigestAlgAndValue(this, ocspResponse);
    //
    // ValidationResult validationResult;
    // validationResult = new ValidationResult(this, revocationStatus);
    // }

    public OCSPRef(Node node, String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix) {
	super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public OCSPIdentifier getOCSPIdentifier() {
	if (ocspIdentifier == null) {
	    Element element = getChildElementNS("OCSPIdentifier");
	    if (element != null)
		ocspIdentifier = new OCSPIdentifier(element, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
	}

	return ocspIdentifier;
    }

    public DigestAlgAndValue getDigestAlgAndValue() {
	if (digestAlgAndValue == null) {
	    Element element = getChildElementNS("DigestAlgAndValue");
	    if (element != null)
		digestAlgAndValue = new DigestAlgAndValue(element, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
	}

	return digestAlgAndValue;
    }

    public ValidationResult getValidationResult() {
	if (validationResult == null) {
	    Element element = getChildElementNS("ValidationResult");
	    if (element != null)
		validationResult = new ValidationResult(element, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
	}

	return validationResult;
    }

}
