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

import java.util.Date;

import javax.xml.crypto.MarshalException;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/*
 <ds:Signature ID?>
 ...
 <ds:Object>
 <QualifyingProperties>
 ...
 <UnsignedProperties>
 <UnsignedSignatureProperties>
 (ArchiveTimeStamp)+
 </UnsignedSignatureProperties>
 </UnsignedProperties>
 </QualifyingProperties>
 </ds:Object>
 </ds:Signature>-
 */

/**
 * 
 * @author miro
 */
public class ArchivalXAdESImpl extends ExtendedLongXAdESImpl
// implements XAdES_A
{

    /*
     * public ArchivalXAdESImpl(Element baseElement, boolean useExplicitPolicy) { super(baseElement,
     * useExplicitPolicy); }
     */

    public ArchivalXAdESImpl(Element baseElement, boolean readOnlyMode, String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix, String digestMethod) {
	super(baseElement, readOnlyMode, xadesPrefix, xadesNamespace, xmlSignaturePrefix, digestMethod);
    }

    protected void unmarshal() throws MarshalException {
	QualifyingProperties qp = getQualifyingProperties();
	if (qp != null) {
	    try {
		Element qpElement = qp.getElement();

		for (XAdES.Element key: XAdES.Element.values()) {
		    NodeList nl = qpElement.getElementsByTagNameNS(xadesNamespace, key.getElementName());
		    int size;
		    if (nl != null && (size = nl.getLength()) > 0) {
			if (XAdES.Element.SIGNING_TIME.equals(key)) {
			    SigningTime signingTime = new SigningTime(nl.item(0), xadesPrefix, xadesNamespace, xmlSignaturePrefix);
			    Date date = signingTime.getSigningTime();
			    if (date != null)
				data.put(XAdES.Element.SIGNING_TIME, date);
			} else if (XAdES.Element.SIGNER_DETAILS.equals(key)) {
			    SignerDetails signerDetails = new SignerDetails(nl.item(0), xadesPrefix, xadesNamespace, xmlSignaturePrefix);
			    data.put(XAdES.Element.SIGNER, signerDetails.getSigner());
			} else if (XAdES.Element.COMPLETE_CERTIFICATE_REFS.equals(key)) {
			    CompleteCertificateRefsImpl completeCertificateRefs;
			    completeCertificateRefs = new CompleteCertificateRefsImpl(nl.item(0), xadesPrefix, xadesNamespace, xmlSignaturePrefix);
			    data.put(XAdES.Element.COMPLETE_CERTIFICATE_REFS, completeCertificateRefs);
			} else if (XAdES.Element.COMPLETE_REVOCATION_REFS.equals(key)) {
			    CompleteRevocationRefsImpl completeRevocationRefs;
			    completeRevocationRefs = new CompleteRevocationRefsImpl(nl.item(0), xadesPrefix, xadesNamespace, xmlSignaturePrefix);
			    data.put(XAdES.Element.COMPLETE_REVOCATION_REFS, completeRevocationRefs);
			}

		    }
		}
	    } catch (Exception ex) {
		throw new MarshalException(ex);
	    }
	}
    }
}
