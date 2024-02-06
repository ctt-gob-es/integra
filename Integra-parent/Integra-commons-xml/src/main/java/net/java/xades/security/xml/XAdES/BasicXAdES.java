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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureException;

import org.w3c.dom.Element;

import net.java.xades.security.xml.WrappedKeyStorePlace;
import net.java.xades.security.xml.XMLSignatureDocument;
import net.java.xades.security.xml.XmlWrappedKeyInfo;

/*
 <?xml version="1.0"?>
 <schema xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns="http://uri.etsi.org/01903/v1.3.2#"
 targetNamespace="http://uri.etsi.org/01903/v1.3.2#"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
 elementFormDefault="qualified">
 <xsd:import namespace="http://www.w3.org/2000/09/xmldsig#"
 schemaLocation="http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd"/>

 <ds:Signature ID?>
 ...
 <ds:Object>
 <QualifyingProperties>
 <SignedProperties>
 <SignedSignatureProperties>
 (SigningTime)?
 (SigningCertificate)?
 (SignatureProductionPlace)?
 (SignerRole)?
 </SignedSignatureProperties>
 <SignedDataObjectProperties>
 (DataObjectFormat)*
 (CommitmentTypeIndication)*
 (AllDataObjectsTimeStamp)*
 (IndividualDataObjectsTimeStamp)*
 </SignedDataObjectProperties>
 </SignedProperties>
 <UnsignedProperties>
 <UnsignedSignatureProperties>
 (CounterSignature)*
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
public class BasicXAdES extends XMLSignatureDocument {

    private QualifyingProperties qualifyingProperties;
    private List<QualifyingPropertiesReference> qualifyingPropertiesReferences;
    private WrappedKeyStorePlace wrappedKeyStorePlace = WrappedKeyStorePlace.KEY_INFO;

    private Signer signer;

    public BasicXAdES(Element baseElement) {
	super(baseElement);
    }

    public QualifyingProperties getQualifyingProperties(String signatureIdPrefix) {
	if (qualifyingProperties == null) {
	    /*
	     * qualifyingProperties = new QualifyingProperties(this, getBaseElement(),
	     * signatureIdPrefix);
	     */
	}

	return qualifyingProperties;
    }

    public void setQualifyingProperties(QualifyingProperties qualifyingProperties) {
	this.qualifyingProperties = qualifyingProperties;
    }

    public List<QualifyingPropertiesReference> getQualifyingPropertiesReferences() {
	if (qualifyingPropertiesReferences == null) {
	    qualifyingPropertiesReferences = new ArrayList<QualifyingPropertiesReference>();
	}

	return qualifyingPropertiesReferences;
    }

    public void setQualifyingPropertiesReferences(List<QualifyingPropertiesReference> qpr) {
	this.qualifyingPropertiesReferences = qpr;
    }

    public XMLObject getXAdESObject(QualifyingProperties qualifyingProperties) {
	List<QualifyingPropertiesReference> qpr = getQualifyingPropertiesReferences();
	ArrayList<XMLStructure> content = new ArrayList<XMLStructure>(qpr.size() + 1);
	content.add(qualifyingProperties);
	content.addAll(qpr);
	return newXMLObject(content);
    }

    public final XmlWrappedKeyInfo getXmlWrappedKeyInfo() {
	return XmlWrappedKeyInfo.CERTIFICATE;
    }

    public final void setXmlWrappedKeyInfo(XmlWrappedKeyInfo wrappedKeyInfo) {
    }

    public WrappedKeyStorePlace getWrappedKeyStorePlace() {
	return wrappedKeyStorePlace;
    }

    public void setWrappedKeyStorePlace(WrappedKeyStorePlace wrappedKeyStorePlace) {
	this.wrappedKeyStorePlace = wrappedKeyStorePlace;
    }

    public void sign(X509Certificate certificate, PrivateKey privateKey, String signatureMethod, List refsIdList, String signatureIdPrefix, String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix) throws MarshalException, XMLSignatureException, GeneralSecurityException {
	List referencesIdList = new ArrayList(refsIdList);
	if (WrappedKeyStorePlace.SIGNING_CERTIFICATE_PROPERTY.equals(getWrappedKeyStorePlace())) {
	    /* @ToDo: Implement SigningCertificate */
	} else {
	    /*
	     * @ToDo The ds:KeyInfo element also MAY contain other certificates forming a chain that
	     * MAY reach the point of trust;
	     */
	}

	QualifyingProperties qp = getQualifyingProperties(signatureIdPrefix);
	SignedProperties sp = qp.getSignedProperties();

	SignedSignatureProperties ssp = sp.getSignedSignatureProperties();
	ssp.setSigningTime();

	Signer signer = getSigner();
	if (signer != null)
	    ssp.setSigner(signer);

	XMLObject xadesObject = getXAdESObject(qp);
	addXMLObject(xadesObject);

	List transforms = null;

	String spId = sp.getId();
	Reference spReference = getReference(spId, transforms, xadesNamespace + "SignedProperties");
	referencesIdList.add(spReference);

	super.sign(certificate, privateKey, signatureMethod, referencesIdList, signatureIdPrefix, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public Signer getSigner() {
	return signer;
    }

    public void setSigner(Signer signer) {
	this.signer = signer;
    }

}
