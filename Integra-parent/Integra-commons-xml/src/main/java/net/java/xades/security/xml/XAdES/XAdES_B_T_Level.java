package net.java.xades.security.xml.XAdES;

/**
 * ETSI EN 319 132-1 V1.1.1 Electronic Signatures and Infrastructures (ESI);
 *
 * 4.2 & Annex C) ETSI defines two XML Schema files for the present specification:
 *  - http://uri.etsi.org/01903/v1.3.2/XAdES01903v132-201601.xsd contains the
 *  definitions of qualifying properties defined within the namespace whose URI value is http://uri.etsi.org/01903/v1.3.2#.
 *  - http://uri.etsi.org/01903/v1.4.1/XAdES01903v141-201601.xsd contains the
 * definitions of qualifying properties defined within the namespace whose URI value is http://uri.etsi.org/01903/v1.4.1#.
 *
 * 6.3 Requirements on XAdES signature's elements, qualifying properties and services
 *
 * Requirements for XAdES-B-T:
 *  - ds:KeyInfo/X509Data                      shall be present
 *  - ds:SignedInfo/ds:CanonicalizationMethod  shall be present
 *  - ds:Reference shall be present            shall be present
 *      - ds:Reference/ds:Transforms           may be present
 *  - SigningTime                              shall be present
 *  - SigningCertificateV2                     shall be present
 *  - SigningCertificate shall                 not be present
 *  - DataObjectFormat                         conditioned presence
 *      - DataObjectFormat/Description         may be present
 *      - DataObjectFormat/ObjectIdentifier    may be present
 *      - DataObjectFormat/MimeType            shall be present
 *      - DataObjectFormat/Encoding            may be present
 *      - ObjectReference attribute            shall be present
 *  - SignerRole                               shall not be present
 *  - SignerRoleV2                             may be present
 *  - CommitmentTypeIndication                 may be present
 *  - SignatureProductionPlaceV2               may be present
 *  - SignatureProductionPlace                 shall not be present
 *  - CounterSignature                         may be present
 *  - AllDataObjectsTimeStamp                  may be present
 *  - IndividualDataObjectsTimeStamp           may be present
 *  - SignaturePolicyIdentifier                may be present
 *  - SignaturePolicyStore                     conditioned presence
 *  - SignatureTimeStamp                       shall be present
 *  - CompleteCertificateRefs                  shall not be present
 *  - AttributeCertificateRefs                 shall not be present
 *  - SigAndRefsTimeStamp                      shall not be present
 *  - RefsOnlyTimeStamp                        shall not be present
 *  - ArchiveTimeStamp                         shall not be present
 **/

/*
https://uri.etsi.org/01903/v1.3.2/XAdES01903v132-201601.xsd
-----------------------------------------------------------

<?xml version="1.0"?>
<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema"
		xmlns="http://uri.etsi.org/01903/v1.3.2#"
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
		targetNamespace="http://uri.etsi.org/01903/v1.3.2#"
		elementFormDefault="qualified">
	<xsd:import namespace="http://www.w3.org/2000/09/xmldsig#"
			schemaLocation="http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/xmldsig-core-schema.xsd"/>

        <ds:Signature ID?>
            ...
            <ds:Object>
                <QualifyingProperties>
                    <SignedProperties>
                        <SignedSignatureProperties>
                            (SigningTime)?
                            (SigningCertificateV2)?
                            (SignatureProductionPlaceV2)?
                            (SignerRoleV2)?
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
                            (SignatureTimeStamp)*
                        </UnsignedSignatureProperties>
                    </UnsignedProperties>
                </QualifyingProperties>
            </ds:Object>
        </ds:Signature>-
*/
public interface XAdES_B_T_Level extends XAdES_B_B_Level, XadesWithSignatureTimeStamp {

}
