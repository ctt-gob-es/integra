package net.java.xades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Sample usage of signing SignatureProductionPlaceV2:
 * <p>
 * {@code
 * <xades:SignatureProductionPlace>
 *     <xades:City>City</xades:City>
 *     <xades:StreetAddress>StreetAddress</xades:StreetAddress>
 *     <xades:StateOrProvince>StateOrProvince</xades:StateOrProvince>
 *     <xades:PostalCode>PostalCode</xades:PostalCode>
 *     <xades:CountryName>CountryName</xades:CountryName>
 * </xades:SignatureProductionPlace>
 * }
 * </p>
 */
public class SignatureProductionPlaceV2Details extends XAdESStructure
{
    public SignatureProductionPlaceV2Details(Document document, SignedSignatureProperties ssp,
            SignatureProductionPlaceV2 signatureProductionPlace, String xadesPrefix,
            String xadesNamespace, String xmlSignaturePrefix)
    {
        super(document, ssp, "SignatureProductionPlaceV2", xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);

        if (signatureProductionPlace.getCity() != null)
        {
            Element city = createElement("City");
            city.setTextContent(signatureProductionPlace.getCity());
            getNode().appendChild(city);
        }

        if (signatureProductionPlace.getStreetAddress() != null)
        {
            Element streetAddress = createElement("StreetAddress");
            streetAddress.setTextContent(signatureProductionPlace.getStreetAddress());
            getNode().appendChild(streetAddress);
        }

        if (signatureProductionPlace.getStateOrProvince() != null)
        {
            Element stateOrProvince = createElement("StateOrProvince");
            stateOrProvince.setTextContent(signatureProductionPlace.getStateOrProvince());
            getNode().appendChild(stateOrProvince);
        }

        if (signatureProductionPlace.getPostalCode() != null)
        {
            Element postalCode = createElement("PostalCode");
            postalCode.setTextContent(signatureProductionPlace.getPostalCode());
            getNode().appendChild(postalCode);
        }

        if (signatureProductionPlace.getCountryName() != null)
        {
            Element countryName = createElement("CountryName");
            countryName.setTextContent(signatureProductionPlace.getCountryName());
            getNode().appendChild(countryName);
        }
    }

    public SignatureProductionPlaceV2Details(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}