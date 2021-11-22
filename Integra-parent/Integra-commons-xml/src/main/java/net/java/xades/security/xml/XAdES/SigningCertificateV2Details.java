package net.java.xades.security.xml.XAdES;

import java.security.GeneralSecurityException;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Sample usage of SigningCertificateV2:
 *
 * <xades:SigningCertificateV2>
 *     <xades:Cert>
 *         <xades:CertDigest>
 *             <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
 *             <ds:DigestValue>rFQEEAdlZJieHIdInK8bYoB6aMs=</ds:DigestValue>
 *         </xades:CertDigest>
 *         <xades:IssuerSerialV2>MIGeMIGQpIGNMIGKMQswCQYDVQQGEwJMSzEQMA4GA1UECBMHV2VzdGVybjEQMA4GA1UEBxMHQ29sb21ibzEWMBQGA1UEChMNU29mdHdhcmUgVmlldzERMA8GA1UECxMIVHJhaW5pbmcxLDAqBgNVBAMTI1NvZnR3YXJlIFZpZXcgQ2VydGlmaWNhdGUgQXV0aG9yaXR5AgkA9qs6c/ASQqU=</xades:IssuerSerialV2>
 *     </xades:Cert>
 * </xades:SigningCertificate>
 *
 */

public class SigningCertificateV2Details extends XAdESStructure
{
    public SigningCertificateV2Details(final Document document, final SignedSignatureProperties ssp,
            final SigningCertificateV2 signingCertificate, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix) throws GeneralSecurityException
    {
        super(document, ssp, "SigningCertificateV2", xadesPrefix, xadesNamespace, xmlSignaturePrefix);

        // TODO: Unimplemented URI parameter
        final Element cert = createElement("Cert");

        final Element certDigest = createElement("CertDigest");

        final Element digestMethod = createElementNS(XMLSignature.XMLNS, xmlSignaturePrefix,
                "DigestMethod");
        digestMethod.setPrefix(xmlSignaturePrefix);
        digestMethod.setAttributeNS(xmlSignaturePrefix, "Algorithm", signingCertificate.getDigestMethodAlgorithm());

        final Element digestValue = createElementNS(XMLSignature.XMLNS, xmlSignaturePrefix, "DigestValue");
        digestValue.setPrefix(xmlSignaturePrefix);
        digestValue.setTextContent(signingCertificate.getDigestValue());

        certDigest.appendChild(digestMethod);
        certDigest.appendChild(digestValue);
        cert.appendChild(certDigest);

        if (signingCertificate.getIssuerSerialV2() != null) {
            final Element issuerSerial = createElement("IssuerSerialV2");
            issuerSerial.setTextContent(signingCertificate.getIssuerSerialV2());
            cert.appendChild(issuerSerial);
        }

        getNode().appendChild(cert);
    }

    public SigningCertificateV2Details(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}
