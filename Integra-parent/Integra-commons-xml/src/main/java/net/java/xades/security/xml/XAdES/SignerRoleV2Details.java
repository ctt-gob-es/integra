package net.java.xades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * 
 * <p:SignerRoleV2>
 *     <p:ClaimedRoles>
 *         <p:ClaimedRole>
 *             ANYTYPE
 *         </p:ClaimedRole>
 *     </p:ClaimedRoles>
 *     <p:CertifiedRolesV2>
 *         <p:CertifiedRole>
 *             ANYTYPE
 *         </p:CertifiedRole>
 *     </p:CertifiedRolesV2>
 *     <p:SignedAssertions>
 *         ANYTYPE
 *     <p:SignedAssertions>
 * </p:SignerRoleV2>
 */

public class SignerRoleV2Details extends XAdESStructure
{
    public SignerRoleV2Details(Document document, SignedSignatureProperties ssp, SignerRoleV2 signerRoleV2,
            String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix)
    {
        super(document, ssp, "SignerRoleV2", xadesPrefix, xadesNamespace, xmlSignaturePrefix);

        Element claimedRoles = createElement("ClaimedRoles");
        Element certifiedRoles = createElement("CertifiedRolesV2");
        Element signedAssertions = createElement("SignedAssertions");

        for (String sr : signerRoleV2.getClaimedRoles())
        {
            Element claimedRole = createElement("ClaimedRole");
            claimedRole.setTextContent(sr);
            claimedRoles.appendChild(claimedRole);
        }

        // TODO: Implement support for certified role and attribute certificates management
        for (String sr : signerRoleV2.getCertifiedRolesV2())
        {
            Element certifiedRole = createElement("CertifiedRole");
            certifiedRole.setTextContent(sr);
            certifiedRoles.appendChild(certifiedRole);
        }
        
        // TODO: Implement support for signed assertions
        for (String sr : signerRoleV2.getSignedAssertions())
        {
            Element signedAssertion = createElement("SignedAssertion");
            signedAssertion.setTextContent(sr);
            signedAssertions.appendChild(signedAssertion);
        }

        if (signerRoleV2.getClaimedRoles().size() > 0)
        {
            getNode().appendChild(claimedRoles);
        }

        if (signerRoleV2.getCertifiedRolesV2().size() > 0)
        {
            getNode().appendChild(certifiedRoles);
        }
        
        if (signerRoleV2.getSignedAssertions().size() > 0)
        {
            getNode().appendChild(signedAssertions);
        }
    }

    public SignerRoleV2Details(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}
