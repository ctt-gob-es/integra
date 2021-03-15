package net.java.xades.security.xml.XAdES;

import java.security.cert.X509Certificate;

public interface XadesWithBaselineAttributes {
	
    SigningCertificateV2 getSigningCertificateV2();

    /**
     * Set the signing certificate.
     * @param signingCertificate Signing certificate information.
     * @param additionalInfo Signing certificate additional data. Mainly, issuer serial info.
     */
    void setSigningCertificateV2(X509Certificate signingCertificate, SigningCertificateV2Info additionalInfo);

    SignatureProductionPlace getSignatureProductionPlaceV2();
    
    /**
     * Set the production place.
     * @param productionPlace Production place information.
     */
    void setSignatureProductionPlaceV2(SignatureProductionPlaceV2 productionPlace);

    SignerRoleV2 getSignerRoleV2();
    
    /**
     * Set the signer roles.
     * @param signerRole Signer's Roles.
     */
    void setSignerRoleV2(SignerRoleV2 signerRole);

    SignaturePolicyStore getSignaturePolicyStore();
    
    /**
     * Set the signature policy store.
     * @param signaturePolicyStore Signature policy content.
     */
    void setSignaturePolicyStore(SignaturePolicyStore signaturePolicyStore);
}
