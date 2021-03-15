package net.java.xades.security.xml.XAdES;

/**
 * Extra information required by a SigningCertitifcateV2 element.
 */
public class SigningCertificateV2Info implements SigningCertificateInfo {

	private String issuerSerialV2; 
	
	public SigningCertificateV2Info(String issuerSerialEncoded) {
		this.issuerSerialV2 = issuerSerialEncoded;
	}
	
	public String getIssuerSerialV2() {
		return this.issuerSerialV2;
	}
}
