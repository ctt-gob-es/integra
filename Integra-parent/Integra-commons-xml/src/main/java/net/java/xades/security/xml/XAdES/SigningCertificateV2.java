package net.java.xades.security.xml.XAdES;

public interface SigningCertificateV2 extends SigningCertificateBase 
{
	void setIssuerSerialV2(String issuerSerial);
	String getIssuerSerialV2();
}
