package net.java.xades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.DigestMethod;

import net.java.xades.util.Base64;

public class SigningCertificateV2Impl implements SigningCertificateV2
{
	private X509Certificate certificate;
	private String digestMethod;
	private String issuerSerial = null;
	
	public SigningCertificateV2Impl(final X509Certificate certificate, final String digestMethod) 
	{
		this.certificate = certificate;
		this.digestMethod = digestMethod;
	}

	public String getDigestMethodAlgorithm() 
	{
		return this.digestMethod;
	}

	public String getDigestValue() throws GeneralSecurityException
	{
		
	    String algorithm;

	    if (DigestMethod.SHA256.equals(digestMethod)) {
		algorithm = "SHA-256";
	    } else if (DigestMethod.SHA512.equals(digestMethod)) {
		algorithm = "SHA-512";
	    } else if ("http://www.w3.org/2001/04/xmldsig-more#sha384".equals(digestMethod)) {
		algorithm = "SHA-384";
	    } else if (DigestMethod.SHA1.equals(digestMethod)) {
		algorithm = "SHA-1";
	    } else {
		throw new GeneralSecurityException("Unsupported digest algorithm: " + digestMethod);
	    }

	    String result;
	    try
	    {
		MessageDigest md = MessageDigest.getInstance(algorithm);	
		md.update(this.certificate.getEncoded());
		result = Base64.encodeBytes(md.digest());
	    }
	    catch (Exception e)
	    {
		throw new GeneralSecurityException(e);
	    }
		
		return result;
	}

	public void setIssuerSerialV2(final String issuerSerial) {
		this.issuerSerial = issuerSerial;
	}
	
	public String getIssuerSerialV2() {
		return this.issuerSerial;
	}
}
