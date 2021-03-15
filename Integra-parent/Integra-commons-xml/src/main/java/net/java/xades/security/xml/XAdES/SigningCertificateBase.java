package net.java.xades.security.xml.XAdES;

import java.security.GeneralSecurityException;

public interface SigningCertificateBase 
{
	public String getDigestMethodAlgorithm();
	public String getDigestValue() throws GeneralSecurityException;
}
