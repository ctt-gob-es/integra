package net.java.xades.security.xml.XAdES;

import java.util.List;

import javax.xml.crypto.MarshalException;

/**
 * The minimun methods needed to sign a XAdES implementation. 
 */
public abstract class BaseXAdESImpl implements XAdESBase {

	
	protected abstract void marshalQualifyingProperties(final QualifyingProperties qp, final String signatureIdPrefix, final List referencesIdList) throws MarshalException;
	
	protected abstract void marshalQualifyingProperties(final QualifyingProperties qp, final String signatureIdPrefix, final List referencesIdList, final String tsaUrl) throws MarshalException;
}
