package net.java.xades.security.xml.XAdES;

public class SignaturePolicyStoreImpl implements SignaturePolicyStore
{    
    private String sPDocSpecification;
    private String signaturePolicyDocument;
    private String sigPolDocLocalURI;
    
    public SignaturePolicyStoreImpl(final String docSpecification)
    {
        this.sPDocSpecification = docSpecification;
    }

    @Override
	public String getSPDocSpecification()
    {
		return this.sPDocSpecification;
	}
    
	@Override
	public void setSignaturePolicyDocument(String policyDocument)
	{
		this.signaturePolicyDocument = policyDocument;		
	}

	@Override
	public String getSignaturePolicyDocument()
	{
		return this.signaturePolicyDocument;
	}

	@Override
	public void setSigPolDocLocalURI(String uri)
	{
		this.sigPolDocLocalURI = uri;
	}

	@Override
	public String getSigPolDocLocalURI()
	{
		return this.sigPolDocLocalURI;
	}
}
