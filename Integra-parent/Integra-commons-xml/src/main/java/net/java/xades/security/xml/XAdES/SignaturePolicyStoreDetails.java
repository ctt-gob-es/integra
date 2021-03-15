package net.java.xades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class SignaturePolicyStoreDetails extends XAdESStructure
{
    public SignaturePolicyStoreDetails(Document document, UnsignedSignatureProperties usp,
            SignaturePolicyStore signaturePolicyStore, String xadesPrefix,
            String xadesNamespace, String xmlSignaturePrefix)
    {
        super(document, usp, "SignaturePolicyStore", xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);

        // SPDocSpecification
        Element docSpecification = createElement("SPDocSpecification");
        
	    Element identifier = createElement("Identifier");
	    identifier.appendChild(getDocument().createTextNode(signaturePolicyStore.getSPDocSpecification()));
	    
	    docSpecification.appendChild(identifier);
	    getNode().appendChild(docSpecification);
        
        
        // SignaturePolicyDocument
        if (signaturePolicyStore.getSignaturePolicyDocument() != null)
        {
            Element policyDocument = createElement("SignaturePolicyDocument");
            policyDocument.setTextContent(signaturePolicyStore.getSignaturePolicyDocument());
            getNode().appendChild(policyDocument);
        }

        // SigPolDocLocalURI
        else if (signaturePolicyStore.getSigPolDocLocalURI() != null)
        {
            Element policyLocalUri = createElement("SigPolDocLocalURI");
            policyLocalUri.setTextContent(signaturePolicyStore.getSigPolDocLocalURI());
            getNode().appendChild(policyLocalUri);
        }
    }

    public SignaturePolicyStoreDetails(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}