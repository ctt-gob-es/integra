package es.gob.afirma.signature.cades;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;

public class SignaturePolicyDocument extends ASN1Encodable {
    
    /**
     * Describe constant <code>DISPLAY_TEXT_MAXIMUM_SIZE</code> here.
     *
     */
    public static final int DISPLAY_TEXT_MAXIMUM_SIZE = 200;
    
    DERIA5String sigPolicyLocalURI;
    DEROctetString sigPolicyEncoded;
    
    /**
     * Creates a new <code>SignaturePolicyDocument</code> instance.
     *
     * @param type the desired encoding type for the text. 
     * @param localURI The URI to the policy document. Strings longer than 200
     * characters are truncated. 
     */
    public SignaturePolicyDocument(String localURI)
    {
       if (localURI.length() > DISPLAY_TEXT_MAXIMUM_SIZE)
       {
          // RFC3280 limits these strings to 200 chars
          // truncate the string
	   localURI = localURI.substring (0, DISPLAY_TEXT_MAXIMUM_SIZE);
       }
       
       this.sigPolicyLocalURI = null;
       this.sigPolicyLocalURI = new DERIA5String(localURI);
    }
    
    /**
     * Creates a new <code>SignaturePolicyDocument</code> instance.
     *
     * @param localURI The URI to the policy document.
     */
    public SignaturePolicyDocument(DERIA5String localUri) {
        this.sigPolicyEncoded = null;
        this.sigPolicyLocalURI = localUri;
    }
    
    /**
     * Creates a new <code>SignaturePolicyDocument</code> instance.
     *
     * @param policyDocument the policy document encoded. 
     */
    public SignaturePolicyDocument(byte[] policyEncoded)
    {
	this.sigPolicyEncoded = new DEROctetString(policyEncoded);
	this.sigPolicyLocalURI = null;
    }
    
    /**
     * Creates a new <code>SignaturePolicyDocument</code> instance.
     *
     * @param policyDocument the policy document encoded. 
     */
    public SignaturePolicyDocument(DEROctetString policyEncoded) {
        this.sigPolicyEncoded = policyEncoded;
        this.sigPolicyLocalURI = null;
    }

    public static SignaturePolicyDocument getInstance(Object obj) {
        if (obj == null || obj instanceof SignaturePolicyDocument)
        {
            return (SignaturePolicyDocument) obj;
        }
        else if (obj instanceof DERIA5String)
        {
            return new SignaturePolicyDocument((DERIA5String) obj);
        }
        else if (obj instanceof String)
        {
            return new SignaturePolicyDocument((String) obj);
        }
        else if (obj instanceof DEROctetString)
        {
            return new SignaturePolicyDocument((DEROctetString) obj);
        }
        else if (obj instanceof byte[])
        {
            return new SignaturePolicyDocument((byte[]) obj);
        }

        throw new IllegalArgumentException(
                "Unknown object in 'SignaturePolicyDocument' factory : "
                        + obj.getClass().getName() + ".");
    }
    

    public String getSigPolicyLocalURI()
    {
        return this.sigPolicyLocalURI != null ? this.sigPolicyLocalURI.getString() : null;
    }

    public byte[] getSigPolicyEncoded()
    {
        return this.sigPolicyEncoded != null ? this.sigPolicyEncoded.getOctets() : null;
    }

    /**
     * <pre>
     * SignaturePolicyDocument ::= CHOICE {
     *     sigPolicyEncoded OCTET STRING,
     *     sigPolicyLocalURI IA5String
     * }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        if (this.sigPolicyLocalURI != null)
        {
            return this.sigPolicyLocalURI; 
        }
        return this.sigPolicyEncoded;
    }
}
