package es.gob.afirma.signature.cades;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;

public class SPDocSpecification extends ASN1Encodable {
    
    private ASN1ObjectIdentifier  oid;
    private DERIA5String uri;

    public static SPDocSpecification getInstance(Object obj) {
        if (obj == null || obj instanceof SPDocSpecification)
        {
            return (SPDocSpecification) obj;
        }
        else if (obj instanceof ASN1ObjectIdentifier)
        {
            return new SPDocSpecification((ASN1ObjectIdentifier) obj);
        }
        else if (obj instanceof DERIA5String)
        {
            return new SPDocSpecification((DERIA5String) obj);
        }

        throw new IllegalArgumentException(
                "Unknown object in 'SPDocSpecification' factory : "
                        + obj.getClass().getName() + ".");
    }

    public SPDocSpecification(ASN1ObjectIdentifier oid) {
        this.oid = oid;
        this.uri = null;
    }
    
    public SPDocSpecification(DERIA5String uri) {
        this.oid = null;
        this.uri = uri;
    }

    public ASN1ObjectIdentifier getOid()
    {
        return oid;
    }

    public DERIA5String getUri()
    {
        return uri;
    }

    /**
     * <pre>
     * SPDocSpecification ::= CHOICE {
     *     oid OBJECT IDENTIFIER,
     *     uri IA5String
     * }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        if (this.oid != null)
        {
            return this.oid; 
        }
        return this.uri;
    }
}
