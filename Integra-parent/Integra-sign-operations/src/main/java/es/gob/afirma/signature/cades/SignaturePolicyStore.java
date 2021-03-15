package es.gob.afirma.signature.cades;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

public class SignaturePolicyStore extends ASN1Encodable {
    
    private SPDocSpecification  spDocSpec;
    private SignaturePolicyDocument spDocument;

    public static SignaturePolicyStore getInstance(Object obj) {
        if (obj == null || obj instanceof SignaturePolicyStore)
        {
            return (SignaturePolicyStore) obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new SignaturePolicyStore((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException(
                "Unknown object in 'SignaturePolicyStore' factory : "
                        + obj.getClass().getName() + ".");
    }

    public SignaturePolicyStore(ASN1Sequence seq) {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        spDocSpec = SPDocSpecification.getInstance(seq.getObjectAt(0));
        spDocument = SignaturePolicyDocument.getInstance(seq.getObjectAt(1));
    }

    public SignaturePolicyStore(
	SPDocSpecification  	spDocSpec,
	SignaturePolicyDocument	spDocument)
    {
        this.spDocSpec = spDocSpec;
        this.spDocument = spDocument;
    }

    public SPDocSpecification getSPDocSpec()
    {
        return spDocSpec;
    }

    public SignaturePolicyDocument getSpDocument()
    {
        return spDocument;
    }

    /**
     * <pre>
     * SignaturePolicyStore ::= SEQUENCE {
     *     spDocSpec SPDocSpecification ,
     * 	   spDocument SignaturePolicyDocument
     * }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(spDocSpec);
        v.add(spDocument);

        return new DERSequence(v);
    }
}
