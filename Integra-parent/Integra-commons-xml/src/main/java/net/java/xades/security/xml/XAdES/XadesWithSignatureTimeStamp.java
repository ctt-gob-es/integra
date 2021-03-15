package net.java.xades.security.xml.XAdES;

import java.util.List;

public interface XadesWithSignatureTimeStamp {

    List<SignatureTimeStamp> getSignatureTimeStamps();
    void setSignatureTimeStamps(List<SignatureTimeStamp> signatureTimeStamps);
}
