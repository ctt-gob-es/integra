package net.java.xades.security.xml.XAdES;

import java.util.Date;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public interface XAdESBase {

    public Element getBaseElement();
    public Document getBaseDocument();

    public Date getSigningTime();
    public void setSigningTime(Date signingTime);

    public Signer getSigner();
    public void setSigner(Signer signer);

    public List<DataObjectFormat> getDataObjectFormats();
    public void setDataObjectFormats(List<DataObjectFormat> dataObjectFormats);

    public List<CommitmentTypeIndication> getCommitmentTypeIndications();
    public void setCommitmentTypeIndications(List<CommitmentTypeIndication> commitmentTypeIndications);

    public List<AllDataObjectsTimeStamp> getAllDataObjectsTimeStamps();
    public void setAllDataObjectsTimeStamps(List<AllDataObjectsTimeStamp> allDataObjectsTimeStamps);

    public List<XAdESTimeStamp> getIndividualDataObjectsTimeStamps();
    public void setIndividualDataObjectsTimeStamps(List<IndividualDataObjectsTimeStamp> individualDataObjectsTimeStamps);

    public List<CounterSignature> getCounterSignatures();
    public void setCounterSignatures(List<CounterSignature> counterSignatures);   
    
    public String getXadesPrefix();
    public String getXadesNamespace();
    public String getXmlSignaturePrefix();
    public String getDigestMethod();
}
