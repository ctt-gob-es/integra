package net.java.xades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.TreeMap;

import javax.xml.crypto.MarshalException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 *
 * @author miro
 */
public class BLevelXAdESImpl extends BaseXAdESImpl implements XAdES_B_B_Level
{
    protected boolean readOnlyMode = true;
    protected TreeMap<XAdES.Element, Object> data;
    private final Element baseElement;
    private Document baseDocument;
    private QualifyingProperties qualifyingProperties;

    public String xadesPrefix;
    public String xadesNamespace;
    public String xmlSignaturePrefix;
    public String digestMethod;

    public BLevelXAdESImpl(final Document document, final Element baseElement, final boolean readOnlyMode,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix,
            final String digestMethod)
    {
        this.baseDocument = document;

        if (baseElement != null)
        {
            this.baseDocument = baseElement.getOwnerDocument();
        }

        this.baseElement = baseElement;
        this.readOnlyMode = readOnlyMode;

        this.data = new TreeMap<XAdES.Element, Object>();

        this.xadesPrefix = xadesPrefix;
        this.xadesNamespace = xadesNamespace;
        this.xmlSignaturePrefix = xmlSignaturePrefix;
        this.digestMethod = digestMethod;
    }

    @Override
	public Document getBaseDocument()
    {
        return this.baseDocument;
    }

    @Override
	public Element getBaseElement()
    {
        return this.baseElement;
    }

    @Override
	public String getDigestMethod()
    {
        return this.digestMethod;
    }

    @Override
	public Date getSigningTime()
    {
        return (Date) this.data.get(XAdES.Element.SIGNING_TIME);
    }

    @Override
	public SigningCertificateV2 getSigningCertificateV2()
    {
        return (SigningCertificateV2) this.data.get(XAdES.Element.SIGNING_CERTIFICATE_V2);
    }

    @Override
	public SignatureProductionPlaceV2 getSignatureProductionPlaceV2()
    {
        return (SignatureProductionPlaceV2) this.data.get(XAdES.Element.SIGNATURE_PRODUCTION_PLACE_V2);
    }

    @Override
	public SignerRoleV2 getSignerRoleV2()
    {
        return (SignerRoleV2) this.data.get(XAdES.Element.SIGNER_ROLE_V2);
    }

    @Override
	public Signer getSigner()
    {
        return (Signer) this.data.get(XAdES.Element.SIGNER);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<DataObjectFormat> getDataObjectFormats()
    {
        return (List<DataObjectFormat>) this.data.get(XAdES.Element.DATA_OBJECT_FORMATS);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<CommitmentTypeIndication> getCommitmentTypeIndications()
    {
        return (List<CommitmentTypeIndication>) this.data.get(XAdES.Element.COMMITMENT_TYPE_INDICATIONS);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<AllDataObjectsTimeStamp> getAllDataObjectsTimeStamps()
    {
        return (List<AllDataObjectsTimeStamp>) this.data.get(XAdES.Element.ALL_DATA_OBJECTS_TIMESTAMPS);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<XAdESTimeStamp> getIndividualDataObjectsTimeStamps()
    {
        return (List<XAdESTimeStamp>) this.data.get(XAdES.Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMPS);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<CounterSignature> getCounterSignatures()
    {
        return (List<CounterSignature>) this.data.get(XAdES.Element.COUNTER_SIGNATURES);
    }

    @Override
	public void setSigningTime(final Date signingTime)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (signingTime != null) {
			this.data.put(XAdES.Element.SIGNING_TIME, signingTime);
		} else {
			this.data.remove(XAdES.Element.SIGNING_TIME);
		}
    }

    @Override
	public void setSigningCertificateV2(X509Certificate signingCertificate, SigningCertificateV2Info additionalInfo)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (signingCertificate == null) {
        	this.data.remove(XAdES.Element.SIGNING_CERTIFICATE_V2);
		}
        else {
        	final SigningCertificateV2Impl sci = new SigningCertificateV2Impl(signingCertificate, this.digestMethod);
        	sci.setIssuerSerialV2(additionalInfo != null ? additionalInfo.getIssuerSerialV2() : null);
        	this.data.put(XAdES.Element.SIGNING_CERTIFICATE_V2, sci);
        }
    }

    @Override
	public void setSignatureProductionPlaceV2(final SignatureProductionPlaceV2 productionPlace)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (productionPlace != null) {
			this.data.put(XAdES.Element.SIGNATURE_PRODUCTION_PLACE_V2, productionPlace);
		} else {
			this.data.remove(XAdES.Element.SIGNATURE_PRODUCTION_PLACE_V2);
		}
    }

    @Override
	public void setSignerRoleV2(final SignerRoleV2 signerRole)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (signerRole != null) {
			this.data.put(XAdES.Element.SIGNER_ROLE_V2, signerRole);
		} else {
			this.data.remove(XAdES.Element.SIGNER_ROLE_V2);
		}
    }

    @Override
	public void setSigner(final Signer signer)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (signer != null) {
			this.data.put(XAdES.Element.SIGNER, signer);
		} else {
			this.data.remove(XAdES.Element.SIGNER);
		}
    }

    @Override
	public void setDataObjectFormats(final List<DataObjectFormat> dataObjectFormats)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (dataObjectFormats != null && dataObjectFormats.size() > 0) {
			this.data.put(XAdES.Element.DATA_OBJECT_FORMATS, dataObjectFormats);
		} else {
			this.data.remove(XAdES.Element.DATA_OBJECT_FORMATS);
		}
    }

    @Override
	public void setCommitmentTypeIndications(
            final List<CommitmentTypeIndication> commitmentTypeIndications)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (commitmentTypeIndications != null && commitmentTypeIndications.size() > 0) {
			this.data.put(XAdES.Element.COMMITMENT_TYPE_INDICATIONS, commitmentTypeIndications);
		} else {
			this.data.remove(XAdES.Element.COMMITMENT_TYPE_INDICATIONS);
		}
    }

    @Override
	public void setAllDataObjectsTimeStamps(final List<AllDataObjectsTimeStamp> allDataObjectsTimeStamps)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (allDataObjectsTimeStamps != null && allDataObjectsTimeStamps.size() > 0) {
			this.data.put(XAdES.Element.ALL_DATA_OBJECTS_TIMESTAMPS, allDataObjectsTimeStamps);
		} else {
			this.data.remove(XAdES.Element.ALL_DATA_OBJECTS_TIMESTAMPS);
		}
    }

    @Override
	public void setIndividualDataObjectsTimeStamps(
            final List<IndividualDataObjectsTimeStamp> individualDataObjectsTimeStamps)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (individualDataObjectsTimeStamps != null && individualDataObjectsTimeStamps.size() > 0) {
			this.data.put(XAdES.Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMPS,
                    individualDataObjectsTimeStamps);
		} else {
			this.data.remove(XAdES.Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMPS);
		}
    }

    @Override
	public void setCounterSignatures(final List<CounterSignature> counterSignatures)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
		}

        if (counterSignatures != null && counterSignatures.size() > 0) {
			this.data.put(XAdES.Element.COUNTER_SIGNATURES, counterSignatures);
		} else {
			this.data.remove(XAdES.Element.COUNTER_SIGNATURES);
		}
    }

    // Each implementation have to inherit this method
    // and to return the appropriate XAdES type.
    // This is important for checking cases in new XML Advanced Signature
    protected XAdES getXAdESType()
    {
        return XAdES.B_B_LEVEL;
    }

    protected QualifyingProperties getQualifyingProperties()
    {
        if (this.qualifyingProperties == null)
        {
            final NodeList nl = this.baseElement.getElementsByTagNameNS(this.xadesNamespace,
                    XAdES.Element.QUALIFYING_PROPERTIES.getElementName());
            if (nl != null && nl.getLength() > 0)
            {
                this.qualifyingProperties = new QualifyingProperties(nl.item(0), this.xadesPrefix,
                        this.xadesNamespace, this.xmlSignaturePrefix);
            }
        }

        return this.qualifyingProperties;
    }

    @SuppressWarnings("static-method")
	protected SignedSignatureProperties getSignedSignatureProperties(final QualifyingProperties qp)
    {
        return qp.getSignedProperties().getSignedSignatureProperties();
    }

    @SuppressWarnings("static-method")
	protected SignedDataObjectProperties getSignedDataObjectProperties(final QualifyingProperties qp)
    {
        return qp.getSignedProperties().getSignedDataObjectProperties();
    }

    @SuppressWarnings("static-method")
	protected UnsignedSignatureProperties getUnsignedSignatureProperties(final QualifyingProperties qp)
    {
        return qp.getUnsignedProperties().getUnsignedSignatureProperties();
    }

    @SuppressWarnings("unchecked")
    protected void marshalQualifyingProperties(final QualifyingProperties qp, final String signatureIdPrefix,
            final List referencesIdList) throws MarshalException
    {
        SignedSignatureProperties ssp;
        SignedDataObjectProperties sdop;
        UnsignedSignatureProperties usp;

        try
        {
            for (final XAdES.Element key : XAdES.Element.values())
            {
                if (XAdES.Element.SIGNING_TIME.equals(key))
                {
                    ssp = getSignedSignatureProperties(qp);
                    ssp.setSigningTime();
                }
                else
                {
                    final Object value = this.data.get(key);

                    if (value != null)
                    {
                        if (XAdES.Element.SIGNER.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSigner((Signer) value);
                        }
                        else if (XAdES.Element.SIGNING_CERTIFICATE_V2.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSigningCertificateV2((SigningCertificateV2) value);
                        }
                        else if (XAdES.Element.SIGNATURE_POLICY_IDENTIFIER.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignaturePolicyIdentifier((SignaturePolicyIdentifier) value);
                        }
                        else if (XAdES.Element.SIGNATURE_PRODUCTION_PLACE_V2.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignatureProductionPlaceV2((SignatureProductionPlaceV2) value);
                        }
                        else if (XAdES.Element.SIGNER_ROLE_V2.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignerRoleV2((SignerRoleV2) value);
                        }
                        else if (XAdES.Element.DATA_OBJECT_FORMATS.equals(key))
                        {
                            sdop = getSignedDataObjectProperties(qp);
                            sdop.setDataObjectFormat((ArrayList<DataObjectFormat>) value);
                        }
                        else if (XAdES.Element.COMMITMENT_TYPE_INDICATIONS.equals(key))
                        {
                            // TODO: Manage CommitmentTypeIndication as a ArrayList
                            sdop = getSignedDataObjectProperties(qp);
                            sdop.setCommitmentTypeIndications((ArrayList<CommitmentTypeIndication>) value);
                        }
                        else if (XAdES.Element.SIGNATURE_POLICY_STORE.equals(key))
                        {
                            usp = getUnsignedSignatureProperties(qp);
                            usp.setSignaturePolicyStore((SignaturePolicyStore) value);
                        }
                    }
                }
            }
        }
        catch (final GeneralSecurityException ex)
        {
            throw new MarshalException(ex);
        }
    }
    
    @SuppressWarnings("unchecked")
    protected void marshalQualifyingProperties(final QualifyingProperties qp, final String signatureIdPrefix,
            final List referencesIdList, String tsaUrl) throws MarshalException
    {
        SignedSignatureProperties ssp;
        SignedDataObjectProperties sdop;
	UnsignedSignatureProperties usp;

        try
        {
            for (final XAdES.Element key : XAdES.Element.values())
            {
                if (XAdES.Element.SIGNING_TIME.equals(key))
                {
                    ssp = getSignedSignatureProperties(qp);
                    ssp.setSigningTime();
                }
                else
                {
                    final Object value = this.data.get(key);

                    if (value != null)
                    {
                        if (XAdES.Element.SIGNER.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSigner((Signer) value);
                        }
                        else if (XAdES.Element.SIGNING_CERTIFICATE_V2.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSigningCertificateV2((SigningCertificateV2) value);
                        }
                        else if (XAdES.Element.SIGNATURE_POLICY_IDENTIFIER.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignaturePolicyIdentifier((SignaturePolicyIdentifier) value);
                        }
                        else if (XAdES.Element.SIGNATURE_PRODUCTION_PLACE_V2.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignatureProductionPlaceV2((SignatureProductionPlaceV2) value);
                        }
                        else if (XAdES.Element.SIGNER_ROLE_V2.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignerRoleV2((SignerRoleV2) value);
                        }
                        else if (XAdES.Element.DATA_OBJECT_FORMATS.equals(key))
                        {
                            sdop = getSignedDataObjectProperties(qp);
                            sdop.setDataObjectFormat((ArrayList<DataObjectFormat>) value);
                        }
                        else if (XAdES.Element.COMMITMENT_TYPE_INDICATIONS.equals(key))
                        {
                            // TODO: Manage CommitmentTypeIndication as a ArrayList
                            sdop = getSignedDataObjectProperties(qp);
                            sdop.setCommitmentTypeIndications((ArrayList<CommitmentTypeIndication>) value);
                        }
                        else if (XAdES.Element.ALL_DATA_OBJECTS_TIMESTAMPS.equals(key))
                        {
                            sdop = getSignedDataObjectProperties(qp);
                            sdop.setAllDataObjectsTimeStamp((ArrayList<AllDataObjectsTimeStamp>) value, tsaUrl);
                        }
                        else if (XAdES.Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMPS.equals(key))
                        {
                            sdop = getSignedDataObjectProperties(qp);
                            sdop.setIndividualDataObjectsTimeStamp((ArrayList<IndividualDataObjectsTimeStamp>) value, tsaUrl);
                        }
                        else if (XAdES.Element.SIGNATURE_TIME_STAMP.equals(key))
                        {
                            usp = getUnsignedSignatureProperties(qp);
                            usp.setSignatureTimeStamp((ArrayList<SignatureTimeStamp>) value, tsaUrl);
                        }
                        else if (XAdES.Element.COMPLETE_CERTIFICATE_REFS.equals(key))
                        {
                            usp = getUnsignedSignatureProperties(qp);
                            usp.setCompleteCertificateRefs((Collection<X509Certificate>) value, signatureIdPrefix);
                        }
                        else if (XAdES.Element.SIGNATURE_POLICY_STORE.equals(key))
                        {
                            usp = getUnsignedSignatureProperties(qp);
                            usp.setSignaturePolicyStore((SignaturePolicyStore) value);
                        }
                    }
                }
            }
        }
        catch (final GeneralSecurityException ex)
        {
            throw new MarshalException(ex);
        }
    }
    
    @Override
    public String getXadesPrefix()
    {
	return this.xadesPrefix;
    }

    @Override
    public String getXmlSignaturePrefix()
    {
	return this.xmlSignaturePrefix;
    }

    @Override
    public String getXadesNamespace()
    {
	return this.xadesNamespace;
    }

    @Override
    public void setSignaturePolicyIdentifier(SignaturePolicyIdentifier signaturePolicyIdentifier)
    {
	if (this.readOnlyMode)
	{
	    throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
	}

	if (signaturePolicyIdentifier != null)
	{
	    this.data.put(XAdES.Element.SIGNATURE_POLICY_IDENTIFIER, signaturePolicyIdentifier);
	}
	else
	{
	    this.data.remove(XAdES.Element.SIGNATURE_POLICY_IDENTIFIER);
	}
    }

    @Override
    public SignaturePolicyIdentifier getSignaturePolicyIdentifier()
    {
	return (SignaturePolicyIdentifier) this.data.get(XAdES.Element.SIGNATURE_POLICY_IDENTIFIER);
    }


    @Override
    public void setSignaturePolicyStore(SignaturePolicyStore signaturePolicyStore)
    {
	if (this.readOnlyMode)
	{
	    throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
	}

	if (signaturePolicyStore != null)
	{
	    this.data.put(XAdES.Element.SIGNATURE_POLICY_STORE, signaturePolicyStore);
	}
	else
	{
	    this.data.remove(XAdES.Element.SIGNATURE_POLICY_STORE);
	}
    }

    @Override
    public SignaturePolicyStore getSignaturePolicyStore()
    {
	return (SignaturePolicyStore) this.data.get(XAdES.Element.SIGNATURE_POLICY_STORE);
    }
}
