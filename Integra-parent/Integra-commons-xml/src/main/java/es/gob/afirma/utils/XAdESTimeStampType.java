// Copyright (C) 2017 MINHAP, Gobierno de España
// This program is licensed and may be used, modified and redistributed under the terms
// of the European Public License (EUPL), either version 1.1 or (at your
// option) any later version as soon as they are approved by the European Commission.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and
// more details.
// You should have received a copy of the EUPL1.1 license
// along with this program; if not, you may find it at
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/**
 * <b>File:</b><p>es.gob.afirma.utils.XAdESTimeStampType.java.</p>
 * <b>Description:</b><p>Class that contains information related to a time-stamp contained inside of a XML signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>08/08/2016.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.utils;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Element;

/**
 * <p>Class that contains information related to a time-stamp contained inside of a XML signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public class XAdESTimeStampType implements Serializable, Comparable<XAdESTimeStampType> {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 848299532795539565L;

    /**
     * Attribute that represents the value of the <code>Id</code> attribute.
     */
    private String id;

    /**
     * Attribute that represents the generation time of the time-stamp.
     */
    private Date timestampGenerationDate;

    /**
     * Attribute that represents the ASN.1 time-stamp contained inside.
     */
    private TimeStampToken asn1Timestamp;

    /**
     * Attribute that represents the XML time-stamp contained inside.
     */
    private Element xmlTimestamp;

    /**
     * Attribute that represents the signing certificate of the time-stamp contained inside.
     */
    private X509Certificate tstCertificate = null;

    /**
     * Attribute that represents the canonicalization algorithm used to calculate the stamped data.
     */
    private String canonicalizationAlgorithm = null;

    /**
     * Gets the value of the attribute {@link #id}.
     * @return the value of the attribute {@link #id}.
     */
    public final String getId() {
	return id;
    }

    /**
     * Sets the value of the attribute {@link #id}.
     * @param idParam The value for the attribute {@link #id}.
     */
    public final void setId(String idParam) {
	this.id = idParam;
    }

    /**
     * Gets the value of the attribute {@link #timestampGenerationDate}.
     * @return the value of the attribute {@link #timestampGenerationDate}.
     */
    public final Date getTimestampGenerationDate() {
	return timestampGenerationDate;
    }

    /**
     * Sets the value of the attribute {@link #timestampGenerationDate}.
     * @param timestampGenerationDateParam The value for the attribute {@link #timestampGenerationDate}.
     */
    public final void setTimestampGenerationDate(Date timestampGenerationDateParam) {
	this.timestampGenerationDate = timestampGenerationDateParam;
    }

    /**
     * Gets the value of the attribute {@link #asn1Timestamp}.
     * @return the value of the attribute {@link #asn1Timestamp}.
     */
    public final TimeStampToken getAsn1Timestamp() {
	return asn1Timestamp;
    }

    /**
     * Sets the value of the attribute {@link #asn1Timestamp}.
     * @param asn1TimestampParam The value for the attribute {@link #asn1Timestamp}.
     */
    public final void setAsn1Timestamp(TimeStampToken asn1TimestampParam) {
	this.asn1Timestamp = asn1TimestampParam;
    }

    /**
     * Gets the value of the attribute {@link #xmlTimestamp}.
     * @return the value of the attribute {@link #xmlTimestamp}.
     */
    public final Element getXmlTimestamp() {
	return xmlTimestamp;
    }

    /**
     * Sets the value of the attribute {@link #xmlTimestamp}.
     * @param xmlTimestampParam The value for the attribute {@link #xmlTimestamp}.
     */
    public final void setXmlTimestamp(Element xmlTimestampParam) {
	this.xmlTimestamp = xmlTimestampParam;
    }

    /**
     * Gets the value of the attribute {@link #tstCertificate}.
     * @return the value of the attribute {@link #tstCertificate}.
     */
    public final X509Certificate getTstCertificate() {
	return tstCertificate;
    }

    /**
     * Sets the value of the attribute {@link #tstCertificate}.
     * @param tstCertificateParam The value for the attribute {@link #tstCertificate}.
     */
    public final void setTstCertificate(X509Certificate tstCertificateParam) {
	this.tstCertificate = tstCertificateParam;
    }

    /**
     * {@inheritDoc}
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    @Override
    public final int compareTo(XAdESTimeStampType o) {
	return timestampGenerationDate.compareTo(o.getTimestampGenerationDate());
    }

    /**
     * Gets the value of the attribute {@link #canonicalizationAlgorithm}.
     * @return the value of the attribute {@link #canonicalizationAlgorithm}.
     */
    public final String getCanonicalizationAlgorithm() {
	return canonicalizationAlgorithm;
    }

    /**
     * Sets the value of the attribute {@link #canonicalizationAlgorithm}.
     * @param canonicalizationAlgorithmParam The value for the attribute {@link #canonicalizationAlgorithm}.
     */
    public final void setCanonicalizationAlgorithm(String canonicalizationAlgorithmParam) {
	this.canonicalizationAlgorithm = canonicalizationAlgorithmParam;
    }

}
