// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.TslRevocationStatus.java.</p>
 * <b>Description:</b><p>Class that represents structure of a TSL revocation status.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;

import es.gob.afirma.tsl.elements.json.ByteArrayB64;
import es.gob.afirma.tsl.elements.json.DateString;


/** 
 * <p>Class that represents structure of a TSL revocation status.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class TslRevocationStatus implements Serializable {

    /**
     * Attribute that represents . 
     */
    private static final long serialVersionUID = -5363107298313176833L;
    /**
	 * Attribute that represents the revocation status in TSL revocation status.
	 */
	private Integer revocationStatus;

	/**
	 * Attribute that represents the revocation description in TSL revocation status.
	 */
	private String revocationDesc;

	/**
	 * Attribute that represents if is from service status in TSL revocation status.
	 */
	private Boolean isFromServStat;

	/**
	 * Attribute that represents the URL in TSL revocation status.
	 */
	private String url;

	/**
	 * Attribute that represents the DP-AIA in TSL revocation status.
	 */
	private Boolean dpAia;

	/**
	 * Attribute that represents the TSP Service Information which has validated the certificate.
	 */
	private TspServiceInformation tspServiceInformation;

	/**
	 * Attribute that represents the evidence type in TSL revocation status.
	 */
	private Integer evidenceType;

	/**
	 * Attribute that represents the evidence in TSL revocation status.
	 */
	private ByteArrayB64 evidence;

	/**
	 * Attribute that represents the revocation reason of the certificate.
	 */
	private Integer revocationReason;

	/**
	 * Attribute that represents the revocation date of the certificate.
	 */
	private DateString revocationDate;

	/**
	 * Gets the value of the attribute {@link #revocationStatus}.
	 * @return the value of the attribute {@link #revocationStatus}.
	 */
	public final Integer getRevocationStatus() {
		return revocationStatus;
	}

	/**
	 * Sets the value of the attribute {@link #revocationStatus}.
	 * @param revocationStatusP The value for the attribute {@link #revocationStatus}.
	 */
	public final void setRevocationStatus(final Integer revocationStatusP) {
		this.revocationStatus = revocationStatusP;
	}

	/**
	 * Gets the value of the attribute {@link #revocationDescription}.
	 * @return the value of the attribute {@link #revocationDescription}.
	 */
	public final String getRevocationDesc() {
		return revocationDesc;
	}

	/**
	 * Sets the value of the attribute {@link #revocationDesc}.
	 * @param revocationDescP The value for the attribute {@link #revocationDesc}.
	 */
	public final void setRevocationDesc(final String revocationDescP) {
		this.revocationDesc = revocationDescP;
	}

	/**
	 * Gets the value of the attribute {@link #isFromServStat}.
	 * @return the value of the attribute {@link #isFromServStat}.
	 */
	public final Boolean getIsFromServStat() {
		return isFromServStat;
	}

	/**
	 * Sets the value of the attribute {@link #isFromServStat}.
	 * @param isFromServStatP The value for the attribute {@link #isFromServStat}.
	 */
	public final void setIsFromServStat(final Boolean isFromServStatP) {
		this.isFromServStat = isFromServStatP;
	}

	/**
	 * Gets the value of the attribute {@link #url}.
	 * @return the value of the attribute {@link #url}.
	 */
	public final String getUrl() {
		return url;
	}

	/**
	 * Sets the value of the attribute {@link #url}.
	 * @param urlParam The value for the attribute {@link #url}.
	 */
	public final void setUrl(final String urlParam) {
		this.url = urlParam;
	}

	/**
	 * Gets the value of the attribute {@link #dpAia}.
	 * @return the value of the attribute {@link #dpAia}.
	 */
	public Boolean getDpAia() {
		return dpAia;
	}

	/**
	 * Sets the value of the attribute {@link #dpAia}.
	 * @param dpAiaParam The value for the attribute {@link #dpAia}.
	 */
	public void setDpAia(final Boolean dpAiaParam) {
		this.dpAia = dpAiaParam;
	}

	/**
	 * Gets the value of the attribute {@link #tspServiceInformation}.
	 * @return the value of the attribute {@link #tspServiceInformation}.
	 */
	public final TspServiceInformation getTspServiceInformation() {
		return tspServiceInformation;
	}

	/**
	 * Sets the value of the attribute {@link #tspServiceInformation}.
	 * @param tspServiceInformationParam The value for the attribute {@link #tspServiceInformation}.
	 */
	public final void setTspServiceInformation(TspServiceInformation tspServiceInformationParam) {
		this.tspServiceInformation = tspServiceInformationParam;
	}

	/**
	 * Gets the value of the attribute {@link #evidenceType}.
	 * @return the value of the attribute {@link #evidenceType}.
	 */
	public final Integer getEvidenceType() {
		return evidenceType;
	}

	/**
	 * Sets the value of the attribute {@link #evidenceType}.
	 * @param evidenceTypeParam The value for the attribute {@link #evidenceType}.
	 */
	public final void setEvidenceType(final Integer evidenceTypeParam) {
		this.evidenceType = evidenceTypeParam;
	}

	/**
	 * Gets the value of the attribute {@link #evidence}.
	 * @return the value of the attribute {@link #evidence}.
	 */
	public final ByteArrayB64 getEvidence() {
		return evidence;
	}

	/**
	 * Sets the value of the attribute {@link #evidence}.
	 * @param evidenceParam The value for the attribute {@link #evidence}.
	 */
	public final void setEvidence(final ByteArrayB64 evidenceParam) {
		this.evidence = evidenceParam;
	}

	/**
	 * Gets the value of the attribute {@link #revocationReason}.
	 * @return the value of the attribute {@link #revocationReason}.
	 */
	public final Integer getRevocationReason() {
		return revocationReason;
	}

	/**
	 * Sets the value of the attribute {@link #revocationReason}.
	 * @param revocationReasonParam The value for the attribute {@link #revocationReason}.
	 */
	public final void setRevocationReason(Integer revocationReasonParam) {
		this.revocationReason = revocationReasonParam;
	}

	/**
	 * Gets the value of the attribute {@link #revocationDate}.
	 * @return the value of the attribute {@link #revocationDate}.
	 */
	public final DateString getRevocationDate() {
		return revocationDate;
	}

	/**
	 * Sets the value of the attribute {@link #revocationDate}.
	 * @param revocationDateParam The value for the attribute {@link #revocationDate}.
	 */
	public final void setRevocationDate(DateString revocationDateParam) {
		this.revocationDate = revocationDateParam;
	}
}
