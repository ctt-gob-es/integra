// Copyright (C) 2012-13 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.VerificationReport.java.</p>
 * <b>Description:</b><p>Class that specifies the validations to be performed on the specified firm and the information to be returned in the response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>21/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 21/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that specifies the validations to be performed on the specified firm and the information to be returned in the response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 21/11/2014.
 */
public class VerificationReport implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -2048840373964643015L;

    /**
     * Attribute that indicates whether you want to verify the revocation status of the certificate.
     */
    private Boolean checkCertificateStatus = true;

    /**
     * Attribute that indicates whether the response includes certificate validated.
     */
    private Boolean includeCertificateValues = false;

    /**
     * Attribute that indicates whether the response includes elements revocation status query.
     */
    private Boolean includeRevocationValues = false;

    /**
     * Attribute that specifies the level of detail you want to get in the service response.
     */
    private DetailLevelEnum reportDetailLevel;

    /**
     * Constructor method for the class VerificationReport.java.
     */
    public VerificationReport() {
    }

    /**
     * Gets the value of the attribute {@link #checkCertificateStatus}.
     * @return the value of the attribute {@link #checkCertificateStatus}.
     */
    public final Boolean getCheckCertificateStatus() {
	return checkCertificateStatus;
    }

    /**
     * Sets the value of the attribute {@link #checkCertificateStatus}.
     * @param checkCertificateStatusParam The value for the attribute {@link #checkCertificateStatus}.
     */
    public final void setCheckCertificateStatus(Boolean checkCertificateStatusParam) {
	this.checkCertificateStatus = checkCertificateStatusParam;
    }

    /**
     * Gets the value of the attribute {@link #includeCertificateValues}.
     * @return the value of the attribute {@link #includeCertificateValues}.
     */
    public final Boolean getIncludeCertificateValues() {
	return includeCertificateValues;
    }

    /**
     * Sets the value of the attribute {@link #includeCertificateValues}.
     * @param includeCertificateValuesParam The value for the attribute {@link #includeCertificateValues}.
     */
    public final void setIncludeCertificateValues(Boolean includeCertificateValuesParam) {
	this.includeCertificateValues = includeCertificateValuesParam;
    }

    /**
     * Gets the value of the attribute {@link #includeRevocationValues}.
     * @return the value of the attribute {@link #includeRevocationValues}.
     */
    public final Boolean getIncludeRevocationValues() {
	return includeRevocationValues;
    }

    /**
     * Sets the value of the attribute {@link #includeRevocationValues}.
     * @param includeRevocationValuesParam The value for the attribute {@link #includeRevocationValues}.
     */
    public final void setIncludeRevocationValues(Boolean includeRevocationValuesParam) {
	this.includeRevocationValues = includeRevocationValuesParam;
    }

    /**
     * Gets the value of the attribute {@link #reportDetailLevel}.
     * @return the value of the attribute {@link #reportDetailLevel}.
     */
    public final DetailLevelEnum getReportDetailLevel() {
	return reportDetailLevel;
    }

    /**
     * Sets the value of the attribute {@link #reportDetailLevel}.
     * @param reportDetailLevelParam The value for the attribute {@link #reportDetailLevel}.
     */
    public final void setReportDetailLevel(DetailLevelEnum reportDetailLevelParam) {
	this.reportDetailLevel = reportDetailLevelParam;
    }

}
