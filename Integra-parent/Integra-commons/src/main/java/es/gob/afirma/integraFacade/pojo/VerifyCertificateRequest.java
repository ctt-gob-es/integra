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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.VerifyCertificateRequest.java.</p>
 * <b>Description:</b><p>Class that represents the request for the service to verify a certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the request for the service to verify a certificate.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class VerifyCertificateRequest implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -5378180663261035557L;

    /**
     * Attribute that represents the certificate to validate.
     */
    private byte[ ] certificate;

    /**
     * Attribute that represents the location of the certificate in a documents manager or documents repository.
     */
    private Repository certificateRepository;

    /**
     * Attribute that represents application identifier.
     */
    private String applicationId;

    /**
     * Attribute that indicates whether the response should return details of validated certificates.
     */
    private Boolean returnReadableCertificateInfo = false;

    /**
     * Attribute that Specifies the validations to be performed on the certificate and the information to be returned in the response.
     */
    private VerificationReport returnVerificationReport;

    /**
     * Constructor method for the class VerifyCertificateRequest.java.
     */
    public VerifyCertificateRequest() {
    }

    /**
     * Gets the value of the attribute {@link #certificate}.
     * @return the value of the attribute {@link #certificate}.
     */
    public final byte[ ] getCertificate() {
	return certificate;
    }

    /**
     * Sets the value of the attribute {@link #certificate}.
     * @param certificateParam The value for the attribute {@link #certificate}.
     */
    public final void setCertificate(byte[ ] certificateParam) {
	if (certificateParam != null) {
	    this.certificate = certificateParam.clone();
	}
    }

    /**
     * Gets the value of the attribute {@link #certificateRepository}.
     * @return the value of the attribute {@link #certificateRepository}.
     */
    public final Repository getCertificateRepository() {
	return certificateRepository;
    }

    /**
     * Sets the value of the attribute {@link #certificateRepository}.
     * @param certificateRepositoryParam The value for the attribute {@link #certificateRepository}.
     */
    public final void setCertificateRepository(Repository certificateRepositoryParam) {
	this.certificateRepository = certificateRepositoryParam;
    }

    /**
     * Gets the value of the attribute {@link #applicationId}.
     * @return the value of the attribute {@link #applicationId}.
     */
    public final String getApplicationId() {
	return applicationId;
    }

    /**
     * Sets the value of the attribute {@link #applicationId}.
     * @param applicationIdParam The value for the attribute {@link #applicationId}.
     */
    public final void setApplicationId(String applicationIdParam) {
	this.applicationId = applicationIdParam;
    }

    /**
     * Gets the value of the attribute {@link #returnReadableCertificateInfo}.
     * @return the value of the attribute {@link #returnReadableCertificateInfo}.
     */
    public final Boolean getReturnReadableCertificateInfo() {
	return returnReadableCertificateInfo;
    }

    /**
     * Sets the value of the attribute {@link #returnReadableCertificateInfo}.
     * @param returnReadableCertificateInfoParam The value for the attribute {@link #returnReadableCertificateInfo}.
     */
    public final void setReturnReadableCertificateInfo(Boolean returnReadableCertificateInfoParam) {
	this.returnReadableCertificateInfo = returnReadableCertificateInfoParam;
    }

    /**
     * Gets the value of the attribute {@link #returnVerificationReport}.
     * @return the value of the attribute {@link #returnVerificationReport}.
     */
    public final VerificationReport getReturnVerificationReport() {
	return returnVerificationReport;
    }

    /**
     * Sets the value of the attribute {@link #returnVerificationReport}.
     * @param returnVerificationReportParam The value for the attribute {@link #returnVerificationReport}.
     */
    public final void setReturnVerificationReport(VerificationReport returnVerificationReportParam) {
	this.returnVerificationReport = returnVerificationReportParam;
    }
}
