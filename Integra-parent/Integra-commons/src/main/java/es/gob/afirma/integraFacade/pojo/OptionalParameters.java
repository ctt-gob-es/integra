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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.OptionalParams.java.</p>
 * <b>Description:</b><p>Class that represents optional parameters to include into a web service request to get more information on the web service
 * response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>21/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/11/2019.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents optional parameters to include into a web service request to get more information on the web service response.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/11/2019.
 */
public class OptionalParameters implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 8180828922377844874L;

    /**
     * Attribute that indicates whether the response should return details of validated certificates.
     */
    private boolean returnReadableCertificateInfo = false;

    /**
     * Attribute that indicates whether you want to get detailed information about the attribute of the signature "TimeStampToken" in the service response.
     */
    private boolean additionalReportOption = false;

    /**
     * Attribute that indicates whether you want to get the result of each verification task.
     */
    private boolean returnProcessingDetails = false;

    /**
     * Attribute that indicates whether the response should return a formal policy document in ASN1 or XML format.
     */
    private boolean returnSignPolicyDocument = false;

    /**
     * Attribute that indicates whether the response should return information about signed data.
     */
    private boolean returnSignedDataInfo = false;

    /**
     * Attribute that indicates whether the response should return the expiration date of the signature.
     */
    private boolean returnNextUpdate = false;
    
    /**
     * Attribute that indicates whether the validation should be process as a no baseline signature.
     */    
    private boolean processAsNotBaseline = false;
    
    /**
     * Attribute that represents the validation level of certificate required. 
     */
    private String certificateValidationLevel;

    /**
     * Constructor method for the class OptionalParams.java.
     */
    public OptionalParameters() {
    }

    /**
     * Gets the value of the attribute {@link #returnReadableCertificateInfo}.
     * @return the value of the attribute {@link #returnReadableCertificateInfo}.
     */
    public final boolean isReturnReadableCertificateInfo() {
	return returnReadableCertificateInfo;
    }

    /**
     * Sets the value of the attribute {@link #returnReadableCertificateInfo}.
     * @param returnReadableCertificateInfoParam The value for the attribute {@link #returnReadableCertificateInfo}.
     */
    public final void setReturnReadableCertificateInfo(boolean returnReadableCertificateInfoParam) {
	this.returnReadableCertificateInfo = returnReadableCertificateInfoParam;
    }

    /**
     * Gets the value of the attribute {@link #additionalReportOption}.
     * @return the value of the attribute {@link #additionalReportOption}.
     */
    public final boolean isAdditionalReportOption() {
	return additionalReportOption;
    }

    /**
     * Sets the value of the attribute {@link #additionalReportOption}.
     * @param additionalReportOptionParam The value for the attribute {@link #additionalReportOption}.
     */
    public final void setAdditionalReportOption(boolean additionalReportOptionParam) {
	this.additionalReportOption = additionalReportOptionParam;
    }

    /**
     * Gets the value of the attribute {@link #returnProcessingDetails}.
     * @return the value of the attribute {@link #returnProcessingDetails}.
     */
    public final boolean isReturnProcessingDetails() {
	return returnProcessingDetails;
    }

    /**
     * Sets the value of the attribute {@link #returnProcessingDetails}.
     * @param returnProcessingDetailsParam The value for the attribute {@link #returnProcessingDetails}.
     */
    public final void setReturnProcessingDetails(boolean returnProcessingDetailsParam) {
	this.returnProcessingDetails = returnProcessingDetailsParam;
    }

    /**
     * Gets the value of the attribute {@link #returnSignedDataInfo}.
     * @return the value of the attribute {@link #returnSignedDataInfo}.
     */
    public final boolean isReturnSignedDataInfo() {
	return returnSignedDataInfo;
    }

    /**
     * Sets the value of the attribute {@link #returnSignedDataInfo}.
     * @param returnSignedDataInfoParam The value for the attribute {@link #returnSignedDataInfo}.
     */
    public final void setReturnSignedDataInfo(boolean returnSignedDataInfoParam) {
	this.returnSignedDataInfo = returnSignedDataInfoParam;
    }

    /**
     * Gets the value of the attribute {@link #returnSignPolicyDocument}.
     * @return the value of the attribute {@link #returnSignPolicyDocument}.
     */
    public final boolean isReturnSignPolicyDocument() {
	return returnSignPolicyDocument;
    }

    /**
     * Sets the value of the attribute {@link #returnSignPolicyDocument}.
     * @param returnSignPolicyDocumentParam The value for the attribute {@link #returnSignPolicyDocument}.
     */
    public final void setReturnSignPolicyDocument(boolean returnSignPolicyDocumentParam) {
	this.returnSignPolicyDocument = returnSignPolicyDocumentParam;
    }

    
    /**
     * Gets the value of the attribute {@link #certificateValidationLevel}.
     * @return the value of the attribute {@link #certificateValidationLevel}.
     */
    public final String getCertificateValidationLevel() {
        return certificateValidationLevel;
    }

    
    /**
     * Sets the value of the attribute {@link #certificateValidationLevel}.
     * @param certificateValidationLevelParam The value for the attribute {@link #certificateValidationLevel}.
     */
    public final void setCertificateValidationLevel(String certificateValidationLevelParam) {
        this.certificateValidationLevel = certificateValidationLevelParam;
    }

    /**
     * Gets the value of the attribute {@link #returnNextUpdate}.
     * @return the value of the attribute {@link #returnNextUpdate}.
     */
    public boolean isReturnNextUpdate() {
        return returnNextUpdate;
    }

    /**
     * Sets the value of the attribute {@link #returnNextUpdate}.
     * @param returnNextUpdateParam The value for the attribute {@link #returnNextUpdate}.
     */
    public void setReturnNextUpdate(boolean returnNextUpdateParam) {
        this.returnNextUpdate = returnNextUpdateParam;
    }

    /**
     * Gets the value of the attribute {@link #processAsNotBaseline}.
     * @return the value of the attribute {@link #processAsNotBaseline}.
     */
    public boolean isProcessAsNotBaseline() {
        return processAsNotBaseline;
    }

    /**
     * Sets the value of the attribute {@link #processAsNotBaseline}.
     * @param returnNextUpdateParam The value for the attribute {@link #processAsNotBaseline}.
     */
    public void setProcessAsNotBaseline(boolean processAsNotBaseline) {
        this.processAsNotBaseline = processAsNotBaseline;
    }
    
}
