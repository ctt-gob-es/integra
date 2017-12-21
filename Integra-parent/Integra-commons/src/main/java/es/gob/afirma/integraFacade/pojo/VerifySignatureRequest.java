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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.VerifySignatureRequest.java.</p>
 * <b>Description:</b><p>Class that represents the request for the service to verify a signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>21/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 21/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the request for the service to verify a signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 21/11/2014.
 */
public class VerifySignatureRequest implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -2511525560777219003L;

    /**
     * Attribute that contains the signed document to verify.
     */
    private byte[ ] document;

    /**
     * Attribute that contains the hash of the original data for verification with respect to the data included in the signature.
     */
    private DocumentHash documentHash;

    /**
     * Attribute that represents the location of a document in a document manager or repository.
     */
    private Repository documentRepository;

    /**
     * Attribute that contains the signature to verify.
     */
    private byte[ ] signature;

    /**
     * Attribute that represents the location of a signature in a document manager or repository.
     */
    private Repository signatureRepository;

    /**
     * Attribute that represents application identifier.
     */
    private String applicationId;

    /**
     * Attribute that specifies the validations to be performed on the specified signature and the information to be returned in the response.
     */
    private VerificationReport returnVerificationReport;

    /**
     * Attribute that represents optional parameters in the request to get more information in the response.
     */
    private OptionalParameters optionalParameters;

    /**
     * Constructor method for the class VerifySignatureRequest.java.
     */
    public VerifySignatureRequest() {
    }

    /**
     * Gets the value of the attribute {@link #document}.
     * @return the value of the attribute {@link #document}.
     */
    public final byte[ ] getDocument() {
	return document;
    }

    /**
     * Sets the value of the attribute {@link #document}.
     * @param documentParam The value for the attribute {@link #document}.
     */
    public final void setDocument(byte[ ] documentParam) {
	if (documentParam != null) {
	    this.document = documentParam.clone();
	}
    }

    /**
     * Gets the value of the attribute {@link #documentHash}.
     * @return the value of the attribute {@link #documentHash}.
     */
    public final DocumentHash getDocumentHash() {
	return documentHash;
    }

    /**
     * Sets the value of the attribute {@link #documentHash}.
     * @param documentHashParam The value for the attribute {@link #documentHash}.
     */
    public final void setDocumentHash(DocumentHash documentHashParam) {
	this.documentHash = documentHashParam;
    }

    /**
     * Gets the value of the attribute {@link #documentRepository}.
     * @return the value of the attribute {@link #documentRepository}.
     */
    public final Repository getDocumentRepository() {
	return documentRepository;
    }

    /**
     * Sets the value of the attribute {@link #documentRepository}.
     * @param documentRepositoryParam The value for the attribute {@link #documentRepository}.
     */
    public final void setDocumentRepository(Repository documentRepositoryParam) {
	this.documentRepository = documentRepositoryParam;
    }

    /**
     * Gets the value of the attribute {@link #signature}.
     * @return the value of the attribute {@link #signature}.
     */
    public final byte[ ] getSignature() {
	return signature;
    }

    /**
     * Sets the value of the attribute {@link #signature}.
     * @param signatureParam The value for the attribute {@link #signature}.
     */
    public final void setSignature(byte[ ] signatureParam) {
	if (signatureParam != null) {
	    this.signature = signatureParam.clone();
	}
    }

    /**
     * Gets the value of the attribute {@link #signatureRepository}.
     * @return the value of the attribute {@link #signatureRepository}.
     */
    public final Repository getSignatureRepository() {
	return signatureRepository;
    }

    /**
     * Sets the value of the attribute {@link #signatureRepository}.
     * @param signatureRepositoryParam The value for the attribute {@link #signatureRepository}.
     */
    public final void setSignatureRepository(Repository signatureRepositoryParam) {
	this.signatureRepository = signatureRepositoryParam;
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
     * Gets the value of the attribute {@link #returnVerificationReport}.
     * @return the value of the attribute {@link #returnVerificationReport}.
     */
    public final VerificationReport getVerificationReport() {
	return returnVerificationReport;
    }

    /**
     * Sets the value of the attribute {@link #returnVerificationReport}.
     * @param returnVerificationReportParam The value for the attribute {@link #returnVerificationReport}.
     */
    public final void setVerificationReport(VerificationReport returnVerificationReportParam) {
	this.returnVerificationReport = returnVerificationReportParam;
    }

    /**
     * Gets the value of the attribute {@link #optionalParameters}.
     * @return the value of the attribute {@link #optionalParameters}.
     */
    public final OptionalParameters getOptionalParameters() {
	return optionalParameters;
    }

    /**
     * Sets the value of the attribute {@link #optionalParameters}.
     * @param optionalParametersParam The value for the attribute {@link #optionalParameters}.
     */
    public final void setOptionalParameters(OptionalParameters optionalParametersParam) {
	this.optionalParameters = optionalParametersParam;
    }
}
