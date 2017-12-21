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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.IndividualSignatureReport.java.</p>
 * <b>Description:</b><p>Class that contains detailed information of verification processes performed.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 24/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;
import java.util.Map;

/**
 * <p>Class that contains detailed information of verification processes performed.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/11/2014.
 */
public class IndividualSignatureReport implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 1927638793981507260L;

    /**
     * Attribute that represents the result of the process.
     */
    private Result result;

    /**
     * Attribute that contains details of the signer certificate.
     */
    private Map<String, Object> readableCertificateInfo;

    /**
     * Attribute that represents the identifier of the signature policy.
     */
    private String signaturePolicyIdentifier;

    /**
     * Attribute that represents the document that specifies the signature policy.
     */
    private byte[ ] sigPolicyDocument;

    /**
     * Attribute that contains the result of the different steps involved in the process of verifying an electronic signature.
     */
    private ProcessingDetail processingDetails;

    /**
     * Attribute that contains additional information resulting from the processing signature.
     */
    private String detailedReport;

    /**
     * Constructor method for the class IndividualSignatureReport.java.
     */
    public IndividualSignatureReport() {
    }

    /**
     * Gets the value of the attribute {@link #result}.
     * @return the value of the attribute {@link #result}.
     */
    public final Result getResult() {
	return result;
    }

    /**
     * Sets the value of the attribute {@link #result}.
     * @param resultParam The value for the attribute {@link #result}.
     */
    public final void setResult(Result resultParam) {
	this.result = resultParam;
    }

    /**
     * Gets the value of the attribute {@link #readableCertificateInfo}.
     * @return the value of the attribute {@link #readableCertificateInfo}.
     */
    public final Map<String, Object> getReadableCertificateInfo() {
	return readableCertificateInfo;
    }

    /**
     * Sets the value of the attribute {@link #readableCertificateInfo}.
     * @param readableCertificateInfoParam The value for the attribute {@link #readableCertificateInfo}.
     */
    public final void setReadableCertificateInfo(Map<String, Object> readableCertificateInfoParam) {
	this.readableCertificateInfo = readableCertificateInfoParam;
    }

    /**
     * Gets the value of the attribute {@link #signaturePolicyIdentifier}.
     * @return the value of the attribute {@link #signaturePolicyIdentifier}.
     */
    public final String getSignaturePolicyIdentifier() {
	return signaturePolicyIdentifier;
    }

    /**
     * Sets the value of the attribute {@link #signaturePolicyIdentifier}.
     * @param signaturePolicyIdentifierParam The value for the attribute {@link #signaturePolicyIdentifier}.
     */
    public final void setSignaturePolicyIdentifier(String signaturePolicyIdentifierParam) {
	this.signaturePolicyIdentifier = signaturePolicyIdentifierParam;
    }

    /**
     * Gets the value of the attribute {@link #sigPolicyDocument}.
     * @return the value of the attribute {@link #sigPolicyDocument}.
     */
    public final byte[ ] getSigPolicyDocument() {
	return sigPolicyDocument;
    }

    /**
     * Sets the value of the attribute {@link #sigPolicyDocument}.
     * @param sigPolicyDocumentParam The value for the attribute {@link #sigPolicyDocument}.
     */
    public final void setSigPolicyDocument(byte[ ] sigPolicyDocumentParam) {
	if (sigPolicyDocumentParam != null) {
	    this.sigPolicyDocument = sigPolicyDocumentParam.clone();
	}
    }

    /**
     * Gets the value of the attribute {@link #processingDetails}.
     * @return the value of the attribute {@link #processingDetails}.
     */
    public final ProcessingDetail getProcessingDetails() {
	return processingDetails;
    }

    /**
     * Sets the value of the attribute {@link #processingDetails}.
     * @param processingDetailsParam The value for the attribute {@link #processingDetails}.
     */
    public final void setProcessingDetails(ProcessingDetail processingDetailsParam) {
	this.processingDetails = processingDetailsParam;
    }

    /**
     * Gets the value of the attribute {@link #detailedReport}.
     * @return the value of the attribute {@link #detailedReport}.
     */
    public final String getDetailedReport() {
	return detailedReport;
    }

    /**
     * Sets the value of the attribute {@link #detailedReport}.
     * @param detailedReportParam The value for the attribute {@link #detailedReport}.
     */
    public final void setDetailedReport(String detailedReportParam) {
	this.detailedReport = detailedReportParam;
    }

}
