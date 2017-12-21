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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.RequestEvisorGenerateReport.java.</p>
 * <b>Description:</b><p> Class that represents the request object for eVisor generate report service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import java.util.List;

/** 
 * <p>Class that represents the request object for eVisor generate report service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class RequestEvisorGenerateReport {

    /**
     * Attribute that represents id of WS client. 
     */
    private String idClient;

    /**
     * Attribute that represents id of application of evisor used for generate report. 
     */
    private String applicationId;

    /**
     * Attribute that represents if of template used for evisor to generate report. 
     */
    private String templateId;

    /**
     * Attribute that represents signature. 
     */
    private byte[] signature;

    /**
     * Attribute that represents id of object in repository. 
     */
    private String signRepositoryObjectId;

    /**
     * Attribute that represents id of repository. 
     */
    private String signRepositoryRepositoryId;

    /**
     * Attribute that represents validation response value (true or false). 
     */
    private byte[] validationResponse;

    /**
     * Attribute that represents document used in report. 
     */
    private byte[] document;

    /**
     * Attribute that represents id of repository. 
     */
    private String docRepositoryLocationRepositoryId;

    /**
     * Attribute that represents id of object in repository. 
     */
    private String docRepositoryLocationObjectId;

    /**
     * Attribute that represents if signature will be included in report (true or false). 
     */
    private String includeSignature;

    /**
     * Attribute that represents a list of barcode elements to include in report. 
     */
    private List<BarcodeEvisorRequest> barcodeList;

    /**
     * Attribute that represents a list of external parameters to generate report. 
     */
    private List<ParameterEvisorRequest> externalParameterList;

    /**
     * Gets the value of the attribute {@link #idClient}.
     * @return the value of the attribute {@link #idClient}.
     */
    public final String getIdClient() {
	return idClient;
    }

    /**
     * Sets the value of the attribute {@link #idClient}.
     * @param idClientParam The value for the attribute {@link #idClient}.
     */
    public final void setIdClient(String idClientParam) {
	this.idClient = idClientParam;
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
     * Gets the value of the attribute {@link #templateId}.
     * @return the value of the attribute {@link #templateId}.
     */
    public final String getTemplateId() {
	return templateId;
    }

    /**
     * Sets the value of the attribute {@link #templateId}.
     * @param templateIdParam The value for the attribute {@link #templateId}.
     */
    public final void setTemplateId(String templateIdParam) {
	this.templateId = templateIdParam;
    }

    /**
     * Gets the value of the attribute {@link #signature}.
     * @return the value of the attribute {@link #signature}.
     */
    public final byte[] getSignature() {
	return signature;
    }

    /**
     * Sets the value of the attribute {@link #signature}.
     * @param signatureParam The value for the attribute {@link #signature}.
     */
    public final void setSignature(byte[] signatureParam) {
	this.signature = signatureParam;
    }

    /**
     * Gets the value of the attribute {@link #signRepositoryObjectId}.
     * @return the value of the attribute {@link #signRepositoryObjectId}.
     */
    public final String getSignRepositoryObjectId() {
	return signRepositoryObjectId;
    }

    /**
     * Sets the value of the attribute {@link #signRepositoryObjectId}.
     * @param signRepositoryObjectIdParam The value for the attribute {@link #signRepositoryObjectId}.
     */
    public final void setSignRepositoryObjectId(String signRepositoryObjectIdParam) {
	this.signRepositoryObjectId = signRepositoryObjectIdParam;
    }

    /**
     * Gets the value of the attribute {@link #signRepositoryRepositoryId}.
     * @return the value of the attribute {@link #signRepositoryRepositoryId}.
     */
    public final String getSignRepositoryRepositoryId() {
	return signRepositoryRepositoryId;
    }

    /**
     * Sets the value of the attribute {@link #signRepositoryRepositoryId}.
     * @param signRepositoryRepositoryIdParam The value for the attribute {@link #signRepositoryRepositoryId}.
     */
    public final void setSignRepositoryRepositoryId(String signRepositoryRepositoryIdParam) {
	this.signRepositoryRepositoryId = signRepositoryRepositoryIdParam;
    }

    /**
     * Gets the value of the attribute {@link #validationResponse}.
     * @return the value of the attribute {@link #validationResponse}.
     */
    public final byte[] getValidationResponse() {
	return validationResponse;
    }

    /**
     * Sets the value of the attribute {@link #validationResponse}.
     * @param validationResponseParam The value for the attribute {@link #validationResponse}.
     */
    public final void setValidationResponse(byte[] validationResponseParam) {
	this.validationResponse = validationResponseParam;
    }

    /**
     * Gets the value of the attribute {@link #document}.
     * @return the value of the attribute {@link #document}.
     */
    public final byte[] getDocument() {
	return document;
    }

    /**
     * Sets the value of the attribute {@link #document}.
     * @param documentParam The value for the attribute {@link #document}.
     */
    public final void setDocument(byte[] documentParam) {
	this.document = documentParam;
    }

    /**
     * Gets the value of the attribute {@link #docRepositoryLocationRepositoryId}.
     * @return the value of the attribute {@link #docRepositoryLocationRepositoryId}.
     */
    public final String getDocRepositoryLocationRepositoryId() {
	return docRepositoryLocationRepositoryId;
    }

    /**
     * Sets the value of the attribute {@link #docRepositoryLocationRepositoryId}.
     * @param docRepositoryLocationRepositoryIdParam The value for the attribute {@link #docRepositoryLocationRepositoryId}.
     */
    public final void setDocRepositoryLocationRepositoryId(String docRepositoryLocationRepositoryIdParam) {
	this.docRepositoryLocationRepositoryId = docRepositoryLocationRepositoryIdParam;
    }

    /**
     * Gets the value of the attribute {@link #docRepositoryLocationObjectId}.
     * @return the value of the attribute {@link #docRepositoryLocationObjectId}.
     */
    public final String getDocRepositoryLocationObjectId() {
	return docRepositoryLocationObjectId;
    }

    /**
     * Sets the value of the attribute {@link #docRepositoryLocationObjectId}.
     * @param docRepositoryLocationObjectIdParam The value for the attribute {@link #docRepositoryLocationObjectId}.
     */
    public final void setDocRepositoryLocationObjectId(String docRepositoryLocationObjectIdParam) {
	this.docRepositoryLocationObjectId = docRepositoryLocationObjectIdParam;
    }

    /**
     * Gets the value of the attribute {@link #includeSignature}.
     * @return the value of the attribute {@link #includeSignature}.
     */
    public final String getIncludeSignature() {
	return includeSignature;
    }

    /**
     * Sets the value of the attribute {@link #includeSignature}.
     * @param includeSignatureParam The value for the attribute {@link #includeSignature}.
     */
    public final void setIncludeSignature(String includeSignatureParam) {
	this.includeSignature = includeSignatureParam;
    }

    /**
     * Gets the value of the attribute {@link #barcodeList}.
     * @return the value of the attribute {@link #barcodeList}.
     */
    public final List<BarcodeEvisorRequest> getBarcodeList() {
	return barcodeList;
    }

    /**
     * Sets the value of the attribute {@link #barcodeList}.
     * @param barcodeListParam The value for the attribute {@link #barcodeList}.
     */
    public final void setBarcodeList(List<BarcodeEvisorRequest> barcodeListParam) {
	this.barcodeList = barcodeListParam;
    }

    /**
     * Gets the value of the attribute {@link #externalParameterList}.
     * @return the value of the attribute {@link #externalParameterList}.
     */
    public final List<ParameterEvisorRequest> getExternalParameterList() {
	return externalParameterList;
    }

    /**
     * Sets the value of the attribute {@link #externalParameterList}.
     * @param externalParameterListParam The value for the attribute {@link #externalParameterList}.
     */
    public final void setExternalParameterList(List<ParameterEvisorRequest> externalParameterListParam) {
	this.externalParameterList = externalParameterListParam;
    }

}
