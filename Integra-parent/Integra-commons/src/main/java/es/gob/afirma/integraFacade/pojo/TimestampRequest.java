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
 * <b>File:</b><p>es.gob.afirma.integraWSFacade.ServerSignerRequest.java.</p>
 * <b>Description:</b><p>Class that represents the request for the server signature service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the request for the server signature service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/03/2016.
 */
public class TimestampRequest implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 2317924093068390460L;

    /**
     * Attribute that represents the type of the timestamp.
     */
    private TimestampTypeEnum timestampType;

    /**
     * Attribute that represents document to be signed.
     */
    private byte[ ] dataToStamp;

    /**
     * Attribute that represents application identifier.
     */
    private String applicationId;

    /**
     * Attribute that contains the hash of the original data for verification with respect to the data included in the timestamp.
     */
    private DocumentHash documentHash;

    /**
     * Attribute that contains the information of the canonicalization.
     */
    private TransformData transformData;

    /**
     * Attribute that represents the type of the document. InlineXML, Base64XML, EscapedXML, Base64Data, TransformedData, DocumentHash
     */
    private DocumentTypeEnum documentType;

    /**
     * Attribute that represents the timestamp for the timestamp verify service.
     */
    private byte[ ] timestampTimestampToken;

    /**
     * Attribute that represents the timestamp for the timestamp renew service.
     */
    private byte[ ] timestampPreviousTimestampToken;

    /**
     * Constructor method for the class TimestampRequest.java.
     */
    public TimestampRequest() {
    }

    /**
     * Gets the value of the attribute {@link #timestampType}.
     * @return the value of the attribute {@link #timestampType}.
     */
    public final TimestampTypeEnum getTimestampType() {
	return timestampType;
    }

    /**
     * Sets the value of the attribute {@link #timestampType}.
     * @param timestampTypeParam The value for the attribute {@link #timestampType}.
     */
    public final void setTimestampType(TimestampTypeEnum timestampTypeParam) {
	this.timestampType = timestampTypeParam;
    }

    /**
     * Gets the value of the attribute {@link #dataToStamp}.
     * @return the value of the attribute {@link #dataToStamp}.
     */
    public final byte[ ] getDataToStamp() {
	return dataToStamp;
    }

    /**
     * Sets the value of the attribute {@link #dataToStamp}.
     * @param dataToStampParam The value for the attribute {@link #dataToStamp}.
     */
    public final void setDataToStamp(byte[ ] dataToStampParam) {
	if (dataToStampParam != null) {
	    this.dataToStamp = dataToStampParam.clone();
	}
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
     * Gets the value of the attribute {@link #documentType}.
     * @return the value of the attribute {@link #documentType}.
     */
    public final DocumentTypeEnum getDocumentType() {
	return documentType;
    }

    /**
     * Sets the value of the attribute {@link #documentType}.
     * @param documentTypeParam The value for the attribute {@link #documentType}.
     */
    public final void setDocumentType(DocumentTypeEnum documentTypeParam) {
	this.documentType = documentTypeParam;
    }

    /**
     * Gets the value of the attribute {@link #transformData}.
     * @return the value of the attribute {@link #transformData}.
     */
    public final TransformData getTransformData() {
	return transformData;
    }

    /**
     * Sets the value of the attribute {@link #transformData}.
     * @param transformDataParam The value for the attribute {@link #transformData}.
     */
    public final void setTransformData(TransformData transformDataParam) {
	this.transformData = transformDataParam;
    }

    /**
     * Gets the value of the attribute {@link #timestampTimestampToken}.
     * @return the value of the attribute {@link #timestampTimestampToken}.
     */
    public final byte[ ] getTimestampTimestampToken() {
	return timestampTimestampToken;
    }

    /**
     * Sets the value of the attribute {@link #timestampTimestampToken}.
     * @param timestampTimestampTokenParam The value for the attribute {@link #timestampTimestampToken}.
     */
    public final void setTimestampTimestampToken(byte[ ] timestampTimestampTokenParam) {
	if (timestampTimestampTokenParam != null) {
	    this.timestampTimestampToken = timestampTimestampTokenParam.clone();
	}
    }

    /**
     * Gets the value of the attribute {@link #timestampPreviousTimestampToken}.
     * @return the value of the attribute {@link #timestampPreviousTimestampToken}.
     */
    public final byte[ ] getTimestampPreviousTimestampToken() {
	return timestampPreviousTimestampToken;
    }

    /**
     * Sets the value of the attribute {@link #timestampPreviousTimestampToken}.
     * @param timestampPreviousTimestampTokenParam The value for the attribute {@link #timestampPreviousTimestampToken}.
     */
    public final void setTimestampPreviousTimestampToken(byte[ ] timestampPreviousTimestampTokenParam) {
	if (timestampPreviousTimestampTokenParam != null) {
	    this.timestampPreviousTimestampToken = timestampPreviousTimestampTokenParam.clone();
	}
    }
}
