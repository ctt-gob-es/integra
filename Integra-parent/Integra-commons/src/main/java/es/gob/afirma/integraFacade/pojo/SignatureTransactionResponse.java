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
 * <b>File:</b><p>es.gob.afirma.integraWSFacade.SignatureTransactionResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the service to get a signature transaction.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the response from the service to get a signature transaction.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/11/2014.
 */
public class SignatureTransactionResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -11567065474966077L;

    /**
     * Attribute that indicates whether the operation has been satisfied.
     */
    private boolean state;

    /**
     * Attribute that represents description of error or exception happened.
     */
    private String description;

    /**
     * Attribute that represents the content of signature associated with the requested transaction identifier.
     */
    private byte[ ] signature;

    /**
     * Attribute that represents signature format associated with the transactional identifier.
     */
    private String signatureFormat;

    /**
     * Attribute that represents the information about the error response returned.
     */
    private ErrorResponse error;

    /**
     * Constructor method for the class SignatureTransactionResponse.java.
     */
    public SignatureTransactionResponse() {
    }

    /**
     * Gets the value of the attribute {@link #state}.
     * @return the value of the attribute {@link #state}.
     */
    public final boolean isState() {
	return state;
    }

    /**
     * Sets the value of the attribute {@link #state}.
     * @param stateParam The value for the attribute {@link #state}.
     */
    public final void setState(boolean stateParam) {
	this.state = stateParam;
    }

    /**
     * Gets the value of the attribute {@link #description}.
     * @return the value of the attribute {@link #description}.
     */
    public final String getDescription() {
	return description;
    }

    /**
     * Sets the value of the attribute {@link #description}.
     * @param descriptionParam The value for the attribute {@link #description}.
     */
    public final void setDescription(String descriptionParam) {
	this.description = descriptionParam;
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
     * Gets the value of the attribute {@link #signatureFormat}.
     * @return the value of the attribute {@link #signatureFormat}.
     */
    public final String getSignatureFormat() {
	return signatureFormat;
    }

    /**
     * Sets the value of the attribute {@link #signatureFormat}.
     * @param signatureFormatParam The value for the attribute {@link #signatureFormat}.
     */
    public final void setSignatureFormat(String signatureFormatParam) {
	this.signatureFormat = signatureFormatParam;
    }

    /**
     * Gets the value of the attribute {@link #error}.
     * @return the value of the attribute {@link #error}.
     */
    public final ErrorResponse getError() {
	return error;
    }

    /**
     * Sets the value of the attribute {@link #error}.
     * @param errorParam The value for the attribute {@link #error}.
     */
    public final void setError(ErrorResponse errorParam) {
	this.error = errorParam;
    }

}
