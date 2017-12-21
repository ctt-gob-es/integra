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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.ResponseValidateOCSP.java.</p>
 * <b>Description:</b><p> Class that represents the response object for validate ocsp service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import java.util.Date;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/** 
 * <p>Class that represents the response object for validate ocsp service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ResponseValidateOCSP{

//    /**
//     * Constant attribute that identifies the OCSP response status: <code>Response has valid confirmations</code>.
//     */
//    public static final int STATUS_SUCCESSFUL = 0;
//
//    /**
//     * Constant attribute that identifies the OCSP response status: <code>Illegal confirmation request</code>.
//     */
//    public static final int STATUS_MALFORMED_REQUEST = 1;
//
//    /**
//     * Constant attribute that identifies the OCSP response status: <code>Internal error in issuer</code>.
//     */
//    public static final int STATUS_INTERNAL_ERROR = 2;
//
//    /**
//     * Constant attribute that identifies the OCSP response status: <code>Try again later</code>.
//     */
//    public static final int STATUS_TRY_LATER = 3;
//
//    /**
//     * Constant attribute that identifies the OCSP response status: <code>Must sign the request</code>.
//     */
//    public static final int STATUS_SIGREQUIRED = 5;
//
//    /**
//     * Constant attribute that identifies the OCSP response status: <code>Request unauthorized</code>.
//     */
//    public static final int STATUS_UNAUTHORIZED = 6;

    /**
     * Attribute that represents the OCSP response status. The possible values are:
     * <ul>
     * <li>{@link #STATUS_SUCCESSFUL}</li>
     * <li>{@link #STATUS_MALFORMED_REQUEST}</li>
     * <li>{@link #STATUS_INTERNAL_ERROR}</li>
     * <li>{@link #STATUS_TRY_LATER}</li>
     * <li>{@link #STATUS_SIGREQUIRED}</li>
     * <li>{@link #STATUS_UNAUTHORIZED}</li>
     * </ul>
     */
    @XmlElement
    private int status = -1;

    /**
     * Attribute that represents the revocation date.
     */
    @XmlElement
    private Date revocationDate;

    /**
     * Attribute that represents the error message when the status is not correct.
     */
    @XmlElement
    private String errorMsg;

    /**
     * Attribute that represents the date when the cached response expires.
     */
    @XmlElement
    private Date maxAge;
    
    /**
     * Attribute that indicates if integra request fails. 
     */
    @XmlElement
    private boolean integraSuccess;
    
    /**
     * Attribute that represents integra request error message. 
     */
    @XmlElement
    private String integraErrorMsg;
    
    /**
     * Constructor method for the class ResponseValidateOCSP.java. 
     */
    public ResponseValidateOCSP(){
	super();
    }

    /**
     * Constructor method for the class ResponseValidateOCSP.java.
     * @param statusParam 
     * @param errorMsgParam 
     * @param revocationDateParam 
     * @param maxAgeParam 
     * @param result 
     */
    public ResponseValidateOCSP(int statusParam, String errorMsgParam, Date revocationDateParam, Date maxAgeParam, boolean result) {
	super();
	this.status = statusParam;
	this.errorMsg = errorMsgParam;
	this.revocationDate = revocationDateParam;
	this.maxAge = maxAgeParam;
	this.integraSuccess = result;
    }

    /**
     * Constructor method for the class ResponseValidateOCSP.java.
     * @param result 
     * @param message 
     */
    public ResponseValidateOCSP(boolean result, String message) {
	super();
	this.status = -1;
	this.errorMsg = null;
	this.revocationDate = null;
	this.maxAge = null;
	this.integraSuccess = result;
	this.integraErrorMsg = message;
    }

    /**
     * Gets the value of the attribute {@link #maxAge}.
     * @return the value of the attribute {@link #maxAge}.
     */
    public final Date getMaxAge() {
	return maxAge;
    }

    /**
     * Sets the value of the attribute {@link #maxAge}.
     * @param maxAgeParam The value for the attribute {@link #maxAge}.
     */
    public final void setMaxAge(Date maxAgeParam) {
	this.maxAge = maxAgeParam;
    }

    /**
     * Gets the value of the attribute {@link #status}.
     * @return the value of the attribute {@link #status}.
     */
    public final int getStatus() {
	return status;
    }

    /**
     * Sets the value of the attribute {@link #status}.
     * @param statusParam The value for the attribute {@link #status}.
     */
    public final void setStatus(int statusParam) {
	this.status = statusParam;
    }

    /**
     * Gets the value of the attribute {@link #revocationDate}.
     * @return the value of the attribute {@link #revocationDate}.
     */
    public final Date getRevocationDate() {
	return revocationDate;
    }

    /**
     * Sets the value of the attribute {@link #revocationDate}.
     * @param revocationDateParam The value for the attribute {@link #revocationDate}.
     */
    public final void setRevocationDate(Date revocationDateParam) {
	this.revocationDate = revocationDateParam;
    }

    /**
     * Gets the value of the attribute {@link #errorMsg}.
     * @return the value of the attribute {@link #errorMsg}.
     */
    public final String getErrorMsg() {
	return errorMsg;
    }

    /**
     * Sets the value of the attribute {@link #errorMsg}.
     * @param errorMsgParam The value for the attribute {@link #errorMsg}.
     */
    public final void setErrorMsg(String errorMsgParam) {
	this.errorMsg = errorMsgParam;
    }
    
    /**
     * Gets the value of the attribute {@link #integraSuccess}.
     * @return the value of the attribute {@link #integraSuccess}.
     */
    public final boolean isIntegraSuccess() {
        return integraSuccess;
    }

    /**
     * Sets the value of the attribute {@link #integraSuccess}.
     * @param integraSuccessParam The value for the attribute {@link #integraSuccess}.
     */
    public final void setIntegraSuccess(boolean integraSuccessParam) {
        this.integraSuccess = integraSuccessParam;
    }

    /**
     * Gets the value of the attribute {@link #integraErrorMsg}.
     * @return the value of the attribute {@link #integraErrorMsg}.
     */
    public final String getIntegraErrorMsg() {
        return integraErrorMsg;
    }

    /**
     * Sets the value of the attribute {@link #integraErrorMsg}.
     * @param integraErrorMsgParam The value for the attribute {@link #integraErrorMsg}.
     */
    public final void setIntegraErrorMsg(String integraErrorMsgParam) {
        this.integraErrorMsg = integraErrorMsgParam;
    }
}
