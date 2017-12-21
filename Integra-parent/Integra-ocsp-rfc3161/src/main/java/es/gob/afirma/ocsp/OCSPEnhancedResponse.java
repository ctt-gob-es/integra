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
 * <b>File:</b><p>es.gob.afirma.ocsp.OCSPEnhancedResponse.java.</p>
 * <b>Description:</b><p>Class that represents an OCSP response with the date when the cached OCSP response expires, as defined on the lightweight profile
 * recommendations defined in the RFC 5019.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>20/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 20/11/2014.
 */
package es.gob.afirma.ocsp;

import java.io.Serializable;
import java.util.Date;

/**
 * <p>Class that represents an OCSP response with the date when the cached OCSP response expires, as defined on the lightweight profile
 * recommendations defined in the RFC 5019.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 20/11/2014.
 */
public class OCSPEnhancedResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = -2181848083482498676L;

    /**
     * Constant attribute that identifies the OCSP response status: <code>Response has valid confirmations</code>.
     */
    public static final int STATUS_SUCCESSFUL = 0;

    /**
     * Constant attribute that identifies the OCSP response status: <code>Illegal confirmation request</code>.
     */
    public static final int STATUS_MALFORMED_REQUEST = 1;

    /**
     * Constant attribute that identifies the OCSP response status: <code>Internal error in issuer</code>.
     */
    public static final int STATUS_INTERNAL_ERROR = 2;

    /**
     * Constant attribute that identifies the OCSP response status: <code>Try again later</code>.
     */
    public static final int STATUS_TRY_LATER = 3;

    /**
     * Constant attribute that identifies the OCSP response status: <code>Must sign the request</code>.
     */
    public static final int STATUS_SIGREQUIRED = 5;

    /**
     * Constant attribute that identifies the OCSP response status: <code>Request unauthorized</code>.
     */
    public static final int STATUS_UNAUTHORIZED = 6;

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
    private int status;

    /**
     * Attribute that represents the revocation date.
     */
    private Date revocationDate;

    /**
     * Attribute that represents the error message when the status is not correct.
     */
    private String errorMsg;

    /**
     * Attribute that represents the date when the cached response expires.
     */
    private Date maxAge;

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

}
