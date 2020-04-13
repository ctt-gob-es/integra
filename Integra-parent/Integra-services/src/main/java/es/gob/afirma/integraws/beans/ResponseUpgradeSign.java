// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.ResponseUpgradeSign.java.</p>
 * <b>Description:</b><p> Class that represents the response object for upgrade service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/04/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/04/2020.
 */
package es.gob.afirma.integraws.beans;

import java.util.Date;

/** 
 * <p>Class that represents the response object for upgrade service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/04/2020.
 */
public class ResponseUpgradeSign {

    /**
     * Attribute that represents sign returned. 
     */
    private byte[] sign;
    
    /**
     * Attribute that indicates if integra request fails. 
     */
    private boolean integraSuccess;
    
    /**
     * Attribute that represents integra request error message. 
     */
    private String integraErrorMsg;
    
    /**
     * Attribute that represents the expiration date of the signature.
     */
    private Date expirationDate;
    
    /**
     * Constructor method for the class ResponseUpgradeSign.java. 
     */
    public ResponseUpgradeSign() {
	super();
    }

    /**
     * Constructor method for the class ResponseUpgradeSign.java.
     * @param signParam 
     * @param integraSuccessParam 
     * @param expirationDateParam 
     */
    public ResponseUpgradeSign(byte[ ] signParam, boolean integraSuccessParam, Date expirationDateParam) {
	super();
	this.sign = signParam;
	this.integraSuccess = integraSuccessParam;
	this.expirationDate = expirationDateParam;
    }

    /**
     * Constructor method for the class ResponseUpgradeSign.java.
     * @param integraSuccessParam 
     * @param integraErrorMsgParam 
     */
    public ResponseUpgradeSign(boolean integraSuccessParam, String integraErrorMsgParam) {
	super();
	this.integraSuccess = integraSuccessParam;
	this.integraErrorMsg = integraErrorMsgParam;
    }

    /**
     * Gets the value of the attribute {@link #sign}.
     * @return the value of the attribute {@link #sign}.
     */
    public final byte[ ] getSign() {
        return sign;
    }

    /**
     * Sets the value of the attribute {@link #sign}.
     * @param signParam The value for the attribute {@link #sign}.
     */
    public final void setSign(byte[ ] signParam) {
        this.sign = signParam;
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

    /**
     * Gets the value of the attribute {@link #expirationDate}.
     * @return the value of the attribute {@link #expirationDate}.
     */
    public Date getExpirationDate() {
        return expirationDate;
    }

    /**
     * Sets the value of the attribute {@link #expirationDate}.
     * @param expirationDateParam The value for the attribute {@link #expirationDate}.
     */
    public void setExpirationDate(Date expirationDateParam) {
        this.expirationDate = expirationDateParam;
    }
 
}
