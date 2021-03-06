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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.ResponseGetSignedData.java.</p>
 * <b>Description:</b><p> Class that represents the response object for get signed data service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

/** 
 * <p>Class that represents the response object for get signed data service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
import es.gob.afirma.signature.OriginalSignedData;


/** 
 * <p>Class that represents the response object for get signed data service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 17/5/2016.
 */
public class ResponseGetSignedData {

    /**
     * Attribute that represents original signed data. 
     */
    private OriginalSignedData originalSignedData;
    
    /**
     * Attribute that indicates if integra request fails. 
     */
    private boolean integraSuccess;
    
    /**
     * Attribute that represents integra request error message. 
     */
    private String integraErrorMsg;

    /**
     * Constructor method for the class ResponseGetSignedData.java. 
     */
    public ResponseGetSignedData() {
	super();
    }
    
    /**
     * Constructor method for the class ResponseGetSignedData.java.
     * @param originalSignedDataParam 
     * @param integraSuccessParam 
     */
    public ResponseGetSignedData(OriginalSignedData originalSignedDataParam, boolean integraSuccessParam) {
	super();
	this.originalSignedData = originalSignedDataParam;
	this.integraSuccess = integraSuccessParam;
    }

    /**
     * Constructor method for the class ResponseGetSignedData.java.
     * @param integraSuccessParam 
     * @param integraErrorMsgParam  
     */
    public ResponseGetSignedData(boolean integraSuccessParam, String integraErrorMsgParam) {
	super();
	this.integraSuccess = integraSuccessParam;
	this.integraErrorMsg = integraErrorMsgParam;
    }

    /**
     * Gets the value of the attribute {@link #originalSignedData}.
     * @return the value of the attribute {@link #originalSignedData}.
     */
    public final OriginalSignedData getOriginalSignedData() {
        return originalSignedData;
    }

    /**
     * Sets the value of the attribute {@link #originalSignedData}.
     * @param originalSignedDataParam The value for the attribute {@link #originalSignedData}.
     */
    public final void setOriginalSignedData(OriginalSignedData originalSignedDataParam) {
        this.originalSignedData = originalSignedDataParam;
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
