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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.integraws.beans.ResponseServerBatchVerifySignature.java.</p>
 * <b>Description:</b><p> Class that represents the response object for server batch verify signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import java.util.List;

import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureResponse;
import es.gob.afirma.integraFacade.pojo.Result;
import es.gob.afirma.integraFacade.pojo.VerifySignatureResponse;

/** 
 * <p>Class that represents the response object for server batch verify signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class ResponseServerBatchVerifySignature extends BatchVerifySignatureResponse{
    
    /**
     * Attribute that represents serialVersionUID. 
     */
    private static final long serialVersionUID = -5837424463195080360L;

    /**
     * Attribute that indicates if integra request fails. 
     */
    private boolean integraSuccess;
    
    /**
     * Attribute that represents integra request error message. 
     */
    private String integraErrorMsg;

    /**
     * Constructor method for the class ResponseServerBatchVerifySignature.java. 
     */
    public ResponseServerBatchVerifySignature() {
	super();
    }
    
    /**
     * Constructor method for the class ResponseServerBatchVerifySignature.java.
     * @param asyncResponseParam asyncResponseParam value.
     * @param listVerifyResponseParam listVerifyResponseParam value. 
     * @param resultParam resultParam value.
     * @param integraSuccessParam The value for the attribute {@link #integraSuccess}
     */
    public ResponseServerBatchVerifySignature(String asyncResponseParam, List<VerifySignatureResponse> listVerifyResponseParam, Result resultParam, boolean integraSuccessParam) {
	super();
	this.setAsyncResponse(asyncResponseParam);
	this.setListVerifyResponse(listVerifyResponseParam);
	this.setResult(resultParam);
	this.integraSuccess = integraSuccessParam;
	
    }


    /**
     * Constructor method for the class ResponseServerBatchVerifySignature.java.
     * @param integraSuccessParam The value for the attribute {@link #integraSuccess}.
     * @param integraErrorMsg The value for the attribute {@link #integraErrorMsg}. 
     */
    public ResponseServerBatchVerifySignature(boolean integraSuccessParam, String integraErrorMsg) {
	super();
	this.integraSuccess = integraSuccessParam;
	this.integraErrorMsg = integraErrorMsg;
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
