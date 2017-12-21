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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.ResponseServerAsynchronous.java.</p>
 * <b>Description:</b><p> Class that represents the response object for server asynchronous service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import es.gob.afirma.integraFacade.pojo.AsynchronousResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureResponse;
import es.gob.afirma.integraFacade.pojo.InvalidAsyncResponse;
import es.gob.afirma.integraFacade.pojo.ServerSignerResponse;

/** 
 * <p>Class that represents the response object for server asynchronous service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class ResponseServerAsynchronous extends AsynchronousResponse{
    
    /**
     * Attribute that represents serialVersionUID. 
     */
    private static final long serialVersionUID = 6663597557841644347L;

    /**
     * Attribute that indicates if integra request fails. 
     */
    private boolean integraSuccess;
    
    /**
     * Attribute that represents integra request error message. 
     */
    private String integraErrorMsg;

    /**
     * Constructor method for the class ResponseServerAsynchronous.java. 
     */
    public ResponseServerAsynchronous() {
	super();
	
    }
    
    /**
     * Constructor method for the class ResponseServerAsynchronous.java.
     * @param batVerCerResParam 
     * @param batVerSigResParam 
     * @param invAsyResParam 
     * @param serSigResParam 
     * @param integraSuccessParam  
     */
    public ResponseServerAsynchronous(BatchVerifyCertificateResponse batVerCerResParam, BatchVerifySignatureResponse batVerSigResParam, InvalidAsyncResponse invAsyResParam, ServerSignerResponse serSigResParam, boolean integraSuccessParam) {
	super();
	this.setBatVerCerRes(batVerCerResParam);
	this.setBatVerSigRes(batVerSigResParam);
	this.setInvAsyRes(invAsyResParam);
	this.setSerSigRes(serSigResParam);
	this.integraSuccess = integraSuccessParam;
	
    }


    /**
     * Constructor method for the class ResponseServerAsynchronous.java.
     * @param integraSuccessParam 
     * @param message  
     */
    public ResponseServerAsynchronous(boolean integraSuccessParam, String message) {
	super();
	this.integraSuccess = integraSuccessParam;
	this.integraErrorMsg = message;
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
