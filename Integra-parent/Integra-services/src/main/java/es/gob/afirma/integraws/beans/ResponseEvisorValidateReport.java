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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.ResponseEvisorValidateReport.java.</p>
 * <b>Description:</b><p> Class that represents the response object for validate report service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

/** 
 * <p>Class that represents the response object for validate report service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class ResponseEvisorValidateReport {

    /**
     * Attribute that indicates if integra request fails. 
     */
    private boolean integraSuccess;

    /**
     * Attribute that represents integra request error message. 
     */
    private String integraErrorMsg;

    /**
     * Attribute that represents result of validation. 
     */
    private EvisorResult result;
    
    /**
     * Constructor method for the class ResponseEvisorValidateReport.java. 
     */
    public ResponseEvisorValidateReport() {
	super();
    }

    /**
     * Constructor method for the class ResponseEvisorValidateReport.java.
     * @param integraSuccessParam The value for the attribute {@link #integraSuccess} 
     * @param integraErrorMsgParam The value for the attribute {@link #integraErrorMsg}
     */
    public ResponseEvisorValidateReport(boolean integraSuccessParam, String integraErrorMsgParam) {
	super();
	this.integraSuccess = integraSuccessParam;
	this.integraErrorMsg = integraErrorMsgParam;
    }

    /**
     * Constructor method for the class ResponseEvisorValidateReport.java.
     * @param resultParam  The value for the attribute {@link #result}
     * @param integraSuccessParam The value for the attribute {@link #integraSuccess} 
     */
    public ResponseEvisorValidateReport(EvisorResult resultParam, boolean integraSuccessParam) {
	super();
	this.integraSuccess = integraSuccessParam;
	this.result = resultParam;
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
     * Gets the value of the attribute {@link #result}.
     * @return the value of the attribute {@link #result}.
     */
    public final EvisorResult getResult() {
	return result;
    }

    /**
     * Sets the value of the attribute {@link #result}.
     * @param resultParam The value for the attribute {@link #result}.
     */
    public final void setResult(EvisorResult resultParam) {
	this.result = resultParam;
    }

}
