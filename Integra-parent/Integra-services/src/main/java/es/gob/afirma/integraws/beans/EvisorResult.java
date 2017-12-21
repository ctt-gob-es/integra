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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.EvisorResult.java.</p>
 * <b>Description:</b><p> Class that represents the result of evisor validate report needed in request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

/** 
 * <p>Class that represents the result of evisor validate report needed in request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class EvisorResult {

    /**
     * Attribute that represents the result code of the service. 
     */
    private String codeResult;

    /**
     * Attribute that represents any message from service. 
     */
    private String message;

    /**
     * Attribute that represents error cause informed from evisor service if validation fail. 
     */
    private String cause;

    /**
     * Constructor method for the class EvisorResult.java. 
     */
    public EvisorResult() {
	super();
    }

    /**
     * Constructor method for the class EvisorResult.java.
     * @param codeResultParam result code.
     * @param messageParam message from evisor service.
     * @param causeParam Cause of error if evisor service validation fails.
     */
    public EvisorResult(String codeResultParam, String messageParam, String causeParam) {
	super();
	this.codeResult = codeResultParam;
	this.message = messageParam;
	this.cause = causeParam;
    }

    /**
     * Gets the value of the attribute {@link #codeResult}.
     * @return the value of the attribute {@link #codeResult}.
     */
    public final String getCodeResult() {
	return codeResult;
    }

    /**
     * Sets the value of the attribute {@link #codeResult}.
     * @param codeResultParam The value for the attribute {@link #codeResult}.
     */
    public final void setCodeResult(String codeResultParam) {
	this.codeResult = codeResultParam;
    }

    /**
     * Gets the value of the attribute {@link #message}.
     * @return the value of the attribute {@link #message}.
     */
    public final String getMessage() {
	return message;
    }

    /**
     * Sets the value of the attribute {@link #message}.
     * @param messageParam The value for the attribute {@link #message}.
     */
    public final void setMessage(String messageParam) {
	this.message = messageParam;
    }

    /**
     * Gets the value of the attribute {@link #cause}.
     * @return the value of the attribute {@link #cause}.
     */
    public final String getCause() {
	return cause;
    }

    /**
     * Sets the value of the attribute {@link #cause}.
     * @param causeParam The value for the attribute {@link #cause}.
     */
    public final void setCause(String causeParam) {
	this.cause = causeParam;
    }

}
