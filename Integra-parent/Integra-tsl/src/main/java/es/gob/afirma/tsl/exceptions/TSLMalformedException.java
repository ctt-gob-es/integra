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
 * <b>File:</b><p>es.gob.afirma.tsl.exceptions.TSLMalformedException.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.exceptions;

/** 
 * <p>Class that manages the malformed exceptions of the TSL module. .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class TSLMalformedException extends Exception {

    /**
     *  Constant attribute that represents the serial version OID.
     */
    private static final long serialVersionUID = -220613613088790844L;

    /**
     * Attribute that represents a description associated to the error.
     */
    private String errorDesc;

    /**
     * Constructor method for the class TSLMalformedException.java. 
     */
    public TSLMalformedException() {
    }

    /**
     * Constructor method for the class TSLMalformedException.java.
     * @param message 
     */
    public TSLMalformedException(String message) {
	super(message);
	errorDesc = message;
    }

    /**
     * Constructor method for the class TSLMalformedException.java.
     * @param cause 
     */
    public TSLMalformedException(Throwable cause) {
	super(cause);
    }

    /**
     * Constructor method for the class TSLMalformedException.java.
     * @param message
     * @param cause 
     */
    public TSLMalformedException(String message, Throwable cause) {
	super(message, cause);
    }

    /**
     * Constructor method for the class TSLMalformedException.java.
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace 
     */
    public TSLMalformedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
	super(message, cause, enableSuppression, writableStackTrace);
    }

    /**
     * Gets the value of the attribute {@link #errorDesc}.
     * @return the value of the attribute {@link #errorDesc}.
     */
    public String getErrorDesc() {
	return errorDesc;
    }

    /**
     * Sets the value of the attribute {@link #errorDesc}.
     * @param errorDesc The value for the attribute {@link #errorDesc}.
     */
    public void setErrorDesc(String errorDesc) {
	this.errorDesc = errorDesc;
    }

}
