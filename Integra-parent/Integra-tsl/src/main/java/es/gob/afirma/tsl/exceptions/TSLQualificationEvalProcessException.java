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
 * <b>File:</b><p>es.gob.afirma.tsl.exceptions.TSLQualificationEvalProcessException.java.</p>
 * <b>Description:</b><p>Class that represents an exception in the qualification extension evaluation process.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.exceptions;


/** 
 * <p>Class that represents an exception in the qualification extension evaluation process.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public class TSLQualificationEvalProcessException extends Exception {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 6160560778622141821L;

    /**
     * Constructor method for the class TSLQualificationEvalProcessException.java. 
     */
    public TSLQualificationEvalProcessException() {
    }

    /**
     * Constructor method for the class TSLQualificationEvalProcessException.java.
     * @param message Description.
     */
    public TSLQualificationEvalProcessException(String message) {
	super(message);
    }

    /**
     * Constructor method for the class TSLQualificationEvalProcessException.java.
     * @param cause Cause.
     */
    public TSLQualificationEvalProcessException(Throwable cause) {
	super(cause);
    }

    /**
     * Constructor method for the class TSLQualificationEvalProcessException.java.
     * @param message Description.
     * @param cause Cause.
     */
    public TSLQualificationEvalProcessException(String message, Throwable cause) {
	super(message, cause);
    }

    /**
     * Constructor method for the class TSLQualificationEvalProcessException.java.
     * @param message Description.
     * @param cause Cause.
     * @param enableSuppression Suppression.
     * @param writableStackTrace  Write stacktrace.
     */
    public TSLQualificationEvalProcessException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
	super(message, cause, enableSuppression, writableStackTrace);
    }

}
