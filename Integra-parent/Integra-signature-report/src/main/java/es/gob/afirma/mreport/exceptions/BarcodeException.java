// Copyright (C) 2018, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.mreport.exceptions.BarcodeException.java.</p>
 * <b>Description:</b><p>Class that provides information about an error that occurred during the processing of bar codes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 28/08/2020.
 */
package es.gob.afirma.mreport.exceptions;


/** 
 * <p>Class that provides information about an error that occurred during the processing of bar codes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/08/2020.
 */
public class BarcodeException extends Exception {

    /**
     * Attribute that represents the version of class. 
     */
    private static final long serialVersionUID = -7889228288801116079L;
    
    /**
     * Attribute that represents the code associated to unknown error. 
     */
    public static final int UNKNOWN_ERROR = -1;
    
    /**
     * Attribute that represents the code that indicates that input parameters are invalid. 
     */
    public static final int INVALID_INPUT_PARAMETERS = 1;
    
    
    /**
     * Attribute that identifies the error type occurred. 
     */
    private int code = UNKNOWN_ERROR;
    
    /**
     * Attribute that represents a error description. 
     */
    private String description = null;

    /**
     * Constructor method for the class ReportException.java.
     * @param codeId	Identifier of error.
     * @param message 	Error description.
     */
    public BarcodeException(int codeId, String message) {
	super(message);
	this.code = codeId;
	this.description = message;
    }

    /**
     * Constructor method for the class ReportException.java.
     * @param codeId	Identifier of error.
     * @param message 	Error description.
     * @param cause		Error cause.
     */
    public BarcodeException(int codeId, String message,Throwable cause) {
	super(message,cause);
	this.code = codeId;
	this.description = message;
    }
    
    /**
     * Gets the value of the attribute that identifies the error type occurred.
     * @return the value of the attribute that identifies the error type occurred.
     */
    public int getCode() {
        return code;
    }

    
    /**
     * Sets the value of the attribute that identifies the error type occurred.
     * @param codeId The value for the attribute that identifies the error type occurred.
     */
    public void setCode(int codeId) {
        this.code = codeId;
    }

    
    /**
     * Gets the value of the error description.
     * @return the value of the error description.
     */
    public String getDescription() {
        return description;
    }

    
    /**
     * Sets the value of the error description.
     * @param message The value for the error description.
     */
    public void setDescription(String message) {
        this.description = message;
    }

}
