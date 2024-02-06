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
 * <b>File:</b><p>es.gob.signaturereport.mfirma.exception.SignatureManagerException.java.</p>
 * <b>Description:</b><p> Class that contains information about an error occurred while validating or generating a signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 19/08/2020.
 */
package es.gob.afirma.mreport.exceptions;


/** 
 * <p>Class that contains information about an error occurred while generating a signature report.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/08/2020.
 */
public class SignatureReportException extends Exception{

    /**
     * Class serial version.. 
     */
    private static final long serialVersionUID = -4698462229986273569L;
    
    /**
     * Attribute that represents that a unknown error has occurred.
     */
    public static final int UNKNOWN_ERROR = 0;

    /**
     * Attribute that represents that not found platform with identifier supplied. 
     */
    public static final int INVALID_PLATFORM_ID = 1;

    /**
     * Attribute that represents the operation is not supported. 
     */
    public static final int NOT_SUPPORTED = 2;

    /**
     * Attribute that represents an error while processing signature. 
     */
    public static final int SIGNATURE_PROCESS_ERROR = 3;

    /**
     * Attribute that represents that the input parameters supplied to manager are invalid. 
     */
    public static final int INVALID_INPUT_PARAMETERS = 4;
   
    /**
     * Attribute that represents an error while processing signed data. 
     */
    public static final int DOCUMENT_PROCESS_ERROR = 5;

    /**
     * Attribute that represents an error while creating XML request. 
     */
    public static final int XML_REQUEST_ERROR = 6;

    /**
     * Attribute that represents an error while invoking to '@firma'. 
     */
    public static final int AFIRMA_INVOKER_ERROR = 7;

    /**
     * Attribute that represents an error while reading XML response. 
     */
    public static final int XML_RESPONSE_ERROR = 8;
    
    /**
     * Attribute that indicates the SOAP signature is not valid. 
     */
    public static final int INVALID_SOAP_SIGNATURE = 9;
    
    /**
     * Attribute that represents the template is not valid. 
     */
    public static final int INVALID_TEMPLATE = 10;
    
    /**
     * Attribute that identifies the type of error occurred. 
     */
    private int code = UNKNOWN_ERROR;

    /**
     * Attribute that represents the description of error. 
     */
    private String description = null;
    
    /**
     * Constructor method for the class SignatureManagerException.java.
     * @param cause	Error cause.
     */
    public SignatureReportException(Throwable cause) {
    	super(cause);
    }


    /**
     * Constructor method for the class SignatureManagerException.java.
     * @param errorCode		  Error code.
     * @param message Parameter that represents a description of error. 
     */
    public SignatureReportException(int errorCode,String message) {
    	super(message);
    	this.code = errorCode;
    	this.description = message;
    }
    
    /**
     * Constructor method for the class SignatureManagerException.java.
     * @param message Error message.
     * @param cause Error cause.
     */
    public SignatureReportException(String message, Throwable cause) {
	super(message, cause);
    }

    /**
     * Constructor method for the class SignatureManagerException.java.
     * @param errorCode		  Error code.
     * @param message Parameter that represents a description of error.
     * @param errorCause		  Error cause. 
     */
    public SignatureReportException(int errorCode,String message,Throwable errorCause) {
    	super(message,errorCause);
    	this.code = errorCode;
    	this.description = message;
    }
    
    /**
     * Gets the value of the attribute 'code'.
     * @return the value of the attribute 'code'.
     */
    public int getCode() {
        return code;
    }

    
    /**
     * Sets the value of the attribute 'code'.
     * @param errorCode The value for the attribute 'code'.
     */
    public void setCode(int errorCode) {
        this.code = errorCode;
    }

    
    /**
     * Gets the value of the attribute 'description'.
     * @return the value of the attribute 'description'.
     */
    public String getDescription() {
        return description;
    }

    
    /**
     * Sets the value of the attribute 'description'.
     * @param message The value for the attribute 'description'.
     */
    public void setDescription(String message) {
        this.description = message;
    }

   


}
