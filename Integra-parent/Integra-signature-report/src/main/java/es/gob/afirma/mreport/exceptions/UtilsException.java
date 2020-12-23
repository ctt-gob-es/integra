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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/** 
 * <b>File:</b><p>es.gob.afirma.mreport.utils.ToolsException.java.</p>
 * <b>Description:</b><p> Class that contains information about an error that occurred in one of the utility classes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 25/08/2020.
 */
package es.gob.afirma.mreport.exceptions;

/** 
 * <p>Class that contains information about an error that occurred in one of the utility classes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/08/2020.
 */
public class UtilsException extends Exception {

	/**
	 * Attribute that represents serial version of class. 
	 */
	private static final long serialVersionUID = -8115731516478580213L;

	/**
	 * Attribute that represents the code associated to unknown error. 
	 */
	public static final int UNKNOWN_ERROR = -1;

	/**
	 * Attribute that represents the code associated to XML parser error. 
	 */
	public static final int XML_PARSER_ERROR = 1;

	/**
	 * Attribute that represents the code associated to an error while search by XPATH. 
	 */
	public static final int XPATH_ERROR = 2;

	/**
	 * Attribute that represents the code associated to a invalid signature. 
	 */
	public static final int INVALID_SIGNATURE = 3;

	/**
	 * Attribute that represents the code associated to an error while transform by XSLT. 
	 */
	public static final int XSL_TRANSFORM_ERROR = 4;

	/**
	 * Attribute that represents the error code associated to invalid number of page. 
	 */
	public static final int INVALID_PAGE_NUMBER = 5;

	/**
	 * Attribute that represents the file supplied is not valid PDF. 
	 */
	public static final int INVALID_PDF_FILE = 6;

	/**
	 * Attribute that represents the concatenation rule isn't valid. 
	 */
	public static final int INVALID_CONCATENATION_RULE = 7;

	/**
	 * Attribute that represents that an error occurs while the system access to a file. 
	 */
	public static final int ACCESS_FILE_ERROR = 8;
	
	/**
	 * Attribute that represents the document isn't a valid ODF. 
	 */
	public static final int INVALID_ODF_FILE = 9;

	/**
	 * Attribute that represents the operation is not allowed. 
	 */
	public static final int OPERATION_NOT_ALLOWED = 10;

	/**
	 * Attribute that represents the document is not a valid XSL-FO file. 
	 */
	public static final int INVALID_FO_FILE = 11;

	/**
	 * Attribute that represents the rotated angle is not allow. 
	 */
	public static final int INVALID_ROTATED_ANGLE = 12;

	/**
	 * Attribute that specifies the error type. 
	 */
	private int code = UNKNOWN_ERROR;

	/**
	 * Attribute that represents a description of error. 
	 */
	private String description = null;

	/**
	 * Gets the value of the attribute 'code'.
	 * @return the value of the attribute 'code'.
	 */
	public int getCode() {
		return code;
	}

	/**
	 * Sets the value of the attribute 'code'.
	 * @param code The value for the attribute 'code'.
	 */
	public void setCode(int code) {
		this.code = code;
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
	 * @param description The value for the attribute 'description'.
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Constructor method for the class TransformException.java.
	 * @param code		Code of error.
	 * @param description 	Description of error.
	 */
	public UtilsException(int code, String description) {
		super(description);
		this.code = code;
		this.description = description;
	}
	
	/**
     * Constructor method for the class TransformException.java.
     * @param code		Code of error.
     * @param description 	Description of error.
     * @param cause			Error cause.
     */
    public UtilsException(int code, String description,Throwable cause) {
	super(description,cause);
	this.code = code;
	this.description = description;
    }
}
