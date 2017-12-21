// Copyright (C) 2012-13 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.utils.EVisorConstants.java.</p>
 * <b>Description:</b><p>Class that defines constants related to eVisor services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/12/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/12/2011.
 */
package es.gob.afirma.utils;

/**
 * <p>Class that defines constants related to eVisor services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/12/2011.
 */
public final class EVisorConstants {

    /**
     * Constructor method for the class EVisorConstants.java.
     */
    private EVisorConstants() {
    }

    /**
     * Attribute that represents the service name 'SignatureReportService' of eVisor WebServices.
     */
    public static final String SIGNATURE_REPORT_SERVICE = "SignatureReportService";

    /**
     * Attribute that represents method name 'generateReport' of SignatureReportService.
     */
    public static final String GENERATE_REPORT_METHOD = "generateReport";

    /**
     * Attribute that represents method name 'validateReport' of SignatureReportService.
     */
    public static final String VALIDATE_REPORT_METHOD = "validateReport";

    /**
     * <p>Class represents constants that contains XPaths of tags of eVisor services.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 14/12/2011.
     */
    public final class EVisorTagsRequest {

	/**
	 * Constructor method for the class EVisorConstants.java.
	 */
	private EVisorTagsRequest() {
	}

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:ApplicationId</code>.
	 */
	public static final String APPLICATION_ID = "srsm:ApplicationId";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:TemplateId</code>.
	 */
	public static final String TEMPLATE_ID = "srsm:TemplateId";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Report</code>.
	 */
	public static final String REPORT = "srsm:Report";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Signature</code>.
	 */
	private static final String SIGNATURE = "srsm:Signature";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:EncodedSignature</code>.
	 */
	public static final String ENCODED_SIGNATURE = SIGNATURE + "/srsm:EncodedSignature";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:RepositoryLocation</code>.
	 */
	private static final String SIGN_REPOSITORY_LOCATION = SIGNATURE + "/srsm:RepositoryLocation";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Signature/srsm:RepositoryLocation/srsm:ObjectId</code>.
	 */
	public static final String SIGN_REPO_OBJECT_ID = SIGN_REPOSITORY_LOCATION + "/srsm:ObjectId";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Signature/srsm:RepositoryLocation/srsm:RepositoryId</code>.
	 */
	public static final String SIGN_REPO_REPOSITORY_ID = SIGN_REPOSITORY_LOCATION + "/srsm:RepositoryId";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:ValidationResponse</code>.
	 */
	public static final String VALIDATION_RESPONSE = SIGNATURE + "/srsm:ValidationResponse";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Document</code>.
	 */
	private static final String DOCUMENT = "srsm:Document";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:EncodedDocument</code>.
	 */
	public static final String ENCODED_DOCUMENT = DOCUMENT + "/srsm:EncodedDocument";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Document/srsm:RepositoryLocation</code>.
	 */
	private static final String DOC_REPOSITORY_LOCATION = DOCUMENT + "/srsm:RepositoryLocation";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Document/srsm:RepositoryLocation</code>.
	 */
	public static final String DOC_REPO_ID = DOC_REPOSITORY_LOCATION + "/srsm:RepositoryId";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Document/srsm:RepositoryLocation/srsm:ObjectId</code>.
	 */
	public static final String DOC_REPO_OBJECT_ID = DOC_REPOSITORY_LOCATION + "/srsm:ObjectId";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:IncludeSignature</code>.
	 */
	public static final String INCLUDE_SIGNATURE = "srsm:IncludeSignature";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Barcodes/srsm:Barcode</code>.
	 */
	public static final String BARCODE = "srsm:Barcodes/srsm:Barcode";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Type</code>.
	 */
	public static final String BARCODE_TYPE = "srsm:Type";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Message</code>.
	 */
	public static final String BARCODE_MESSAGE = "srsm:Message";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Configuration/srsm:Parameter</code>.
	 */
	public static final String BARCODE_CONFIGURATION_PARAM = "srsm:Configuration/srsm:Parameter";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:ParameterId</code>.
	 */
	public static final String PARAMETER_ID = "srsm:ParameterId";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:ParameterValue</code>.
	 */
	public static final String PARAMETER_VALUE = "srsm:ParameterValue";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:ExternalParameters</code>.
	 */
	private static final String EXTERNAL_PARAMETERS = "srsm:ExternalParameters";

	/**
	 * Attribute that represents the XPath for the tag <code>srsm:Parameter</code>.
	 */
	public static final String EXTERNAL_PARAMETERS_PARAM = EXTERNAL_PARAMETERS + "/srsm:Parameter";

    }
}
