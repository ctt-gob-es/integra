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
 * <b>File:</b><p>es.gob.afirma.signature.SignatureProperties.java.</p>
 * <b>Description:</b><p>Class that defines the keys for the optional input parameters allowed for signing processes of the platform.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/06/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 28/06/2011.
 */
package es.gob.afirma.signature;

/**
 * <p>Class that defines the keys for the optional input parameters allowed for signing processes of the platform.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/06/2011.
 */
public final class SignatureProperties {

    /**
     * Constructor method for the class Afirma5ServiceInvokerProperties.java.
     */
    private SignatureProperties() {
    }

    /**
     * Attribute that represents property name for policy qualifier in CADES signatures.
     */
    public static final String CADES_POLICY_QUALIFIER_PROP = "cades.policyQualifier";

    /**
     * Attribute that represents property name for claimedRole in XAdES signatures.
     */
    public static final String XADES_CLAIMED_ROLE_PROP = "xades.claimedRole";

    /**
     * Attribute that represents property name for policy qualifier in XAdES signatures.
     */
    public static final String XADES_POLICY_QUALIFIER_PROP = "xades.policyQualifier";

    /**
     * Attribute that represents property name for description of the format of the signed data object.
     */
    public static final String XADES_DATA_FORMAT_DESCRIPTION_PROP = "xades.dataFormatObjectDescription";

    /**
     * Attribute that represents property name for mime of the format of the signed data object.
     */
    public static final String XADES_DATA_FORMAT_MIME_PROP = "xades.dataFormatObjectMime";

    /**
     * Attribute that represents property name for encoding of the format of the signed data object.
     */
    public static final String XADES_DATA_FORMAT_ENCODING_PROP = "xades.dataFormatObjectEncoding";

    /**
     * Attribute that represents property name for encoding of the URI canonicalization algorithm to use.
     */
    public static final String XADES_CANONICALIZATION_METHOD = "xades.canonicalizationMethod";

    /**
     * Attribute that represents property name for reason in PAdES signatures.
     */
    public static final String PADES_REASON_PROP = "Pades.signReason";

    /**
     * Attribute that represents property name for contact in PAdES signatures.
     */
    public static final String PADES_CONTACT_PROP = "Pades.signContact";

    /**
     * Attribute that represents property name for location in PAdES signatures.
     */
    public static final String PADES_LOCATION_PROP = "Pades.signLocation";

    /**
     * Attribute that represents property name to define the certification level of the PAdES signature. The allowed values are two:
     * <ul>
     * <li>CERTIFIED_NO_CHANGES_ALLOWED: After the signature is applied, no changes to the document will be allowed.</li>
     * <li>NOT_CERTIFIED: Other people can add approval signatures without invalidating the signature.</li>
     * </ul>
     */
    public static final String PADES_CERTIFICATION_LEVEL = "Pades.certificationLevel";
	
	/**
	 * Attribute representing the name of the property for the image to be inserted as a rubric in the PDF.
	 */
	public static final String PADES_IMAGE ="Pades.image";
	
	/**
	 * Attribute representing the name of the property to indicate the page where the image will be inserted.
	 */
	public static final String PADES_IMAGE_PAGE ="Pades.imagePage";
	
	/**
	 * Attribute representing the name of the property to define the coordinate horizontal lower left of the image position.
	 */
	public static final String PADES_LOWER_LEFT_X ="Pades.imagePositionOnPageLowerLeftX";
	
	/**
	 * Attribute representing the name of the property to define the coordinate vertically lower left of the image position.
	 */
	public static final String PADES_LOWER_LEFT_Y ="Pades.imagePositionOnPageLowerLeftY";
	
	/**
	 * Attribute representing the name of the property to define the coordinate horizontal upper right of the image position.
	 */
	public static final String PADES_UPPER_RIGHT_X ="Pades.imagePositionOnPageUpperRightX";
	
	/**
	 * Attribute representing the name of the property to define the coordinate vertically upper right of the image position.
	 */
	public static final String PADES_UPPER_RIGHT_Y ="Pades.imagePositionOnPageUpperRightY";
	

}
