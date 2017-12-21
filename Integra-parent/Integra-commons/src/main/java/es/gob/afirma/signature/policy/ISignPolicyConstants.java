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
 * <b>File:</b><p>es.gob.afirma.signature.policy.ISignPolicyConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants related to the validation and generation of signatures with signature policies.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 25/11/2014.
 */
package es.gob.afirma.signature.policy;

/**
 * <p>Interface that defines all the constants related to the validation and generation of signatures with signature policies.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/11/2014.
 */
public interface ISignPolicyConstants {

    /**
     *  Constant attribute that identifies the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the identifier of the signature policy
     *  to use for XAdES signatures.
     */
    String KEY_XML_POLICY_ID = "XML_POLICY_ID";

    /**
     *  Constant attribute that identifies the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the identifier of the signature policy
     *  to use for CAdES signatures.
     */
    String KEY_ASN1_POLICY_ID = "ASN1_POLICY_ID";

    /**
     *  Constant attribute that identifies the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the identifier of the signature policy
     *  to use for PAdES signatures.
     */
    String KEY_PDF_POLICY_ID = "PDF_POLICY_ID";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the ID of the signature
     *  policy for ASN.1 signatures.
     */
    String KEY_IDENTIFIER_ASN1 = "-IDENTIFIER_ASN1";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the ID of the signature
     *  policy for XML signatures.
     */
    String KEY_IDENTIFIER_XML = "-IDENTIFIER_XML";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the ID of the signature
     *  policy for PDF signatures.
     */
    String KEY_IDENTIFIER_PDF = "-IDENTIFIER_PDF";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the path of the document
     *  with the hash value of the signature policy.
     */
    String KEY_HASH_VALUE = "-HASH_VALUE";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the description of the
     *  signature policy.
     */
    String KEY_DESCRIPTION = "-DESCRIPTION";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the hash algorithm
     *  used for generating the digest of the document of the signature policy.
     */
    String KEY_HASH_ALGORITHM = "-HASH_ALGORITHM";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the allowed hash
     *  algorithms for XML signatures.
     */
    String KEY_XML_HASH = "XML_HASH-";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the allowed sign
     *  algorithms for XML signatures.
     */
    String KEY_XML_SIGN_HASH = "XML_SIGN_HASH-";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of allowed
     *  hash algorithms.
     */
    String KEY_ALLOWED_HASH_ALGORITHM = "-ALLOWED_HASH_ALGORITHM";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of allowed
     *  sign algorithms.
     */
    String KEY_ALLOWED_SIGN_ALGORITHM = "-ALLOWED_SIGN_ALGORITHM";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of required
     *  signed elements defined by the signature policy.
     */
    String KEY_MANDATORY_SIGNED_ELEMENTS = "-MANDATORY_SIGNED_ELEMENTS";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of optional
     *  signed elements defined by the signature policy.
     */
    String KEY_OPTIONAL_SIGNED_ELEMENTS = "-OPTIONAL_SIGNED_ELEMENTS";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of required
     *  unsigned elements defined by the signature policy.
     */
    String KEY_MANDATORY_UNSIGNED_ELEMENTS = "-MANDATORY_UNSIGNED_ELEMENTS";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of optional
     *  unsigned elements defined by the signature policy.
     */
    String KEY_OPTIONAL_UNSIGNED_ELEMENTS = "-OPTIONAL_UNSIGNED_ELEMENTS";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of signed 
     *  elements that shall not be used, defined by the signature policy.
     */
    String KEY_NOT_ALLOWED_SIGNED_ELEMENT = "-NOT_ALLOWED_SIGNED_ELEMENT";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of unsigned 
     *  elements that shall not be used, defined by the signature policy.
     */
    String KEY_NOT_ALLOWED_UNSIGNED_ELEMENTS = "-NOT_ALLOWED_UNSIGNED_ELEMENTS";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of required 
     *  child elements that shall have a parent element, defined by the signature policy.
     */
    String KEY_REQUIRED_CHILD = "-REQUIRED_CHILD";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of optional 
     *  child elements that shall have a parent element, defined by the signature policy.
     */
    String KEY_OPTIONAL_CHILD = "-OPTIONAL_CHILD";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of 
     *  elements that cannot be child of a parent element, defined by the signature policy.
     */
    String KEY_NOT_ALLOWED_CHILD = "-NOT_ALLOWED_CHILD";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of required 
     *  values for an element, defined by the signature policy.
     */
    String KEY_REQUIRED_VALUE = "-REQUIRED_VALUE";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of required 
     *  entries, defined by the signature policy.
     */
    String KEY_REQUIRED_ENTRIES = "-REQUIRED_ENTRIES";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of optional
     *  entries, defined by the signature policy.
     */
    String KEY_OPTIONAL_ENTRIES = "-OPTIONAL_ENTRIES";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of not allowed 
     *  entries, defined by the signature policy.
     */
    String KEY_NOT_ALLOWED_ENTRIES = "-NOT_ALLOWED_ENTRIES";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of not allowed 
     *  values for an element, defined by the signature policy.
     */
    String KEY_NOT_ALLOWED_VALUE = "-NOT_ALLOWED_VALUE";

    /**
     *  Constant attribute that identifies the fixed part of the key defined on {@link #SIGN_POLICY_PROPERTIES} properties file with the list of allowed 
     *  signing modes defined by the signature policy.
     */
    String KEY_ALLOWED_SIGNING_MODES = "-ALLOWED_SIGNING_MODES";

    /**
     * Constant attribute that identifies the AND operator for the values defined on {@link #SIGN_POLICY_PROPERTIES} properties file. 
     */
    String OPERATOR_AND = ",";

    /**
     * Constant attribute that identifies the OR operator for the values defined on {@link #SIGN_POLICY_PROPERTIES} properties file. 
     */
    String OPERATOR_OR = "|";

    /**
     * Constant attribute that identifies the prefix for an entry of a PDF signature dictionary. 
     */
    String ENTRY_PREFIX = "/";

}
