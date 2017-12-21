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
 * <b>File:</b><p>es.gob.afirma.signature.Signer.java.</p>
 * <b>Description:</b><p>Interface that defines the common methods to implement for generate and upgrade signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/06/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 28/06/2011.
 */
package es.gob.afirma.signature;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

/**
 * <p>Interface that defines the common methods to implement for generate and upgrade signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/06/2011.
 */
public interface Signer {

    /**
     * Method that generates a basic signature.
     * @param data Parameter that represents the data to sign.
     * @param algorithm Parameter that represents the signature algorithm.
     * @param signatureFormat Parameter that represents the signing mode.
     * The allowed values for a CAdES (Baseline or not) signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_MODE_EXPLICIT}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_MODE_IMPLICIT}</li>
     * </ul>
     * The allowed values for a XAdES (Baseline or not) signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * The allowed values for PAdES (Baseline or not) signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_MODE_IMPLICIT}</li>
     * </ul>
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#CADES_POLICY_QUALIFIER_PROP}. This property is only allowed for CAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_CLAIMED_ROLE_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_POLICY_QUALIFIER_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_DESCRIPTION_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_MIME_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_ENCODING_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CERTIFICATION_LEVEL}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CONTACT_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOCATION_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_REASON_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * </ul>
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for CAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * </ul>
     * The allowed values for XAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * </ul>
     * The allowed values for XAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * </ul>
     * The allowed values for PAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetector#FORMAT_PADES_BASIC}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetector#FORMAT_PADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetector#FORMAT_PADES_EPES}</li>
     * </ul>
     * The allowed values for PAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @return an object that represents the generated signature.
     * @throws SigningException If the method fails.
     */
    byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException;

    /**
     * Method that generates a basic co-signature (signature with signers on parallel). This functionality is unsupported for PAdES (Baseline or not) signatures.
     * @param signature Parameter that represents the original signature.
     * @param document Parameter that represents the data used to generate the original signature.
     * @param algorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#CADES_POLICY_QUALIFIER_PROP}. This property is only allowed for CAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_CLAIMED_ROLE_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_POLICY_QUALIFIER_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_DESCRIPTION_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_MIME_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_ENCODING_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CERTIFICATION_LEVEL}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CONTACT_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOCATION_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_REASON_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * </ul>
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for CAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * </ul>
     * The allowed values for XAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * </ul>
     * The allowed values for XAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @return an object that represents the generated co-signature.
     * @throws SigningException If the method fails.
     */
    byte[ ] coSign(byte[ ] signature, byte[ ] document, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException;

    /**
     * Method that generates a basic counter-signature (signature with signers on serial). This functionality is unsupported for PAdES (Baseline or not) signatures.
     * @param signature Parameter that represents the original signature.
     * @param algorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#CADES_POLICY_QUALIFIER_PROP}. This property is only allowed for CAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_CLAIMED_ROLE_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_POLICY_QUALIFIER_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_DESCRIPTION_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_MIME_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_ENCODING_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CERTIFICATION_LEVEL}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CONTACT_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOCATION_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_REASON_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     
     * </ul>
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for CAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * </ul>
     * The allowed values for XAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * </ul>
     * The allowed values for XAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @return an object that represents the generated counter-signature.
     * @throws SigningException If the method fails.
     */
    byte[ ] counterSign(byte[ ] signature, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID) throws SigningException;

    /**
     * Method that generates a basic signature.
     * @param data Parameter that represents the data to sign.
     * @param algorithm Parameter that represents the signature algorithm.
     * @param signatureFormat Parameter that represents the signing mode.
     * The allowed values for a CAdES (Baseline or not) signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_MODE_EXPLICIT}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_MODE_IMPLICIT}</li>
     * </ul>
     * The allowed values for a XAdES (Baseline or not) signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_EXTERNALLY_DETACHED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPED}</li>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_FORMAT_XADES_ENVELOPING}</li>
     * </ul>
     * The allowed values for PAdES (Baseline or not) signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureConstants#SIGN_MODE_IMPLICIT}</li>
     * </ul>
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#CADES_POLICY_QUALIFIER_PROP}. This property is only allowed for CAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_CLAIMED_ROLE_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_POLICY_QUALIFIER_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_DESCRIPTION_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_MIME_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_ENCODING_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CERTIFICATION_LEVEL}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CONTACT_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOCATION_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_REASON_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * </ul>
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for CAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * </ul>
     * The allowed values for XAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * </ul>
     * The allowed values for XAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * </ul>
     * The allowed values for PAdES signature are:
     * <ul>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetector#FORMAT_PADES_BASIC}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetector#FORMAT_PADES_BES}</li>
     * <li>{@link es.gob.afirma.signature.SignatureFormatDetector#FORMAT_PADES_EPES}</li>
     * </ul>
     * The allowed values for PAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @return an object that represents the generated signature.
     * @throws SigningException If the method fails.
     */
    byte[ ] sign(byte[ ] data, String algorithm, String signatureFormat, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException;

    /**
     * Method that generates a basic co-signature (signature with signers on parallel). This functionality is unsupported for PAdES (Baseline or not) signatures.
     * @param signature Parameter that represents the original signature.
     * @param document Parameter that represents the data used to generate the original signature.
     * @param algorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#CADES_POLICY_QUALIFIER_PROP}. This property is only allowed for CAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_CLAIMED_ROLE_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_POLICY_QUALIFIER_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_DESCRIPTION_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_MIME_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_ENCODING_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CERTIFICATION_LEVEL}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CONTACT_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOCATION_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_REASON_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * </ul>
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for CAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * </ul>
     * The allowed values for XAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * </ul>
     * The allowed values for XAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @return an object that represents the generated co-signature.
     * @throws SigningException If the method fails.
     */
    byte[ ] coSign(byte[ ] signature, byte[ ] document, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException;

    /**
     * Method that generates a basic counter-signature (signature with signers on serial). This functionality is unsupported for PAdES (Baseline or not) signatures.
     * @param signature Parameter that represents the original signature.
     * @param algorithm Parameter that represents the signature algorithm.
     * @param privateKey Parameter that represents the private key of the signing certificate.
     * @param extraParams Set of extra configuration parameters. The allowed parameters are:
     * <ul>
     * <li>{@link SignatureProperties#CADES_POLICY_QUALIFIER_PROP}. This property is only allowed for CAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_CLAIMED_ROLE_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_POLICY_QUALIFIER_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_DESCRIPTION_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_MIME_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#XADES_DATA_FORMAT_ENCODING_PROP}. This property is only allowed for XAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CERTIFICATION_LEVEL}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_CONTACT_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOCATION_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_REASON_PROP}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_LOWER_LEFT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_X}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_UPPER_RIGHT_Y}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * <li>{@link SignatureProperties#PADES_IMAGE_PAGE}. This property is only allowed for PAdES (Baseline or not) signatures.</li>
     * </ul>
     * @param includeTimestamp Parameter that indicates if the signature will include a timestamp (true) or not (false).
     * @param signatureForm Parameter that represents the signature form.
     * The allowed values for CAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}</li>
     * </ul>
     * The allowed values for CAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}</li>
     * </ul>
     * The allowed values for XAdES signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_BES}</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_EPES}</li>
     * </ul>
     * The allowed values for XAdES Baseline signature are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_XADES_B_LEVEL}</li>
     * </ul>
     * @param signaturePolicyID Parameter that represents the identifier of the signature policy used for generate the signature with signature
     * policies. The identifier must be defined on the properties file where to configure the validation and generation of signatures with
     * signature policies.
     * @param idClient Parameter that represents the client application identifier.
     * @return an object that represents the generated counter-signature.
     * @throws SigningException If the method fails.
     */
    byte[ ] counterSign(byte[ ] signature, String algorithm, PrivateKeyEntry privateKey, Properties extraParams, boolean includeTimestamp, String signatureForm, String signaturePolicyID, String idClient) throws SigningException;

    /**
     * Method that upgrades a signature adding a timestamp to all of the signers indicated. If the list of signers is null or empty, the timestamp
     * will be added to all of the signers of the signature. The timestamp will be added only to those signers that don't have a previous timestamp.
     * If the signature has a PDF format this method will add a Document Time-stamp dictionary. If the signature has ASiC-S format the method will upgrade the CAdES or XAdES signature
     * contained inside it.
     * @param signature Parameter that represents the signature to upgrade.
     * @param listSigners Parameter that represents the list of signers of the signature to upgrade with a timestamp. Only for ASN.1 and XML signatures.
     * @return the upgraded signature.
     * @throws SigningException If the method fails.
     */
    byte[ ] upgrade(byte[ ] signature, List<X509Certificate> listSigners) throws SigningException;

    /**
     * Method that upgrades a signature adding a timestamp to all of the signers indicated. If the list of signers is null or empty, the timestamp
     * will be added to all of the signers of the signature. The timestamp will be added only to those signers that don't have a previous timestamp.
     * If the signature has a PDF format this method will add a Document Time-stamp dictionary. If the signature has ASiC-S format the method will upgrade the CAdES or XAdES signature
     * contained inside it.
     * @param signature Parameter that represents the signature to upgrade.
     * @param listSigners Parameter that represents the list of signers of the signature to upgrade with a timestamp. Only for ASN.1 and XML signatures.
     * @param idClient Parameter that represents the client application identifier.
     * @return the upgraded signature.
     * @throws SigningException If the method fails.
     */
    byte[ ] upgrade(byte[ ] signature, List<X509Certificate> listSigners, String idClient) throws SigningException;

    /**
     * Method that obtains the data originally signed from a signature.
     * 
     * @param signature Parameter that represents the signature of which is to obtain the data.
     * @return Information about data originally signed.
     * @throws SigningException If the metod fails.
     */
    OriginalSignedData getSignedData(byte[ ] signature) throws SigningException;

}
