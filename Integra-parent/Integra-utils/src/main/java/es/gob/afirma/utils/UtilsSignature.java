// Copyright (C) 2017 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsSignature.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>07/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.5, 04/03/2020.
 */
package es.gob.afirma.utils;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfReader;

import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.cades.CAdESSignerInfo;
import es.gob.afirma.signature.pades.PDFSignatureDictionary;
import es.gob.afirma.signature.xades.XAdESSignerInfo;

/**
 * <p>Class that contains methods related to the manage of signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.5, 04/03/2020.
 */
public final class UtilsSignature implements IUtilsSignature {

    /**
     * Constructor method for the class SignatureUtils.java.
     */
    private UtilsSignature() {
    }

    /**
     * Method that validates the validity period of a certificate and the revocation status
     * of a certificate (if the validation level for the certificates is defined with the value {@link es.gob.afirma.integraFacade.IntegraFacadeConstants#VALIDATION_LEVEL_COMPLETE}).
     * If the validation level for the certificates is defined with the value {@link es.gob.afirma.integraFacade.IntegraFacadeConstants#VALIDATION_LEVEL_COMPLETE} the validation of
     * the revocation status will be via OCSP.
     * @param certificate Parameter that represents the certificate to validate.
     * @param validationDate Parameter that represents the validation date.
     * @param isUpgradeOperation Parameter that indicates if the origin operation is an upgrade signature operation (true) or not (false).
     * @throws SigningException If the certificate isn't valid or the method fails.
     */
    public static void validateCertificate(X509Certificate certificate, Date validationDate, boolean isUpgradeOperation) throws SigningException {
	UtilsSignatureOp.validateCertificate(certificate, validationDate, isUpgradeOperation, null, false);
    }

    /**
     * Method that obtains the signature dictionary with major review.
     * @param reader Parameter that represents the reader for the PDF document.
     * @return the signature dictionary with major review.
     */
    public static PDFSignatureDictionary obtainLatestSignatureFromPDF(PdfReader reader) {
	return UtilsSignatureOp.obtainLatestSignatureFromPDF(reader);
    }

    /**
     * Method that indicates whether a signature dictionary refers to a PDF or PAdES-Basic signature (true) or to a PAdES-BES or PAdES-EPES signature (false).
     * @param pdfDic Parameter that represents the signature dictionary.
     * @return a boolean that indicates whether a signature dictionary refers to a PDF or PAdES-Basic signature (true) or to a PAdES-BES or PAdES-EPES
     * signature (false).
     */
    public static boolean isNotPAdESEnhancedPDF(PdfDictionary pdfDic) {
	return UtilsSignatureOp.isNotPAdESEnhancedPDF(pdfDic);
    }

    /**
     * Method that obtains the <code>SignedData</code> contained inside of a signature dictionary of a PDF document.
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @return an object that represents the <code>SignedData</code>.
     * @throws SigningException If the method fails.
     */
    public static CMSSignedData getCMSSignature(PDFSignatureDictionary signatureDictionary) throws SigningException {
	return UtilsSignatureOp.getCMSSignature(signatureDictionary);
    }

    /**
     * Method that indicates whether the signature includes the original document (true) or not (false).
     * @param cmsSignedData Parameter that represents the pkcs7-signature message.
     * @return a boolean that indicates whether the signature includes the original document (true) or not (false).
     */
    public static boolean isImplicit(CMSSignedData cmsSignedData) {
	return UtilsSignatureOp.isImplicit(cmsSignedData);
    }

    /**
     * Method that compares two bytes arrays and indicates if the hash of each is equals (true) or not (false).
     * @param pdfArrayByteRange Parameter that represents the exact byte range for the digest calculation.
     * @param messageDigestSignature Parameter that represents the message digest algorithm.
     * @param pdfDocument Parameter that represents the first bytes array to compare.
     * @param hashSignature Parameter that represents the second bytes array to compare.
     * @return a boolean that indicates if the hash of each is equals (true) or not (false).
     */
    public static boolean equalsHash(PdfArray pdfArrayByteRange, MessageDigest messageDigestSignature, byte[ ] pdfDocument, byte[ ] hashSignature) {
	return UtilsSignatureOp.equalsHash(pdfArrayByteRange, messageDigestSignature, pdfDocument, hashSignature);
    }

    /**
     * The ISO 32000-1 specifies in section 12.8.3.3.1:
     * - adbe.pkcs7.detached: The original signed message digest over the document’s byte range shall
     *   be incorporated as the normal PKCS#7 SignedData field. No data shall be encapsulated in the
     *   PKCS#7 SignedData field.
     * - adbe.pkcs7.sha1: The SHA1 digest of the document’s byte range shall be encapsulated in the
     *   PKCS#7 SignedData field with ContentInfo of type Data. The digest of that SignedData shall
     *   be incorporated as the normal PKCS#7 digest.
     * This method checks if that conditions are valid.
     * @param dictionarySignature Parameter that represents the signature dictionary.
     * @param signedData Parameter that represents the signed data.
     * @throws SigningException If one of the conditiones isn't valid.
     */
    public static void checkSubFilterConditionsISO320001(PDFSignatureDictionary dictionarySignature, CMSSignedData signedData) throws SigningException {
	UtilsSignatureOp.checkSubFilterConditionsISO320001(dictionarySignature, signedData);
    }

    /**
     * Method that validates the mandatory attributes for a PAdES enhanced signature. The method verifies that:
     * <ul>
     * <li>The <i>content-type</i> attribute cannot be null and must have the value <code>id-data</code>.</li>
     * <li>The entry with the key <i>Cert</i> in the signature dictionary isn't used.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param signedData Parameter that represents the signed data.
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESEnhancedMandatoryAttributes(PDFSignatureDictionary signatureDictionary, CMSSignedData signedData) throws SigningException {
	UtilsSignatureOp.validatePAdESEnhancedMandatoryAttributes(signatureDictionary, signedData);
    }

    /**
     * Method that validates the optional attributes for a PAdES signature. The method verifies that:
     * <ul>
     * <li>The <i>counter-signature</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-reference</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-identifier</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>Reason</i> key isn't present in the signature dictionary if the signature has PAdES-EPES profile.</li>
     * <li>The <i>commitment-type-indication</i> attribute isn't used if the signature has PAdES-BES profile.</li>
     * <li>The <i>signer-location</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>signing-time</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>The <i>content-hints</i> attribute isn't used if the signature has PAdES-EPES or PAdES-BES profile.</li>
     * <li>If the signature dictionary has /M entry that entry must be a date with a valid format by PDF Reference and
     * that date must be before of the validation date if the signature has PAdES-Basic, PAdES-EPES or PAdES-BES profile.</li>
     * </ul>
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param signedData Parameter that represents the signed data.
     * @param isEPES Parameter that indicates if the signature has PAdES-EPES profile (true) or PAdES-BES profile (false).
     * @param isBasic Parameter that indicates if the signature has PAdES-Basic profile (true) or PAdES Enhanced profile (false).
     * @throws SigningException If the validation fails.
     */
    public static void validatePAdESOptionalAttributes(PDFSignatureDictionary signatureDictionary, CMSSignedData signedData, boolean isEPES, boolean isBasic) throws SigningException {
	UtilsSignatureOp.validatePAdESOptionalAttributes(signatureDictionary, signedData, isEPES, isBasic);
    }

    /**
     * Method that obtains the structure of a certificate from a certificates store.
     * @param certificatesStore Parameter that represents the certificates store.
     * @param signerId Parameter that represents the identifier of the signer used to find the certificate.
     * @return an object that represents the structure of the certificate.
     */
    public static X509CertificateHolder getX509CertificateHolderBySignerId(Store certificatesStore, SignerId signerId) {
	return UtilsSignatureOp.getX509CertificateHolderBySignerId(certificatesStore, signerId);
    }

    /**
     * Method that validates the signer of a signature contained inside of a PDF document.
     * @param signedData Parameter that represents the signed data.
     * @param signerInformation Parameter that represents the signer information.
     * @param pdfSignatureDictionary Parameter that represents the PDF signature dictionary.
     * @param validationDate Parameter that represents the validation date.
     * @throws SigningException If the validation fails.
     */
    public static void validatePDFSigner(CMSSignedData signedData, SignerInformation signerInformation, PdfDictionary pdfSignatureDictionary, Date validationDate) throws SigningException {
	UtilsSignatureOp.validatePDFSigner(signedData, signerInformation, pdfSignatureDictionary, validationDate, null);
    }

    /**
     * Method that obtains a list with the principal information related to the signers of a XAdES signature.
     * @param doc Parameter that represents the XML document.
     * @return a list with the principal information related to the signers of a XAdES signature.
     */
    public static List<XAdESSignerInfo> getXAdESListSigners(Document doc) {
	return UtilsSignatureOp.getXAdESListSigners(doc);
    }

    /**
     * Method that obtains a list with the principal information related to the signers of a CAdES signature.
     * @param signedData Parameter that represents the signed data.
     * @return a list with the principal information related to the signers of a CAdES signature.
     */
    public static List<CAdESSignerInfo> getCAdESListSigners(CMSSignedData signedData) {
	return UtilsSignatureOp.getCAdESListSigners(signedData);
    }

    /**
     * Method that validates the signer of a XAdES signature.
     * @param xmlSignature Parameter that represents the XAdES signature.
     * @param signingCertificate Parameter that represents the signing certificate
     * @param tst Parameter that represents the RFC 3161 timestamp associated to the signer.
     * @param xmlTst Parameter that represents the XML timestamp associated to the signer.
     * @param signingMode Parameter that represents the signing mode of the XAdES signature. The possible values are:
     * <ul>
     * <li>{@link IUtilsSignature#DETACHED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPED_SIGNATURE_MODE}</li>
     * <li>{@link IUtilsSignature##ENVELOPING_SIGNATURE_MODE}</li>
     * </ul>
     * @param signedFile Parameter that represents the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @param signedFileName Parameter that represents the name of the file signed by the XML signature when the signed data isn't included into the signed XML document.
     * @throws SigningException If the validation fails.
     */
    public static void validateXAdESSigner(org.apache.xml.security.signature.XMLSignature xmlSignature, X509Certificate signingCertificate, TimeStampToken tst, Element xmlTst, String signingMode, byte[ ] signedFile, String signedFileName) throws SigningException {
	UtilsSignatureOp.validateXAdESSigner(xmlSignature, signingCertificate, tst, xmlTst, signingMode, signedFile, signedFileName, null);
    }

    /**
     * Method that obtains the singing certificate of a signer of a signature.
     * @param signedData Parameter that represents the signed data.
     * @param signerInformation Parameter that represents the information about the signer of the signature.
     * @return an object that represents the signing certificate.
     * @throws SigningException If the certificate hasn't could be retrieved.
     */
    public static X509Certificate getSigningCertificate(CMSSignedData signedData, SignerInformation signerInformation) throws SigningException {
	return UtilsSignatureOp.getSigningCertificate(signedData, signerInformation);
    }

    /**
     * Method that obtains an object as a representation of a XML document.
     * @param xmlDocument Parameter that represents the XML document.
     * @return an object as a representation of the XML document.
     * @throws SigningException If the XML document has a bad format.
     */
    public static Document getDocumentFromXML(byte[ ] xmlDocument) throws SigningException {
	return UtilsSignatureCommons.getDocumentFromXML(xmlDocument);
    }

    /**
     * Method that obtains the revision of the signature dictionary most recent.
     * @param reader Parameter that represents the reader for the PDF document.
     * @return an input stream that represents the revision, or <code>null</code> if the PDF document doesn't contain any signature dictionary.
     * @throws SigningException If cannot access to some revision.
     */
    public static PdfReader obtainLatestRevision(PdfReader reader) throws SigningException {
	return UtilsSignatureOp.obtainLatestRevision(reader);
    }

    /**
     * Method that validates if some approval signature was added to a PDF document after that it was defined as certified.
     * @param mapRevisions Parameter that represents a map with the revisions of the PDF document. Each revision represents a signature dictionary. The key
     * is the revision number, and the value is the revision.
     * @throws SigningException If the method fails or some approval signature was added to a PDF document after that it was defined as certified.
     */
    public static void checkPDFCertificationLevel(Map<Integer, InputStream> mapRevisions) throws SigningException {
	UtilsSignatureOp.checkPDFCertificationLevel(mapRevisions);
    }

}
