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
 * <b>File:</b><p>es.gob.afirma.signature.SignatureFormatDetector.java.</p>
 * <b>Description:</b><p>Class that contains all the functionality related to recognize the signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.3, 06/10/2017.
 */
package es.gob.afirma.signature;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.signature.pades.PDFSignatureDictionary;
import es.gob.afirma.utils.UtilsSignatureOp;

/**
 * <p>Class that contains all the functionality related to recognize the signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 06/10/2017.
 */
@SuppressWarnings("unchecked")
public final class SignatureFormatDetectorCadesPades implements ISignatureFormatDetector {

    /**
     * Constant attribute that represents the OID of the <code>attribute-certificate-references</code> attribute.
     */
    private static final DERObjectIdentifier ID_ATTRIBUTE_CERTIFICATE_REFERENCES = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.44");

    /**
     * Constant attribute that represents the OID of the <code>attribute-revocation-references</code> attribute.
     */
    private static final DERObjectIdentifier ID_ATTRIBUTE_REVOCATION_REFERENCES = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.45");

    /**
     * Constant attribute that represents the OID of the <code>long-term-validation</code> attribute.
     */
    private static final DERObjectIdentifier ID_LONG_TERM_VALIDATION = new ASN1ObjectIdentifier("0.4.0.1733.2.2");

    /**
     * Constant attribute that represents the OID of the <code>archive-time-stamp-v3</code> attribute.
     */
    private static final DERObjectIdentifier ID_ARCHIVE_TIME_STAMP_V3 = new ASN1ObjectIdentifier("0.4.0.1733.2.4");

    /**
     * Constructor method for the class SignatureFormatDetector.java.
     */
    private SignatureFormatDetectorCadesPades() {
    }

    /**
     * Method that obtains the format of a signature.
     * @param signature Parameter that represents the element to evaluate. This element can be an ASN.1 signature or a PDF document.
     * @return the signature format of the element. If the element is an ASN.1 signature, the value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     * If the element is a PDF document, the value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LTV}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BASIC}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PDF}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    public static String getSignatureFormat(byte[ ] signature) {
	// Comprobamos que se ha indicado el elemento a comprobar
	if (signature == null) {
	    throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.SFD_LOG001));
	}

	// Por defecto definimos que el formato no está reconocido
	String format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	// Si se ha indicado una firma ASN.1
	if (isASN1Format(signature)) {
	    format = resolveASN1Format(signature);
	}
	// Si se ha indicado un documento PDF
	else if (isPDFFormat(signature)) {
	    format = resolvePDFFormat(signature);
	}
	return format;
    }

    /**
     * Method that indicates whether a signature is ASN.1 (true) or not (false).
     * @param signature Parameter that represents the signature to check.
     * @return a boolean that indicates whether a signature is ASN.1 (true) or not (false).
     */
    public static boolean isASN1Format(byte[ ] signature) {
	try {
	    CMSSignedData signedData = new CMSSignedData(signature);
	    ContentInfo contentInfo = signedData.getContentInfo();
	    if (!contentInfo.getContentType().equals(CMSObjectIdentifiers.signedData)) {
		// Es una estructura ASN.1, pero no es una firma
		return false;
	    }
	    return true;
	} catch (Exception e) {
	    return false;
	}
    }

    /**
     * Method that indicates whether a signature is XML (true) or not (false).
     * @param signature Parameter that represents the signature to check.
     * @return a boolean that indicates whether a signature is XML (true) or not (false).
     */
    public static boolean isXMLFormat(byte[ ] signature) {
	return SignatureFormatDetectorCommons.isXMLFormat(signature);
    }

    /**
     * Method that indicates whether a signature is PDF (true) or not (false).
     * @param signature Parameter that represents the signature to check.
     * @return a boolean that indicates whether a signature is PDF (true) or not (false).
     */
    public static boolean isPDFFormat(byte[ ] signature) {
	PdfReader reader;
	try {
	    reader = new PdfReader(signature);
	} catch (Exception e) {
	    // No se trata de una documento PDF
	    return false;
	}
	// Creamos un objeto para consultar campos del PDF
	AcroFields fields = reader.getAcroFields();
	// Obtenemos la lista de firmas del documento PDF
	List<String> sigNames = fields.getSignatureNames();
	// En el momento en que el documento PDF tenga alguna firma para
	// validar entendemos que es válido
	for (int i = 0; i < sigNames.size(); i++) {
	    PdfDictionary dictionary = fields.getSignatureDictionary((String) sigNames.get(i));
	    if (dictionary != null) {
		return true;
	    }
	}
	// El documento PDF no contiene firmas
	return false;
    }

    /**
     * Method that indicates if a signature dictionary refers to a PAdES B-Level profile (true) or not (false).
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @return a boolean that indicates if a signature dictionary refers to a PAdES B-Level profile (true) or not (false).
     */
    private static boolean isPAdESBLevel(PDFSignatureDictionary signatureDictionary) {
	/*
	 * Consideramos que una firma es PAdES B-Level si:
	 * > El núcleo de firma CAdES contiene el elemento SignedData.certificates con, al menos, un certificado (el firmante).
	 * > Contiene la entrada /M en el diccionario de firma.
	 * > La entrada /SubFilter del diccionario de firma posee el valor 'ETSI.CAdES.detached'.
	 */
	PdfDictionary pdfDic = signatureDictionary.getDictionary();

	// Accedemos a la entrada /SubFilter
	PdfName subFilterValue = signatureDictionary.getDictionary().getAsName(PdfName.SUBFILTER);

	// Comprobamos que la entrada /SubFilter posee el valor
	// 'ETSI.CAdES.detached' y que se encuentra la entrada /M en el
	// diccionario de firma
	if (subFilterValue.equals(UtilsSignatureOp.CADES_SUBFILTER_VALUE) && pdfDic.get(PdfName.M) != null) {
	    try {
		// Obtenemos los datos firmados
		CMSSignedData signedData = UtilsSignatureOp.getCMSSignature(signatureDictionary);

		// Accedemos al elemento SignedData.certificates y comprobamos
		// que posee al menos un elemento
		if (!signedData.getCertificates().getMatches(null).isEmpty()) {
		    return true;
		}
	    } catch (Exception e) {
		return false;
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signature dictionary refers to a PAdES T-Level profile (true) or not (false).
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param reader Parameter that allows to read the PDF document.
     * @return a boolean that indicates if a signature dictionary refers to a PAdES T-Level profile (true) or not (false).
     */
    private static boolean isPAdESTLevel(PDFSignatureDictionary signatureDictionary, PdfReader reader) {
	/*
	 * Consideramos que una firma es PAdES T-Level si:
	 * > El núcleo de firma CAdES contiene un único elemento signature-time-stamp y el documento PDF no contiene ningún diccionario de sello de tiempo
	 * o
	 * > El núcleo de firma CAdES no contiene ningún elemento signature-time-stamp y el documento PDF contiene un único diccionario de sello de tiempo
	 */
	try {
	    int signatureTimeStampNumber = 0;
	    int documentTimeStampDictionariesNumber = 0;

	    // Obtenemos los datos firmados
	    CMSSignedData signedData = UtilsSignatureOp.getCMSSignature(signatureDictionary);
	    if (!signedData.getCertificates().getMatches(null).isEmpty()) {
		// Obtenemos la lista con todos los firmantes contenidos en la
		// firma
		SignerInformationStore signerInformationStore = signedData.getSignerInfos();
		List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();

		// Accedemos al primer firmante
		SignerInformation signerInfo = listSignersSignature.get(0);

		// Obtenemos el número de atributos signature-time-stamp
		if (signerInfo.getUnsignedAttributes() != null && signerInfo.getUnsignedAttributes().getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
		    signatureTimeStampNumber = signerInfo.getUnsignedAttributes().getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).size();
		}

		// Obtenemos el número de diccionarios de sello de tiempo
		documentTimeStampDictionariesNumber = countDocumentTimeStampDictionaries(reader);

		if (signatureTimeStampNumber == 1 && documentTimeStampDictionariesNumber == 0 || signatureTimeStampNumber == 0 && documentTimeStampDictionariesNumber == 1) {
		    return true;
		}
	    }
	    return false;
	} catch (Exception e) {
	    return false;
	}
    }

    /**
     * Method that indicates if a signature dictionary refers to a PAdES LT-Level profile (true) or not (false).
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param reader Parameter that allows to read the PDF document.
     * @return a boolean that indicates if a signature dictionary refers to a PAdES LT-Level profile (true) or not (false).
     */
    private static boolean isPAdESLTLevel(PDFSignatureDictionary signatureDictionary, PdfReader reader) {
	/*
	 * Consideramos que una firma es PAdES LT-Level si:
	 * > El documento PDF contiene al menos un diccionario DSS
	 * > El núcleo de firma CAdES contiene un único elemento signature-time-stamp y el documento PDF no contiene ningún diccionario de sello de tiempo
	 * o
	 * > El núcleo de firma CAdES no contiene ningún elemento signature-time-stamp y el documento PDF contiene un único diccionario de sello de tiempo
	 */
	if (isPAdESTLevel(signatureDictionary, reader)) {
	    if (reader.getCatalog().get(UtilsSignatureOp.DSS_DICTIONARY_NAME) != null) {
		return true;
	    } else {
		// Instanciamos un objeto para leer las firmas
		AcroFields af = reader.getAcroFields();

		// Obtenemos la lista de firmas del documento PDF
		List<String> listSignatures = af.getSignatureNames();

		for (int i = 0; i < listSignatures.size(); i++) {
		    // Metemos en una variable el nombre de la firma
		    String signatureName = listSignatures.get(i);

		    try {
			// Obtenemos el PdfReader asociado a la revisión que
			// estamos procesando
			PdfReader revisionReader = new PdfReader(af.extractRevision(signatureName));

			if (revisionReader.getCatalog().getAsDict(UtilsSignatureOp.DSS_DICTIONARY_NAME) != null) {
			    return true;
			}
		    } catch (IOException e) {
			return false;
		    }
		}
	    }
	}
	return false;
    }

    /**
     * Method that indicates if a signature dictionary refers to a PAdES LTA-Level profile (true) or not (false).
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @param reader Parameter that allows to read the PDF document.
     * @return a boolean that indicates if a signature dictionary refers to a PAdES LTA-Level profile (true) or not (false).
     */
    private static boolean isPAdESLTALevel(PDFSignatureDictionary signatureDictionary, PdfReader reader) {
	/*
	 * Consideramos que una firma es PAdES LTA-Level si:
	 * > El documento PDF contiene al menos un diccionario DSS
	 * > El documento PDF contiene al menos un diccionario de sello de tiempo
	 * > El núcleo de firma CAdES contiene al menos un atributo signature-time-stamp
	 */
	int signatureTimeStampNumber = 0;
	int documentTimeStampDictionariesNumber = 0;

	try {

	    // Obtenemos los datos firmados
	    CMSSignedData signedData = UtilsSignatureOp.getCMSSignature(signatureDictionary);

	    if (!signedData.getCertificates().getMatches(null).isEmpty()) {
		// Obtenemos la lista con todos los firmantes contenidos en la
		// firma
		SignerInformationStore signerInformationStore = signedData.getSignerInfos();
		List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();

		// Accedemos al primer firmante
		SignerInformation signerInfo = listSignersSignature.get(0);

		// Obtenemos el número de atributos signature-time-stamp
		if (signerInfo.getUnsignedAttributes() != null && signerInfo.getUnsignedAttributes().getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
		    signatureTimeStampNumber = signerInfo.getUnsignedAttributes().getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).size();
		}

		// Obtenemos el número de diccionarios de sello de tiempo
		documentTimeStampDictionariesNumber = countDocumentTimeStampDictionaries(reader);

		if (signatureTimeStampNumber > 1 || documentTimeStampDictionariesNumber > 1) {
		    if (reader.getCatalog().get(UtilsSignatureOp.DSS_DICTIONARY_NAME) != null) {
			return true;
		    } else {
			// Instanciamos un objeto para leer las firmas
			AcroFields af = reader.getAcroFields();

			// Obtenemos la lista de firmas del documento PDF
			List<String> listSignatures = af.getSignatureNames();

			for (int i = 0; i < listSignatures.size(); i++) {
			    // Metemos en una variable el nombre de la firma
			    String signatureName = listSignatures.get(i);

			    // Obtenemos el PdfReader asociado a la revisión que
			    // estamos procesando
			    PdfReader revisionReader = new PdfReader(af.extractRevision(signatureName));

			    if (revisionReader.getCatalog().getAsDict(UtilsSignatureOp.DSS_DICTIONARY_NAME) != null) {
				return true;
			    }
			}
		    }
		}
	    }
	    return false;
	} catch (Exception e) {
	    return false;
	}
    }

    /**
     * Method that obtains the number of Document Time-stamp dictionaries included into the PDF document.
     * @param reader Parameter that allows to read the PDF document.
     * @return the number of Document Time-stamp dictionaries included into the PDF document.
     */
    private static int countDocumentTimeStampDictionaries(PdfReader reader) {
	int documentTimeStampDictionaries = 0;

	// Instanciamos un objeto para leer las firmas
	AcroFields af = reader.getAcroFields();

	// Obtenemos la lista de firmas del documento PDF
	List<String> listSignatures = af.getSignatureNames();

	for (int i = 0; i < listSignatures.size(); i++) {
	    // Metemos en una variable el nombre de la firma
	    String signatureName = listSignatures.get(i);

	    // Obtenemos el diccionario de firma asociado
	    PdfDictionary signatureDictionary = af.getSignatureDictionary(signatureName);

	    // Determinamos el tipo de diccionario obtenido
	    String pdfType = null;
	    if (signatureDictionary.get(PdfName.TYPE) != null) {
		pdfType = signatureDictionary.get(PdfName.TYPE).toString();
	    }

	    String pdfSubFilter = signatureDictionary.get(PdfName.SUBFILTER).toString();

	    // Comprobamos si existe al menos un diccionario de firma de
	    // tipo Document Time-stamp
	    if (pdfSubFilter.equalsIgnoreCase(UtilsSignatureOp.TST_SUBFILTER_VALUE.toString()) && (pdfType == null || pdfType.equals(UtilsSignatureOp.DOC_TIME_STAMP_DICTIONARY_NAME.toString()))) {
		documentTimeStampDictionaries++;
	    }
	}
	return documentTimeStampDictionaries;
    }

    /**
     * Method that obtains the concrete signature format of a PDF document.
     * @param pdfDocument Parameter that represents the PDF document.
     * @return the signature format. The format will have one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LTV}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BASIC}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PDF}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    private static String resolvePDFFormat(byte[ ] pdfDocument) {
	// Por defecto establecemos el formato como no reconocido
	String format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;

	try {
	    // Leemos el documento PDF
	    PdfReader reader = new PdfReader(pdfDocument);

	    // El formato de firma será determinado por la firma con mayor
	    // revisión
	    PDFSignatureDictionary signatureDictionary = UtilsSignatureOp.obtainLatestSignatureFromPDF(reader);

	    if (isPAdESBLevel(signatureDictionary)) {
		format = FORMAT_PADES_B_LEVEL;
		if (isPAdESLTALevel(signatureDictionary, reader)) {
		    format = FORMAT_PADES_LTA_LEVEL;
		} else if (isPAdESLTLevel(signatureDictionary, reader)) {
		    format = FORMAT_PADES_LT_LEVEL;
		} else if (isPAdESTLevel(signatureDictionary, reader)) {
		    format = FORMAT_PADES_T_LEVEL;
		}
	    } else {
		return getFormatOfPAdESSignature(signatureDictionary, reader);
	    }
	} catch (Exception e) {
	    format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	}
	return format;
    }

    /**
     * Method that obtains the concrete signature format of a PDF document when the concrete signature format hasn't Baseline form.
     * @param signatureDictionary Parameter that represents the most recent signature dictionary.
     * @param reader Parameter that allows to read the PDF document.
     * @return the signature format. The format will have one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_LTV}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BASIC}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PDF}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    private static String getFormatOfPAdESSignature(PDFSignatureDictionary signatureDictionary, PdfReader reader) {
	// Por defecto establecemos el formato como no reconocido
	String format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;

	if (isPAdESLTV(reader)) {
	    format = FORMAT_PADES_LTV;
	} else {
	    // Comprobamos el formato específico de la firma
	    if (isPAdESEPES(signatureDictionary)) {
		format = FORMAT_PADES_EPES;
	    } else if (isPAdESBES(signatureDictionary)) {
		format = FORMAT_PADES_BES;
	    } else if (isPAdESBasic(signatureDictionary)) {
		format = FORMAT_PADES_BASIC;
	    } else if (isPDF(signatureDictionary)) {
		format = FORMAT_PDF;
	    }
	}

	return format;
    }

    /**
     * Method that indicates whether a signature dictionary has PAdES-EPES signature format (true) or not (false).
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @return a boolean that indicates whether a signature dictionary has PAdES-EPES signature format (true) or not (false).
     */
    public static boolean isPAdESEPES(PDFSignatureDictionary signatureDictionary) {
	// Según ETSI TS 102 778-3 una firma PAdES-EPES debe tener
	// el valor 'ETSI.CAdES.detached' en el campo /SubFilter
	// y política de firma asociada, es decir, el atributo
	// signature-policy-identifier debe ser un atributo firmado.
	PdfName subFilterValue = signatureDictionary.getDictionary().getAsName(PdfName.SUBFILTER);
	if (subFilterValue.equals(UtilsSignatureOp.CADES_SUBFILTER_VALUE)) {
	    try {
		// Obtenemos los datos firmados
		CMSSignedData signedData = UtilsSignatureOp.getCMSSignature(signatureDictionary);

		// Obtenemos la lista con todos los firmantes contenidos en la
		// firma
		SignerInformationStore signerInformationStore = signedData.getSignerInfos();
		List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();

		// Comprobamos si la firma contenida es CAdES-EPES
		return isCAdESEPES(listSignersSignature);
	    } catch (Exception e) {
		return false;
	    }
	}
	return false;
    }

    /**
     * Method that indicates whether a signature dictionary has PAdES-BES signature format (true) or not (false).
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @return a boolean that indicates whether a signature dictionary has PAdES-BES signature format (true) or not (false).
     */
    public static boolean isPAdESBES(PDFSignatureDictionary signatureDictionary) {
	// Según ETSI TS 102 778-3 una firma PAdES-BES debe tener
	// el valor 'ETSI.CAdES.detached' en el campo /SubFilter
	// y no tener política de firma asociada, es decir, el atributo
	// signature-policy-identifier no debe ser un atributo firmado.
	PdfName subFilterValue = signatureDictionary.getDictionary().getAsName(PdfName.SUBFILTER);
	if (subFilterValue.equals(UtilsSignatureOp.CADES_SUBFILTER_VALUE)) {
	    try {
		// Obtenemos los datos firmados
		CMSSignedData signedData = UtilsSignatureOp.getCMSSignature(signatureDictionary);

		// Obtenemos la lista con todos los firmantes contenidos en la
		// firma
		SignerInformationStore signerInformationStore = signedData.getSignerInfos();
		List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();

		// Accedemos al primer firmante
		SignerInformation signerInfo = listSignersSignature.get(0);

		// Una firma PAdES-BES no tiene política de firma asociada, es
		// decir, ela tributo signature-policy-identifier no debe sesr
		// un atributo firmado.
		if (!hasSignaturePolicyIdentifier(signerInfo)) {
		    return true;
		}

	    } catch (Exception e) {
		return false;
	    }
	}
	return false;
    }

    /**
     * Method that indicates whether a signature dictionary has PAdES-Basic signature format (true) or not (false).
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @return a boolean that indicates whether a signature dictionary has PAdES-Basic signature format (true) or not (false).
     */
    public static boolean isPAdESBasic(PDFSignatureDictionary signatureDictionary) {
	// Según ETSI TS 102 778-2 una firma PAdES básica debe haber sido
	// codificada en PKCS#7
	// y la clave /SubFilter sólo puede tener 2 valores:
	// 'adbe.pkcs7.detached' o 'adbe.pkcs7.sha1'
	PdfName subFilterValue = (PdfName) signatureDictionary.getDictionary().get(PdfName.SUBFILTER);
	if (subFilterValue.equals(PdfName.ADBE_PKCS7_DETACHED) || subFilterValue.equals(PdfName.ADBE_PKCS7_SHA1)) {
	    // obtenemos la firma electrónica que se encuentra dentro de la
	    // clave /Contents del diccionario de firmas
	    byte[ ] signatureBytes = signatureDictionary.getDictionary().getAsString(PdfName.CONTENTS).getOriginalBytes();

	    if (isASN1Format(signatureBytes)) {
		String signatureFormat = resolveASN1Format(signatureBytes);
		return signatureFormat.equals(FORMAT_CMS) || signatureFormat.equals(FORMAT_CMS_T) || signatureFormat.equals(FORMAT_CADES_BES);
	    }

	}
	return false;
    }

    /**
     * Method that indicates whether a signature dictionary has PDF signature format (true) or not (false).
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @return a boolean that indicates whether a signature dictionary has PDF signature format (true) or not (false).
     */
    public static boolean isPDF(PDFSignatureDictionary signatureDictionary) {
	// Consideramos formato PDF si la clave /SubFilter del diccionario de
	// firma no posee algún valor válido para PAdES-BES, PAdES-EPES
	// o PAdES-Basic
	PdfName subFilterValue = (PdfName) signatureDictionary.getDictionary().get(PdfName.SUBFILTER);
	if (!subFilterValue.equals(PdfName.ADBE_PKCS7_DETACHED) && !subFilterValue.equals(PdfName.ADBE_PKCS7_SHA1) && !subFilterValue.equals(UtilsSignatureOp.CADES_SUBFILTER_VALUE)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that indicates whether a PDF document has PAdES-LTV signature format (true) or not (false).
     * @param reader Parameter that allows to access to all of the elements of the PDF document.
     * @return a boolean that indicates whether a PDF document has PAdES-LTV signature format (true) or not (false).
     */
    private static boolean isPAdESLTV(PdfReader reader) {
	// Un documento PDF tendrá el formato de firma PAdES-LTV si posee un
	// diccionario DSS y/o posee al menos un diccionario de firma de tipo
	// Document Time-stamp.
	if (reader.getCatalog().get(UtilsSignatureOp.DSS_DICTIONARY_NAME) != null) {
	    return true;
	} else {
	    return countDocumentTimeStampDictionaries(reader) > 0;
	}
    }

    /**
     * Method that obtains the concrete format of an ASN.1 signature which has, al least, CAdES-T form.
     * @param listSignersSignature Parameter that represents the list of signers of the signature.
     * @param temporalFormat last value of format checked.
     * @return the format of the signature. The format will have one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
     * </ul>
     */
    private static String resolveFormatOfCAdESTSignature(List<SignerInformation> listSignersSignature, String temporalFormat) {
	// Establecemos el formato a devolver como CAdES-T
	String format = temporalFormat;

	// Comprobamos si la firma cumple con el formato CAdES-C
	if (isCAdESC(listSignersSignature)) {
	    // Establecemos el formato a devolver como CAdES-C
	    format = FORMAT_CADES_C;

	    // Comprobamos si la firma es CAdES-XL1
	    if (isCAdESXL1(listSignersSignature)) {
		// Establecemos el formato a devolver como CAdES-XL1
		format = FORMAT_CADES_XL1;
		// Comprobamos si la firma es CAdES-A
		if (isCAdESA(listSignersSignature)) {
		    // Establecemos el formato a devolver como CAdES-A
		    format = FORMAT_CADES_A;
		}
	    }
	    // Comprobamos si la firma es CAdES-XL2
	    else if (isCAdESXL2(listSignersSignature)) {
		// Establecemos el formato a devolver como CAdES-XL2
		format = FORMAT_CADES_XL2;
		// Comprobamos si la firma es CAdES-A
		if (isCAdESA(listSignersSignature)) {
		    // Establecemos el formato a devolver como CAdES-A
		    format = FORMAT_CADES_A;
		}
	    }
	    // Comprobamos si la firma es CAdES-X1
	    else if (isCAdESX1(listSignersSignature)) {
		// Establecemos el formato a devolver como CAdES-X1
		format = FORMAT_CADES_X1;
	    }
	    // Comprobamos si la firma es CAdES-X2
	    else if (isCAdESX2(listSignersSignature)) {
		// Establecemos el formato a devolver como CAdES-X2
		format = FORMAT_CADES_X2;
	    }
	}
	return format;
    }

    /**
     * Method that obtains the format of a CAdES signature without Baseline form.
     * @param temporalFormat Parameter that represents the current format of the CAdES signature. It must have one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}.</li>
     * </ul>
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return the format of the CAdES signature without Baseline form. The format will have one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}.</li>
     * </ul>
     */
    private static String resolveCAdESNoBaselineFormat(String temporalFormat, List<SignerInformation> listSignersSignature) {
	// Primero establecemos el formato a devolver como el formato temporal
	// que posee la firma
	String format = temporalFormat;

	// Si la firma no es CAdES-T comprobamos si pudiera serlo
	if (!format.equals(FORMAT_CADES_T_LEVEL) && isCAdEST(listSignersSignature)) {
	    format = FORMAT_CADES_T;
	}
	// Si la firma cumple con el formato CAdES-T
	// if (format.equals(FORMAT_CADES_T)) {
	format = resolveFormatOfCAdESTSignature(listSignersSignature, format);
	// }
	return format;
    }

    /**
     * Method that obtains the concrete format of an ASN.1 signature which has, al least, CAdES-EPES form.
     * @param signedData Parameter that represents the signed data.
     * @param listSignersSignature Parameter that represents the list of signers of the signature.
     * @return the format of the signature. The format will have one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}.</li>
     * </ul>
     */
    private static String resolveFormatOfCAdESEPESSignature(CMSSignedData signedData, List<SignerInformation> listSignersSignature) {
	// Establecemos el formato a CAdES-EPES
	String format = FORMAT_CADES_EPES;
	// Comprobamos si la firma es CAdES B-Level, esto es, si tiene
	// el atributo firmado signing-time
	if (isCAdESBLevel(listSignersSignature)) {
	    // Establecemos el formato a CAdES B-Level
	    format = FORMAT_CADES_B_LEVEL;
	    // Comprobamos si la firma posee signature-time-stamp en
	    // cuyo caso será CAdES T-Level
	    if (isCAdEST(listSignersSignature)) {
		// Establecemos el formato a CAdES T-Level
		format = FORMAT_CADES_T_LEVEL;
		// Comprobamos si la firma es LT-Level
		if (isCAdESLTLevel(listSignersSignature, signedData)) {
		    format = FORMAT_CADES_LT_LEVEL;
		    // Comprobamos si la firma es LTA-Level
		    if (isCAdESLTALevel(listSignersSignature)) {
			format = FORMAT_CADES_LTA_LEVEL;
		    }
		}
	    }
	}
	// Si la firma no es CAdES B-Level
	else {
	    // Comprobamos si la firma es CAdES-T, CAdES-C, CAdES-X1,
	    // CAdES-X2, CAdES-XL1, CAdES-XL2 o CAdES-A
	    format = resolveCAdESNoBaselineFormat(format, listSignersSignature);
	}
	return format;
    }

    /**
     * Method that obtains the concrete format of an ASN.1 signature.
     * @param signature Parameter that represents the ASN.1 signature.
     * @return the format of the signature. The format will have one of these values:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CMS}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CMS_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    private static String resolveASN1Format(byte[ ] signature) {
	// Inicialmente definidos que el formato no está reconocido
	String format = FORMAT_UNRECOGNIZED;
	try {
	    CMSSignedData signedData = new CMSSignedData(signature);

	    // Obtenemos la información de los firmantes
	    SignerInformationStore signerInformationStore = signedData.getSignerInfos();
	    List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();

	    // Comprobamos si la firma es CMS
	    if (isCMS(listSignersSignature)) {
		format = FORMAT_CMS;
		// Comprobamos si la firma contiene sello de tiempo, y por lo
		// tanto, si es CMS-T
		if (isCAdEST(listSignersSignature)) {
		    format = FORMAT_CMS_T;
		}
	    }
	    // Comprobamos si la firma es CAdES-EPES
	    else if (isCAdESEPES(listSignersSignature)) {
		format = resolveFormatOfCAdESEPESSignature(signedData, listSignersSignature);
	    }
	    // Comprobamos si la firma es CAdES-BES
	    else if (isCAdESBES(listSignersSignature)) {
		// Establecemos el formato a CAdES-EPES
		format = FORMAT_CADES_BES;
		// Comprobamos si la firma es CAdES B-Level, esto es, si tiene
		// el atributo firmado signing-time
		if (isCAdESBLevel(listSignersSignature)) {
		    // Establecemos el formato a CAdES B-Level
		    format = FORMAT_CADES_B_LEVEL;
		    // Comprobamos si la firma posee signature-time-stamp en
		    // cuyo caso será CAdES T-Level
		    if (isCAdEST(listSignersSignature)) {
			// Establecemos el formato a CAdES T-Level
			format = FORMAT_CADES_T_LEVEL;
			// Comprobamos si la firma es LT-Level
			if (isCAdESLTLevel(listSignersSignature, signedData)) {
			    format = FORMAT_CADES_LT_LEVEL;
			    // Comprobamos si la firma es LTA-Level
			    if (isCAdESLTALevel(listSignersSignature)) {
				format = FORMAT_CADES_LTA_LEVEL;
			    }
			} else {
			    format = resolveCAdESNoBaselineFormat(format, listSignersSignature);
			}
		    }
		}
		// Si la firma no es CAdES B-Level
		else {
		    // Comprobamos si la firma es CAdES-T, CAdES-C, CAdES-X1,
		    // CAdES-X2, CAdES-XL1, CAdES-XL2 o CAdES-A
		    format = resolveCAdESNoBaselineFormat(format, listSignersSignature);
		}
	    }
	} catch (Exception e) {
	    format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	}
	return format;
    }

    /**
     * Method that checks whether a signer has CAdES-A format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-A format.
     */
    private static boolean isCAdESA(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();
	// Se considera una firma con formato CAdES-A si al menos uno de
	// sus firmantes posee el atributo no firmado
	// id-aa-ets-archiveTimeStamp o id-aa-ets-archiveTimestampV2
	if (unsignedAttrs != null && (unsignedAttrs.get(ESFAttributes.archiveTimestamp) != null || unsignedAttrs.get(ESFAttributes.archiveTimestampV2) != null)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-A format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-A format.
     */
    private static boolean isCAdESA(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		if (isCAdESA(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-A
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESA((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}

    }

    /**
     * Method that checks whether a set of unsigned attributes are valid for a CAdES-XL signature.
     * @param unsignedAttrs Parameter that represents the set of unsigned attributes.
     * @return a boolean that indicates wheter the unsigned attributes, certValues and revocationValues attributes are not null (true) or yes (false).
     */
    private static boolean areCAdESXLUnsignedAttributes(AttributeTable unsignedAttrs) {
	// Se considera una firma con formato CAdES-XL1 si posee los
	// atributos no firmados
	// id-aa-ets-certValues y id-aa-ets-revocationValues
	if (unsignedAttrs != null && unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_certValues) != null && unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether a signer has CAdES-XL1 format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-XL1 format.
     */
    private static boolean isCAdESXL1(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();
	// Se considera una firma con formato CAdES-XL1 si posee los
	// atributos no firmados
	// id-aa-ets-certValues, id-aa-ets-revocationValues e
	// id-aa-ets-escTimeStamp
	if (areCAdESXLUnsignedAttributes(unsignedAttrs) && unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-XL1 format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-XL1 format.
     */
    private static boolean isCAdESXL1(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		// Accedemos al conjunto de atributos no firmados
		AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();
		// Se considera una firma con formato CAdES-XL1 si posee los
		// atributos no firmados
		// id-aa-ets-certValues, id-aa-ets-revocationValues e
		// id-aa-ets-escTimeStamp
		if (areCAdESXLUnsignedAttributes(unsignedAttrs) && unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp) != null) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-XL1
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESXL1((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}

    }

    /**
     * Method that checks whether a signer has CAdES-XL2 format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-XL2 format.
     */
    private static boolean isCAdESXL2(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();
	// Se considera una firma con formato CAdES-XL2 si posee los
	// atributos no firmados
	// id-aa-ets-certValues, id-aa-ets-revocationValues e
	// id-aa-ets-certCRLTimestamp
	if (areCAdESXLUnsignedAttributes(unsignedAttrs) && unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-XL2 format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-XL2 format.
     */
    private static boolean isCAdESXL2(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		if (isCAdESXL2(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-XL2
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESXL2((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks whether a signer has CAdES-X1 format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-X1 format.
     */
    private static boolean isCAdESX1(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();
	// Se considera una firma con formato CAdES-X1 si posee el
	// atributo no firmado
	// id-aa-ets-escTimeStamp
	if (unsignedAttrs != null && unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-X1 format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-X1 format.
     */
    private static boolean isCAdESX1(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		if (isCAdESX1(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-X1
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESX1((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks whether a signer has CAdES-X2 format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-X2 format.
     */
    private static boolean isCAdESX2(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();
	// Se considera una firma con formato CAdES-X2 si posee el
	// atributo no firmado
	// id-aa-ets-certCRLTimestamp
	if (unsignedAttrs != null && unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-X2 format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-X2 format.
     */
    private static boolean isCAdESX2(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		if (isCAdESX2(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-X2
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESX2((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks whether a signer has CAdES-C format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-C format.
     */
    private static boolean isCAdESC(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();
	// Se considera una firma con formato CAdES-C si posee los
	// atributos no firmados
	// id-aa-ets-CertificateRefs y aa-ets-revocationRefs
	if (unsignedAttrs != null && (unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs) != null || unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs) != null)) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-C format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-C format.
     */
    private static boolean isCAdESC(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		if (isCAdESC(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-C
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESC((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks whether a signer has CAdES-T format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-T format.
     */
    private static boolean isCAdEST(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();
	// Se considera una firma con formato CAdES-T si posee el
	// atributo no firmado
	// id-aa-timeStampToken
	if (unsignedAttrs != null && unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-T format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-T format.
     */
    private static boolean isCAdEST(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		if (isCAdEST(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-T
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdEST((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks whether an ASN.1 signature has <code>SignaturePolicyIdentifier</code> element.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the ASN.1 signature has <code>SignaturePolicyIdentifier</code> element (true) or not (false).
     */
    public static boolean hasSignaturePolicyIdentifier(SignerInformation signerInformation) {
	AttributeTable signedAttrs = signerInformation.getSignedAttributes();
	if (signedAttrs != null && signedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether a signer has CAdES-EPES format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-EPES format.
     */
    private static boolean isCAdESEPES(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos firmados
	AttributeTable signedAttrs = signerInformation.getSignedAttributes();
	// Se considera una firma con formato CAdES-EPES si posee el
	// atributo firmado
	// id-aa-sigPolicyId
	if (signedAttrs != null && signedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-EPES format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-EPES format.
     */
    private static boolean isCAdESEPES(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		// Comprobamos si el firmante tiene formato CAdES-EPES
		if (isCAdESEPES(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-EPES
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESEPES((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks whether a signer has CAdES-BES format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CAdES-BES format.
     */
    private static boolean isCAdESBES(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos firmados
	AttributeTable signedAttrs = signerInformation.getSignedAttributes();
	// Se considera una firma con formato CAdES-BES si posee los
	// atributos firmados
	// id_aa_signingCertificate, o id_aa_signingCertificateV2, o
	// id_aa_ets_otherSigCert
	return signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificate) != null || signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) != null || signedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_otherSigCert) != null;
    }

    /**
     * Method that checks whether a signer has CMS format.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates whether the signer has CMS format.
     */
    private static boolean isCMS(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos firmados
	AttributeTable signedAttrs = signerInformation.getSignedAttributes();
	// Se considera una firma con formato CMS si no posee ningún
	// atributo firmado
	// id_aa_signingCertificate, id_aa_signingCertificateV2, ni
	// id_aa_ets_otherSigCert
	return signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificate) == null && signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) == null && signedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_otherSigCert) == null;
    }

    /**
     * Method that checks whether an ASN.1 signature has CMS format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CMS format.
     */
    private static boolean isCMS(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		// Se considera una firma con formato CMS si no posee ningún
		// atributo firmado
		// id_aa_signingCertificate, id_aa_signingCertificateV2, ni
		// id_aa_ets_otherSigCert
		if (isCMS(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CMS
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCMS((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks whether an ASN.1 signature has CAdES-BES format.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates whether an ASN.1 signature has CAdES-BES format.
     */
    private static boolean isCAdESBES(List<SignerInformation> listSignersSignature) {
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		// Se considera una firma con formato CAdES-BES si posee los
		// atributos firmados
		// id_aa_signingCertificate, o id_aa_signingCertificateV2, o
		// id_aa_ets_otherSigCert
		if (isCAdESBES(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES-BES
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESBES((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}
	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks if a signer contains the <code>signing-time</code> attribute.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates if the signer contains the <code>signing-time</code> attribute (true) or not (false).
     */
    private static boolean isCAdESBLevel(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos firmados
	AttributeTable signedAttrs = signerInformation.getSignedAttributes();

	// Comprobamos si tiene el atributo signing-time
	if (signedAttrs.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks if the signature has <code>signing-time</code> attribute.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates if the signature has <code>signing-time</code> attribute (true) or not (false).
     */
    private static boolean isCAdESBLevel(List<SignerInformation> listSignersSignature) {
	// Si la firma posee firmantes
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		// Accedemos al conjunto de atributos firmados
		AttributeTable signedAttrs = signerInformation.getSignedAttributes();

		// Comprobamos si tiene el atributo signing-time
		if (signedAttrs.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES B-Level
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESBLevel((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}

	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that checks if a signer has CAdES LT-Level format, it contains at least one revocation value into the signed data, and it doesn't contain any of the following unsigned
     * attributes:
     * <ul>
     * <li>complete-certificate-references.</li>
     * <li>complete-revocation-references.</li>
     * <li>attribute-certificate-references.</li>
     * <li>attribute-revocation-references.</li>
     * <li>CAdES-C-time-stamp.</li>
     * <li>time-stamped-certs-crls-references.</li>
     * <li>certificate-values.</li>
     * <li>revocation-values.</li>
     * <li>archive-time-stamp.</li>
     * <li>archive-time-stampv2.</li>
     * <li>long-term-validation.</li>
     * </ul>
     * @param signerInformation Parameter that represents the information about the signer.
     * @param cmsSignedData Parameter that represents the signed data.
     * @return a boolean that indicates if the signer has CAdES LT-Level (true) or not (false).
     */
    private static boolean isCAdESLTLevel(SignerInformation signerInformation, CMSSignedData cmsSignedData) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();

	/*
	 * Comprobamos que la firma no contenga ninguno de los atributos no firmados:
	 * > complete-certificate-references
	 * > complete-revocation-references
	 * > attribute-certificate-references
	 * > attribute-revocation-references
	 * > CAdES-C-time-stamp
	 * > time-stamped-certs-crls-references
	 * > certificate-values
	 * > revocation-values
	 * > archive-time-stamp
	 * > archive-time-stampv2
	 * > long-term-validation
	 *
	 * y que contenga al menos un elemento de revocación dentro de SignedData.crl
	 */
	SignedData signedData = SignedData.getInstance(cmsSignedData.getContentInfo().getContent());
	if (checkUnsignedAttributesForCAdESLTLevel(unsignedAttrs) && signedData.getCRLs() != null && signedData.getCRLs().size() > 0) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks if the signature has LT-Level format, it contains at least one revocation value into the signed data, and it doesn't contain any of the following unsigned attributes:
     * <ul>
     * <li>complete-certificate-references.</li>
     * <li>complete-revocation-references.</li>
     * <li>attribute-certificate-references.</li>
     * <li>attribute-revocation-references.</li>
     * <li>CAdES-C-time-stamp.</li>
     * <li>time-stamped-certs-crls-references.</li>
     * <li>certificate-values.</li>
     * <li>revocation-values.</li>
     * <li>archive-time-stamp.</li>
     * <li>archive-time-stampv2.</li>
     * <li>long-term-validation.</li>
     * </ul>
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @param signedData Parameter that represents the signed data.
     * @return a boolean that indicates if the signature has LT-Level (true) or not (false).
     */
    private static boolean isCAdESLTLevel(List<SignerInformation> listSignersSignature, CMSSignedData signedData) {
	// Recorremos la lista de firmantes
	for (SignerInformation signerInformation: listSignersSignature) {
	    if (isCAdESLTLevel(signerInformation, signedData)) {
		return true;
	    }

	    // Si el firmante posee contrafirmas comprobamos si alguna de
	    // ellas es CAdES LT-Level
	    SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
	    if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESLTLevel((List<SignerInformation>) counterSignatures.getSigners(), signedData)) {
		return true;
	    }
	}
	return false;
    }

    /**
     * Method that checks if a signature doesn't contain any of the next unsigned attributes:
     * <ul>
     * <li>complete-certificate-references.</li>
     * <li>complete-revocation-references.</li>
     * <li>attribute-certificate-references.</li>
     * <li>attribute-revocation-references.</li>
     * <li>CAdES-C-time-stamp.</li>
     * <li>time-stamped-certs-crls-references.</li>
     * <li>certificate-values.</li>
     * <li>revocation-values.</li>
     * <li>archive-time-stamp.</li>
     * <li>archive-time-stampv2.</li>
     * <li>long-term-validation.</li>
     * </ul>
     * @param unsignedAttrs Parameter that represents the unsigned attributes of the signature.
     * @return a boolean that indicates if the signature contains at least one of the attributes (false) or none (true).
     */
    private static boolean checkUnsignedAttributesForCAdESLTLevel(AttributeTable unsignedAttrs) {
	if (unsignedAttrs != null) {
	    // complete-certificate-references
	    if (unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs) != null) {
		return false;
	    }

	    // complete-revocation-references
	    if (unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs) != null) {
		return false;
	    }

	    // attribute-certificate-references
	    if (unsignedAttrs.get(ID_ATTRIBUTE_CERTIFICATE_REFERENCES) != null) {
		return false;
	    }

	    // attribute-revocation-references
	    if (unsignedAttrs.get(ID_ATTRIBUTE_REVOCATION_REFERENCES) != null) {
		return false;
	    }

	    // CAdES-C-time-stamp
	    if (unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp) != null) {
		return false;
	    }

	    // time-stamped-certs-crls-references
	    if (unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp) != null) {
		return false;
	    }

	    // certificate-values
	    if (unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_certValues) != null) {
		return false;
	    }

	    return checkUnsignedAttributesForCAdESLTLevelAux(unsignedAttrs);
	}
	return true;
    }

    /**
     * Method that checks if a signature doesn't contain any of the next unsigned attributes:
     * <ul>
     * <li>revocation-values.</li>
     * <li>archive-time-stamp.</li>
     * <li>archive-time-stampv2.</li>
     * <li>long-term-validation.</li>
     * </ul>
     * @param unsignedAttrs Parameter that represents the unsigned attributes of the signature.
     * @return a boolean that indicates if the signature contains at least one of the attributes (false) or none (true).
     */
    private static boolean checkUnsignedAttributesForCAdESLTLevelAux(AttributeTable unsignedAttrs) {
	// revocation-values
	if (unsignedAttrs.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null) {
	    return false;
	}

	// archive-time-stamp
	if (unsignedAttrs.get(ESFAttributes.archiveTimestamp) != null) {
	    return false;
	}

	// archive-time-stamp-v2
	if (unsignedAttrs.get(ESFAttributes.archiveTimestampV2) != null) {
	    return false;
	}

	// long-term-validation
	if (unsignedAttrs.get(ID_LONG_TERM_VALIDATION) != null) {
	    return false;
	}
	return true;
    }

    /**
     * Method that checks if a signer contains the <code>archive-time-stamp-v3</code> attribute.
     * @param signerInformation Parameter that represents the information about the signer.
     * @return a boolean that indicates if the signer contains the <code>archive-time-stamp-v3</code> attribute (true) or not (false).
     */
    private static boolean isCAdESLTALevel(SignerInformation signerInformation) {
	// Accedemos al conjunto de atributos no firmados
	AttributeTable unsignedAttrs = signerInformation.getUnsignedAttributes();

	// Comprobamos si tiene el atributo archive-time-stamp-v3
	if (unsignedAttrs != null && unsignedAttrs.get(ID_ARCHIVE_TIME_STAMP_V3) != null) {
	    return true;
	}
	return false;
    }

    /**
     * Method that checks if the signature has <code>archive-time-stamp-v3</code> attribute.
     * @param listSignersSignature Parameter that represents the signers list of the signature.
     * @return a boolean that indicates if the signature has <code>archive-time-stamp-v3</code> attribute (true) or not (false).
     */
    private static boolean isCAdESLTALevel(List<SignerInformation> listSignersSignature) {
	// Si la firma posee firmantes
	if (listSignersSignature != null && listSignersSignature.size() > 0) {
	    // Recorremos la lista de firmantes
	    for (SignerInformation signerInformation: listSignersSignature) {
		if (isCAdESLTALevel(signerInformation)) {
		    return true;
		}
		// Si el firmante posee contrafirmas comprobamos si alguna de
		// ellas es CAdES LTA-Level
		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() > 0 && isCAdESLTALevel((List<SignerInformation>) counterSignatures.getSigners())) {
		    return true;
		}

	    }
	    return false;
	} else {
	    return false;
	}
    }

    /**
     * Method that obtains the format associated to a signer of an ASN.1 signature when the signer has, at least, CAdES-C form.
     * @param signerInformation Parameter that represents the information abput the signer to process.
     * @return the signature format. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
     * </ul>
     */
    private static String resolverSignerCAdESCUpperFormat(SignerInformation signerInformation) {
	// Indicamos que el formato es, al menos, CAdES-C
	String format = FORMAT_CADES_C;

	// Comprobamos si el firmante cumple con el formato
	// CAdES-X1
	if (isCAdESX1(signerInformation)) {
	    // Indicamos que el formato es, al menos,
	    // CAdES-X1
	    format = FORMAT_CADES_X1;

	    // Comprobamos si el firmante cumple con el
	    // formato CAdES-XL
	    if (isCAdESXL1(signerInformation)) {
		// Indicamos que el formato es, al menos,
		// CAdES-XL1
		format = FORMAT_CADES_XL1;

		// Comprobamos si el firmante cumple con el
		// formato CAdES-A
		if (isCAdESA(signerInformation)) {
		    // Indicamos que el formato es, al
		    // menos, CAdES-A
		    format = FORMAT_CADES_A;
		}
	    }
	}
	// Comprobamos si el firmante cumple con el formato
	// CAdES-X2
	else if (isCAdESX2(signerInformation)) {
	    // Indicamos que el formato es, al menos,
	    // CAdES-X2
	    format = FORMAT_CADES_X2;

	    // Comprobamos si el firmante cumple con el
	    // formato CAdES-XL
	    if (isCAdESXL2(signerInformation)) {
		// Indicamos que el formato es, al menos,
		// CAdES-XL2
		format = FORMAT_CADES_XL2;

		// Comprobamos si el firmante cumple con el
		// formato CAdES-A
		if (isCAdESA(signerInformation)) {
		    // Indicamos que el formato es, al
		    // menos, CAdES-A
		    format = FORMAT_CADES_A;
		}
	    }
	}
	return format;
    }

    /**
     * Method that obtains the format associated to a signer of an ASN.1 signature when the signer has, at least, CAdES B-Level form.
     * @param signedData Parameter that represents the signature message.
     * @param signerInformation Parameter that represents the information abput the signer to process.
     * @return the signature format. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
     * </ul>
     */
    private static String resolverSignerCAdESBLevelUpperFormat(CMSSignedData signedData, SignerInformation signerInformation) {
	// Indicamos que el formato es, al menos, CAdES B-Level
	String format = FORMAT_CADES_B_LEVEL;

	// Comprobamos si el firmante cumple con el formato CAdES
	// T-Level
	if (isCAdEST(signerInformation)) {
	    // Indicamos que el formato es, al menos, CAdES T-Level
	    format = FORMAT_CADES_T_LEVEL;

	    // Comprobamos si el firmante cumple con el formato
	    // CAdES LT-Level
	    if (isCAdESLTLevel(signerInformation, signedData)) {
		// Indicamos que el formato es, al menos, CAdES
		// LT-Level
		format = FORMAT_CADES_LT_LEVEL;

		// Comprobamos si el firmante cumple con el formato
		// CAdES LTA-Level
		if (isCAdESLTALevel(signerInformation)) {
		    // Indicamos que el formato es, al menos, CAdES
		    // LTA-Level
		    format = FORMAT_CADES_LTA_LEVEL;
		}
	    }
	    // Comprobamos si el firmante cumple con el formato
	    // CAdES-C
	    else if (isCAdESC(signerInformation)) {
		// Comprobamos el formato del firmante a partir del
		// nivel -C
		format = resolverSignerCAdESCUpperFormat(signerInformation);
	    }
	}
	return format;
    }

    /**
     * Method that obtains the format associated to a signer of an ASN.1 signature.
     * @param signedData Parameter that represents the signature message.
     * @param signerInformation Parameter that represents the information abput the signer to process.
     * @return the signature format. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_A}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_XL1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X2}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_X1}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_T}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_C}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_CADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    public static String resolveSignerCAdESFormat(CMSSignedData signedData, SignerInformation signerInformation) {
	// Inicialmente definimos que el formato no está reconocido
	String format = FORMAT_UNRECOGNIZED;

	// Si se ha indicado firmante
	if (signerInformation != null) {
	    // Comprobamos si el firmante cumple con el formato CAdES-EPES
	    if (isCAdESEPES(signerInformation)) {
		// Indicamos que el formato es, al menos, CAdES-EPES
		format = FORMAT_CADES_EPES;

		// Comprobamos si el firmante cumple con el formato CAdES
		// B-Level
		if (isCAdESBLevel(signerInformation)) {
		    format = resolverSignerCAdESBLevelUpperFormat(signedData, signerInformation);
		}
		// Comprobamos si el firmante cumple con el formato CAdES-T
		else if (isCAdEST(signerInformation)) {
		    // Indicamos que el formato es, al menos, CAdES-T
		    format = FORMAT_CADES_T;

		    // Comprobamos si el firmante cumple con el formato
		    // CAdES-C
		    if (isCAdESC(signerInformation)) {
			// Comprobamos el formato del firmante a partir del
			// nivel -C
			format = resolverSignerCAdESCUpperFormat(signerInformation);
		    }
		}
	    }
	    // Comprobamos si el firmante cumple con el formato CAdES-BES
	    if (isCAdESBES(signerInformation)) {
		// Indicamos que el formato es, al menos, CAdES-EPES
		format = FORMAT_CADES_BES;

		// Comprobamos si el firmante cumple con el formato CAdES
		// B-Level
		if (isCAdESBLevel(signerInformation)) {
		    format = resolverSignerCAdESBLevelUpperFormat(signedData, signerInformation);
		}
		// Comprobamos si el firmante cumple con el formato CAdES-T
		else if (isCAdEST(signerInformation)) {
		    // Indicamos que el formato es, al menos, CAdES-T
		    format = FORMAT_CADES_T;

		    // Comprobamos si el firmante cumple con el formato
		    // CAdES-C
		    if (isCAdESC(signerInformation)) {
			// Comprobamos el formato del firmante a partir del
			// nivel -C
			format = resolverSignerCAdESCUpperFormat(signerInformation);
		    }
		}
	    }
	}
	return format;
    }

    /**
     * Method that obtains the format associated to a signature dictionary of a PDF document.
     * @param signatureDictionary Parameter that represents the information about the signature dictionary.
     * @return the signature format. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PDF}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BASIC}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_BES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_PADES_EPES}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    public static String resolveSignatureDictionaryFormat(PDFSignatureDictionary signatureDictionary) {
	// Por defecto establecemos el formato como no reconocido
	String format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	// Comprobamos si el diccionario de firma cumple con el formato PAdES
	// B-Level
	if (isPAdESBLevel(signatureDictionary)) {
	    format = FORMAT_PADES_B_LEVEL;
	    // Comprobamos si la firma contenida en el diccionario de firma
	    // incluye al menos un sello de tiempo en un atributo
	    // signature-time-stamp
	    if (containsSignatureTimeStamp(signatureDictionary)) {
		format = FORMAT_PADES_T_LEVEL;
	    }
	}
	// Si el diccionario de firma no cumple con el formato PAdES B-Level
	else {
	    // Comprobamos si el diccionario de firma cumple con el formato
	    // PAdES-EPES
	    if (isPAdESEPES(signatureDictionary)) {
		format = FORMAT_PADES_EPES;
	    }
	    // Comprobamos si el diccionario de firma cumple con el formato
	    // PAdES-BES
	    else if (isPAdESBES(signatureDictionary)) {
		format = FORMAT_PADES_BES;
	    }
	    // Comprobamos si el diccionario de firma cumple con el formato
	    // PAdES-Basic
	    else if (isPAdESBasic(signatureDictionary)) {
		format = FORMAT_PADES_BASIC;
	    }
	    // Comprobamos si el diccionario de firma cumple con el formato PDF
	    else if (isPDF(signatureDictionary)) {
		format = FORMAT_PDF;
	    }
	}

	// Devolvemos el formato determinado
	return format;
    }

    /**
     * Method that indicates if the CAdES signature contained inside of a signature dictionary contains at least one <code>signature-time-stamp</code> attribute.
     * @param signatureDictionary Parameter that represents the signature dictionary.
     * @return a boolean that indicates if the CAdES signature contained inside of a signature dictionary contains at least one <code>signature-time-stamp</code> attribute.
     */
    private static boolean containsSignatureTimeStamp(PDFSignatureDictionary signatureDictionary) {
	try {
	    // Obtenemos los datos firmados
	    CMSSignedData signedData = UtilsSignatureOp.getCMSSignature(signatureDictionary);
	    if (!signedData.getCertificates().getMatches(null).isEmpty()) {
		// Obtenemos la lista con todos los firmantes contenidos en la
		// firma
		SignerInformationStore signerInformationStore = signedData.getSignerInfos();
		List<SignerInformation> listSignersSignature = (List<SignerInformation>) signerInformationStore.getSigners();

		// Accedemos al primer firmante
		SignerInformation signerInfo = listSignersSignature.get(0);

		// Obtenemos el número de atributos signature-time-stamp
		if (signerInfo.getUnsignedAttributes() != null && signerInfo.getUnsignedAttributes().getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
		    return true;
		}
	    }
	    return false;
	} catch (Exception e) {
	    return false;
	}
    }
}
