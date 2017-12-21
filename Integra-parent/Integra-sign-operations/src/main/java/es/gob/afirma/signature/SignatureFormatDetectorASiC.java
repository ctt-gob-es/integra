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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/**
 * <b>File:</b><p>es.gob.afirma.signature.SignatureFormatDetectorASiC.java.</p>
 * <b>Description:</b><p>Class that represents a format checker for Associated Signature Containers (ASiC).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>18/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 18/01/2016.
 */
package es.gob.afirma.signature;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.NumberConstants;
import es.gob.afirma.utils.UtilsResourcesCommons;

/**
 * <p>Class that represents a format checker for Associated Signature Containers (ASiC).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/01/2016.
 */
public final class SignatureFormatDetectorASiC implements ISignatureFormatDetector {

    /**
     * Constant attribute that identifies the root for the signatures and manifests contained inside of an ASiC signature.
     */
    public static final String META_INF_FOLDER = "META-INF/";

    /**
     * Constant attribute that identifies the name of the file with the mime type contained inside of the ZIP file.
     */
    public static final String MIME_TYPE_FILE = "mimetype";

    /**
     * Constant attribute that represents the mime type of the ZIP file to identify the ASiC-S format.
     */
    public static final String ASIC_S_MIME_TYPE = "application/vnd.etsi.asic-s+zip";

    /**
     * Constant attribute that represents the name of generated CAdES Baseline signature.
     */
    public static final String NAME_SIGNATURE_CADES_B = META_INF_FOLDER + "signature.p7s";

    /**
     * Constant attribute that represents the name of generated XAdES Baseline signature.
     */
    public static final String NAME_SIGNATURE_XADES_B = META_INF_FOLDER + "signatures.xml";

    /**
     * Constructor method for the class SignatureFormatDetectorASiC.java.
     */
    private SignatureFormatDetectorASiC() {
    }

    /**
     * Method that obtains the format of an ASiC signature.
     * @param signature Parameter that represents the ASiC signature as a ZIP file.
     * @return the signature format associated to the ZIP file. The value to return will be on of these:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    public static String getSignatureFormat(byte[ ] signature) {
	// Obtenemos un InputStream a partir del array de bytes de entrada
	InputStream is = null;
	InputStream asicsInputStream = null;

	try {
	    is = new ByteArrayInputStream(signature);
	    asicsInputStream = new ZipInputStream(is);

	    /*
	     * Comprobamos si el fichero ZIP sigue el formato asociado a una firma ASiC-S, esto es:
	     * > Contiene una única firma CAdES o una única firma XAdES
	     * > Sólo existe un elemento firmado (signed data).
	     * En total, debe haber un máximo de 3 elementos y un mínimo de 2.
	     */
	    int signatures = 0;
	    int signedDatas = 0;
	    int entries = 0;
	    String format = ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	    // Recorremos las entradas del fichero ZIP
	    for (ZipEntry entry = ((ZipInputStream) asicsInputStream).getNextEntry(); entry != null; entry = ((ZipInputStream) asicsInputStream).getNextEntry()) {
		// Obtenemos el nombre de la entrada
		String entryName = entry.getName();

		// Si la entrada no hace referencia a una carpeta incrementamos
		// el
		// contador de entradas
		if (!entryName.endsWith("/")) {
		    entries++;
		}

		// Si la entrada es una firma CAdES, incrementamos el contador
		// de firmas y accedemos a su contenido
		if (isCAdESEntry(entryName)) {
		    signatures++;

		    // Obtenemos el formato de la firma ASiC-S a partir de la
		    // firma CAdES contenida
		    format = getSignatureFormatFromASN1Signature(GenericUtilsCommons.getDataFromInputStream(asicsInputStream));
		}
		// Si la entrada es una firma XAdES, incrementamos el contador
		// de firmas y accedemos a su contenido
		else if (isXAdESEntry(entryName)) {
		    signatures++;

		    // Obtenemos el formato de la firma ASiC-S a partir de la
		    // firma XAdES contenida
		    format = getSignatureFormatFromXMLSignature(GenericUtilsCommons.getDataFromInputStream(asicsInputStream));
		}
		// Si la entrada representa datos firmados incrementamos su
		// contador
		else if (entryName.indexOf('/') == -1 && !entryName.equals(MIME_TYPE_FILE)) {
		    signedDatas++;
		}
	    }
	    // Si el fichero ZIP sigue el formato de ASiC-S devolveremos el
	    // formato en base a la firma CAdES o XAdES que contiene. En caso
	    // contrario determinaremos que el formato no está reconocido
	    return getASiCSFormat(entries, signatures, signedDatas, format);
	} catch (IOException e) {
	    return ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	} finally {
	    // Cerramos recursos
	    UtilsResourcesCommons.safeCloseInputStream(asicsInputStream);
	    UtilsResourcesCommons.safeCloseInputStream(is);
	}
    }

    /**
     * Method that obtains the format associated to a ZIP file as an ASiC-S signature if the ZIP file has the structure of an ASiC-S signature and it contains a CAdES Baseline or a XAdES Baseline signature.
     * @param entries Parameter that represents the number of the entries contained inside of the ZIP file.
     * @param signatures Parameter that represents the number of signatures contained inside of the ZIP file.
     * @param signedDatas Parameter that represents the number of signed files contained inside of the ZIP file.
     * @param format Parameter that represents the format of the ASiC-S signature by the format of the contained CAdES Baseline or a XAdES Baseline signature.
     * @return the format of the ASiC-S signature. The allowed values are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    private static String getASiCSFormat(int entries, int signatures, int signedDatas, String format) {
	if (entries > 1 && entries < NumberConstants.INT_4 && signatures == 1 && signedDatas == 1) {
	    return format;
	}
	return ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
    }

    /**
     * Method that obtains the format of an ASiC-S signature from the ASN.1 signature contained inside.
     * @param asn1Signature Parameter that represent the ASN.1 signature.
     * @return the format of the ASiC-S signature. The allowed values are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    private static String getSignatureFormatFromASN1Signature(byte[ ] asn1Signature) {
	// Determinamos el formato de la supuesta firma CAdES contenida y
	// comprobamos que sea de tipo Baseline
	String cadesSignatureFormat = SignatureFormatDetectorCadesPades.getSignatureFormat(asn1Signature);
	if (cadesSignatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LTA_LEVEL)) {
	    return ISignatureFormatDetector.FORMAT_ASIC_S_LTA_LEVEL;
	} else if (cadesSignatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_LT_LEVEL)) {
	    return ISignatureFormatDetector.FORMAT_ASIC_S_LT_LEVEL;
	} else if (cadesSignatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_T_LEVEL)) {
	    return ISignatureFormatDetector.FORMAT_ASIC_S_T_LEVEL;
	} else if (cadesSignatureFormat.equals(ISignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {
	    return ISignatureFormatDetector.FORMAT_ASIC_S_B_LEVEL;
	} else {
	    return ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	}
    }

    /**
     * Method that obtains the format of an ASiC-S signature from the signed XML document contained inside.
     * @param xmlSignature Parameter that represent the signed XML document.
     * @return the format of the ASiC-S signature. The allowed values are:
     * <ul>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LTA_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_LT_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_T_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_ASIC_S_B_LEVEL}.</li>
     * <li>{@link ISignatureFormatDetector#FORMAT_UNRECOGNIZED}.</li>
     * </ul>
     */
    private static String getSignatureFormatFromXMLSignature(byte[ ] xmlSignature) {
	// Determinamos el formato del supuesto documento XML firmado y
	// comprobamos que sea de tipo Baseline
	String xadesSignatureFormat = SignatureFormatDetectorXades.getSignatureFormat(xmlSignature);
	if (xadesSignatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LTA_LEVEL)) {
	    return ISignatureFormatDetector.FORMAT_ASIC_S_LTA_LEVEL;
	} else if (xadesSignatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_LT_LEVEL)) {
	    return ISignatureFormatDetector.FORMAT_ASIC_S_LT_LEVEL;
	} else if (xadesSignatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
	    return ISignatureFormatDetector.FORMAT_ASIC_S_T_LEVEL;
	} else if (xadesSignatureFormat.equals(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
	    return ISignatureFormatDetector.FORMAT_ASIC_S_B_LEVEL;
	} else {
	    return ISignatureFormatDetector.FORMAT_UNRECOGNIZED;
	}
    }

    /**
     * Method that indicates if the name of an entry of a ZIP file has the format: <code>/META-INF/signature.xml</code>.
     * @param entryName Parameter that represents the name of the entry.
     * @return a boolean that indicates if the name of an entry of a ZIP file has the format: <code>/META-INF/signature.xml</code> (true) or not (false).
     */
    public static boolean isXAdESEntry(String entryName) {
	return entryName.endsWith(".xml") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signatures");
    }

    /**
     * Method that indicates if the name of an entry of a ZIP file has the format: <code>/META-INF/signature.p7s</code>.
     * @param entryName Parameter that represents the name of the entry.
     * @return a boolean that indicates if the name of an entry of a ZIP file has the format: <code>/META-INF/signature.p7s</code> (true) or not (false).
     */
    public static boolean isCAdESEntry(String entryName) {
	return entryName.endsWith(".p7s") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature");
    }

}
