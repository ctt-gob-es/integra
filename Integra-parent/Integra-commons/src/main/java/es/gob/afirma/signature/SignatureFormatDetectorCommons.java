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
 * <b>File:</b><p>es.gob.afirma.signature.SignatureFormatDetectorCommons.java.</p>
 * <b>Description:</b><p>Class that contains all the functionality related to recognize the signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 04/03/2020.
 */
package es.gob.afirma.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.signature.xades.IXMLConstants;
import es.gob.afirma.utils.NumberConstants;
import es.gob.afirma.utils.UtilsResourcesCommons;
import es.gob.afirma.utils.UtilsSignatureCommons;

/**
 * <p>Class that contains all the functionality related to recognize the signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 04/03/2020.
 */
public final class SignatureFormatDetectorCommons implements ISignatureFormatDetector {

    /**
     * Constant attribute that identifies the root for the signatures and manifests contained inside of an ASiC signature.
     */
    private static final String META_INF_FOLDER = "META-INF/";

    /**
     * Constructor method for the class SignatureFormatDetectorCommons.java.
     */
    private SignatureFormatDetectorCommons() {
    }

    /**
     * Method that indicates whether a signature is XML (true) or not (false).
     * @param signature Parameter that represents the signature to check.
     * @return a boolean that indicates whether a signature is XML (true) or not (false).
     */
    public static boolean isXMLFormat(byte[ ] signature) {
	try {
	    // Si se ha indicado la firma
	    if (signature != null) {
		Document doc = UtilsSignatureCommons.getDocumentFromXML(signature);
		NodeList nl = null;
		if (doc != null) {
		    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, IXMLConstants.ELEMENT_SIGNATURE);
		    if (nl.getLength() > 0) {
			return true;
		    } else {
			nl = doc.getElementsByTagName(IXMLConstants.ELEMENT_SIGNATURE);
			if (nl.getLength() > 0) {
			    return true;
			}
			return false;
		    }
		}
	    }
	    return false;
	} catch (Exception e) {
	    return false;
	}
    }

    /**
     * Method that indicates if a signature has the ASiC-S format (true) or not (false).
     * @param signature Parameter that represents a ZIP file.
     * @return a boolean that indicates if the signature has the ASiC-S format (true) or not (false).
     */
    public static boolean isASiCFormat(byte[ ] signature) {
	// Si se ha indicado la firma
	if (signature != null) {
	    // Obtenemos un InputStream a partir del array de bytes de entrada
	    InputStream is = null;
	    ZipInputStream asicsInputStream = null;

	    // Creamos un mapa donde incluir las entradas del fichero ZIP
	    Map<String, byte[ ]> mapEntries = new HashMap<String, byte[ ]>();

	    try {
		is = new ByteArrayInputStream(signature);
		asicsInputStream = new ZipInputStream(is);

		// Recorremos las entradas del fichero ZIP
		boolean isASiC = false;
		for (ZipEntry entry = asicsInputStream.getNextEntry(); entry != null; entry = asicsInputStream.getNextEntry()) {
		    OutputStream out = new ByteArrayOutputStream();
		    byte[ ] buffer = new byte[NumberConstants.INT_2048];
		    int data = 0;
		    String entryName = entry.getName();
		    try {
			while (0 < (data = asicsInputStream.read(buffer))) {
			    out.write(buffer, 0, data);
			}

			mapEntries.put(entryName, ((ByteArrayOutputStream) out).toByteArray());
		    } finally {
			// Cerramos recursos
			UtilsResourcesCommons.safeCloseOutputStream(out);
		    }
		    // Comprobamos si la entrada es una firma CAdES o una firma
		    // XAdES
		    if (isCAdESEntry(entryName) || isXAdESEntry(entryName)) {
			isASiC = true;
		    }
		}
		return isASiC;
	    } catch (Exception e) {
		return false;
	    } finally {
		// Cerramos recursos
		UtilsResourcesCommons.safeCloseInputStream(asicsInputStream);
		UtilsResourcesCommons.safeCloseInputStream(is);
	    }
	}  else {
	    throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.SFDC_LOG001));
	}
    }

    /**
     * Method that indicates if the name of an entry of a ZIP file has the format: <code>/META-INF/signature.xml</code>.
     * @param entryName Parameter that represents the name of the entry.
     * @return a boolean that indicates if the name of an entry of a ZIP file has the format: <code>/META-INF/signature.xml</code> (true) or not (false).
     */
    private static boolean isXAdESEntry(String entryName) {
	return entryName.endsWith(".xml") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signatures");
    }

    /**
     * Method that indicates if the name of an entry of a ZIP file has the format: <code>/META-INF/signature.p7s</code>.
     * @param entryName Parameter that represents the name of the entry.
     * @return a boolean that indicates if the name of an entry of a ZIP file has the format: <code>/META-INF/signature.p7s</code> (true) or not (false).
     */
    private static boolean isCAdESEntry(String entryName) {
	return entryName.endsWith(".p7s") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature");
    }

}
