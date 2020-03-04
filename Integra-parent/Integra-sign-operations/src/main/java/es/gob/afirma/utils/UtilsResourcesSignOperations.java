package es.gob.afirma.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.log4j.Logger;
import org.apache.tika.Tika;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.c14n.implementations.Canonicalizer11_OmitComments;
import org.apache.xml.security.c14n.implementations.Canonicalizer11_WithComments;

import es.gob.afirma.i18n.ILogConstantKeys;
//Copyright (C) 2012-13 MINHAP, Gobierno de España
//This program is licensed and may be used, modified and redistributed under the terms
//of the European Public License (EUPL), either version 1.1 or (at your
//option) any later version as soon as they are approved by the European Commission.
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
//or implied. See the License for the specific language governing permissions and
//more details.
//You should have received a copy of the EUPL1.1 license
//along with this program; if not, you may find it at
//http://joinup.ec.europa.eu/software/page/eupl/licence-eupl
/**
* <b>File:</b><p>es.gob.afirma.utils.UtilsResources.java.</p>
* <b>Description:</b><p>Class that provides functionality to control of resources from sign-operations module.</p>
* <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
* <b>Date:</b><p>13/01/2014.</p>
* @author Gobierno de España.
* @version 1.2, 04/03/2020.
*/
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;

/**
 * <p>Class that provides functionality to control the resources for sign-operations module.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 04/03/2020.
 */
public class UtilsResourcesSignOperations {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsResourcesSignOperations.class);
    
    /**
     * Constant attribute that represents the URI of <code>http://www.w3.org/2006/12/xml-c14n11</code> canonicalization algorithm.
     */
    private static final String ALGO_ID_C14N11_OMIT_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11";

    /**
     * Constant attribute that represents the URI of <code>http://www.w3.org/2006/12/xml-c14n11#WithComments</code> canonicalization algorithm.
     */
    private static final String ALGO_ID_C14N11_WITH_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11#WithComments";

    /**
     * Method that detects the media type of the given document. The type detection is based on the content of the given document stream.
     * @param data Parameter that represents the data to check.
     * @return the detected media type.
     */
    public static String getMimeType(byte[ ] data) {
	if (data != null) {
	    Tika t = new Tika();
	    InputStream is = new ByteArrayInputStream(data);
	    try {
		return t.detect(is);
	    } catch (IOException e) {
		LOGGER.error(Language.getResIntegra(ILogConstantKeys.UR_LOG002), e);
	    } finally {
		UtilsResourcesCommons.safeCloseInputStream(is);
	    }
	}
	return "text/plain";
    }
    
    /**
	 * Method that obtains the canonicalizer associated to the URI of the canonicalization method to use.
	 * @param canonicalizationMethod Parameter that represents the URI of the canonicalization algorithm to use.
	 * @return an object that represents the canonializer. The canonicalizer will be:
	 * <ul>
	 * <li>{@link Canonicalizer11_OmitComments} if the canonicalization algorithm to use is {@link CanonicalizationProperties#ALGO_ID_C14N11_OMIT_COMMENTS}.</li>
	 * <li>{@link Canonicalizer11_WithComments} if the canonicalization algorithm to use is {@link CanonicalizationProperties#ALGO_ID_C14N11_WITH_COMMENTS}.</li>
	 * <li>{@link Canonicalizer} on another case.</li>
	 * </ul>
	 * @throws InvalidCanonicalizerException If the canonicalization algorithm is unsupported.
	 */
	public static Object getCanonicalizer(String canonicalizationMethod) throws InvalidCanonicalizerException {
		// Si el algoritmo de canonicalización es
		// http://www.w3.org/2006/12/xml-c14n11, es un algoritmo no soportado
		// por la librería xmlsec 1.4.1, por lo que debemos utilizar una
		// implementación de canonicalizador
		// procedente de Sun
		if (canonicalizationMethod.equals(ALGO_ID_C14N11_OMIT_COMMENTS)) {
			return new Canonicalizer11_OmitComments();
		}
		// Si el algoritmo de canonicalización es
		// http://www.w3.org/2006/12/xml-c14n11#WithComments, es un algoritmo no
		// soportado por la librería xmlsec 1.4.1, por lo que debemos utilizar
		// una implementación de canonicalizador
		// procedente de Sun
		else if (canonicalizationMethod.equals(ALGO_ID_C14N11_WITH_COMMENTS)) {
			return new Canonicalizer11_WithComments();
		}
		// Para otro algoritmo de canonicalización
		else {
			return Canonicalizer.getInstance(canonicalizationMethod);
		}
	}
}
