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
 * <b>File:</b><p>es.gob.afirma.utils.Base64Coder.java.</p>
 * <b>Description:</b><p>Utility class for coding and decoding binary data on Base 64 format.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/02/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 23/02/2011.
 */
package es.gob.afirma.utils;

import java.util.regex.Pattern;

import org.opensaml.xml.util.Base64;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.transformers.TransformersException;

/**
 * <p>Utility class for coding and decoding binary data on Base 64 format.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/03/2011.
 */
public final class Base64CoderCommons {

    /**
     * Constructor method for the class Base64Coder.java.
     */
    private Base64CoderCommons() {
    }

    /**
     * Method that encodes data on Base64.
     * @param data Parameter that represents the data to encode.
     * @return the data encoded on Base64.
     * @throws TransformersException If the method fails.
     */
    public static byte[ ] encodeBase64(byte[ ] data) throws TransformersException {
	if (data == null) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.BC_LOG001));
	}
	try {
	    byte[ ] result = Base64.encodeBytes(data).getBytes();
	    return result == null ? data : result;
	} catch (Exception e) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.BC_LOG002), e);
	}
    }

    /**
     * Method that encodes data on Base64.
     * @param data Parameter that represents the data to encode.
     * @param offset Parameter that represents the initial position where to start the encoding.
     * @param len Parameter that represents the final position where to finish the encoding.
     * @return the data encoded on Base64.
     * @throws TransformersException If the method fails.
     */
    public static byte[ ] encodeBase64(byte[ ] data, int offset, int len) throws TransformersException {
	if (data == null) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.BC_LOG001));
	}

	try {
	    byte[ ] result = Base64.encodeBytes(data, offset, len).getBytes();
	    return result == null ? data : result;
	} catch (Exception e) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.BC_LOG002), e);
	}
    }

    /**
     * Method that decodes data encoded on Base64.
     * @param data Parameter that represents the data to decode.
     * @return the decoded data.
     * @throws TransformersException If the method fails.
     */
    public static byte[ ] decodeBase64(byte[ ] data) throws TransformersException {
	return Base64.decode(new String(data));
    }

    /**
     * 
     * Method that decodes data encoded on Base64.
     * @param data Parameter that represents the data to decode.
     * @param offset Parameter that represents the initial position where to start the decoding.
     * @param len Parameter that represents the final position where to finish the encoding.
     * @return the decoded data.
     * @throws TransformersException If the method fails.
     */
    public static byte[ ] decodeBase64(byte[ ] data, int offset, int len) throws TransformersException {
	byte result[ ] = null;

	if (data == null) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.BC_LOG001));
	}
	try {
	    result = Base64.decode(data, offset, len);
	    return result == null ? data : result;
	} catch (Exception e) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.BC_LOG003), e);
	}
    }

    /**
     * Method that checks if data is encoded on Base64.
     * @param data Parameter that represents the data to check.
     * @return a boolean that defines if the data is encoded on Base64 (true) or not (false).
     */

    public static boolean isBase64Encoded(byte[ ] data) {
	String stringBase64 = new String(data);
	String regex = "([A-Za-z0-9+/]{4})*" + "([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)";

	Pattern patron = Pattern.compile(regex);

	if (!patron.matcher(stringBase64).matches()) {
	    return false;
	}
	return true;
    }

    /**
     * Method that encodes a string on Base64.
     * @param data Parameter that represents the string to encode.
     * @return the string encoded on Base64.
     * @throws TransformersException If the method fails.
     */
    public static String encodeBase64(String data) throws TransformersException {
	if (data == null) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.BC_LOG001));
	}
	try {
	    return Base64.encodeBytes(data.getBytes());
	} catch (Exception e) {
	    throw new TransformersException(e);
	}
    }

    /**
     * Method that decodes a string encoded on Base64.
     * @param data Parameter that represents the string to decode.
     * @return the decoded string.
     * @throws TransformersException If the method fails.
     */
    public static String decodeBase64(String data) throws TransformersException {
	if (data == null) {
	    throw new TransformersException(Language.getResIntegra(ILogConstantKeys.BC_LOG001));
	}
	try {
	    return new String(Base64.decode(data));
	} catch (Exception e) {
	    throw new TransformersException(e);
	}
    }

}
