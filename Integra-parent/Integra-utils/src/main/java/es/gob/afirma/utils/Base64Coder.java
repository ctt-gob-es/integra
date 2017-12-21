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

import es.gob.afirma.transformers.TransformersException;

/**
 * <p>Utility class for coding and decoding binary data on Base 64 format.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/03/2011.
 */
public final class Base64Coder {

    /**
     * Constructor method for the class Base64Coder.java.
     */
    private Base64Coder() {
    }

    /**
     * Method that encodes data on Base64.
     * @param data Parameter that represents the data to encode.
     * @return the data encoded on Base64.
     * @throws TransformersException If the method fails.
     */
    public static byte[ ] encodeBase64(byte[ ] data) throws TransformersException {
	return Base64CoderCommons.encodeBase64(data);
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
	return Base64CoderCommons.encodeBase64(data, offset, len);
    }

    /**
     * Method that decodes data encoded on Base64.
     * @param data Parameter that represents the data to decode.
     * @return the decoded data.
     * @throws TransformersException If the method fails.
     */
    public static byte[ ] decodeBase64(byte[ ] data) throws TransformersException {
	return Base64CoderCommons.decodeBase64(data);
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
	return Base64CoderCommons.decodeBase64(data, offset, len);
    }

    /**
     * Method that checks if data is encoded on Base64.
     * @param data Parameter that represents the data to check.
     * @return a boolean that defines if the data is encoded on Base64 (true) or not (false).
     */

    public static boolean isBase64Encoded(byte[ ] data) {
	return Base64CoderCommons.isBase64Encoded(data);
    }

    /**
     * Method that encodes a string on Base64.
     * @param data Parameter that represents the string to encode.
     * @return the string encoded on Base64.
     * @throws TransformersException If the method fails.
     */
    public static String encodeBase64(String data) throws TransformersException {
	return Base64CoderCommons.encodeBase64(data);
    }

    /**
     * Method that decodes a string encoded on Base64.
     * @param data Parameter that represents the string to decode.
     * @return the decoded string.
     * @throws TransformersException If the method fails.
     */
    public static String decodeBase64(String data) throws TransformersException {
	return Base64CoderCommons.decodeBase64(data);
    }

}
