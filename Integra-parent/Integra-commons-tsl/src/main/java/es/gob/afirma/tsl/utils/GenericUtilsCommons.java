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
 * <b>File:</b><p>es.gob.afirma.utils.GenericUtils.java.</p>
 * <b>Description:</b><p>Class with generic utilities.</p>
 * <b>Project:</b><p@Firma and TS@ Web Services Integration Platform.</p>
 * <b>Date:</b><p>18/03/2011.</p>
 * @author Gobierno de España.
 * @version 1.2, 17/04/2023.
 */
package es.gob.afirma.tsl.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import es.gob.afirma.tsl.i18n.ILogConstantKeys;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.logger.Logger;
import es.gob.afirma.tsl.transformers.TransformersException;



/**
 * <p>Class with generic utilities.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 17/04/2023.
 */
public final class GenericUtilsCommons {

	/**
	 * Constructor method for the class GeneralUtils.java.
	 */
	private GenericUtilsCommons() {
	}

	/**
	 * Asserts whether a value is valid (not null or not empty).
	 * @param value string to validate.
	 * @return true if string is valid and false otherwise.
	 */
	public static boolean assertStringValue(String value) {

		if (value != null && !value.isEmpty()) {
			return true;
		}
		return false;
	}

	/**
	 * Asserts whether a array is valid (not null and not empty).
	 * @param data array to validate.
	 * @return true if array is valid and false otherwise.
	 */
	public static boolean assertArrayValid(byte[ ] data) {

		if (data != null && data.length > 0) {
			return true;
		}
		return false;
	}

	/**
	 * Retrieves a value from a tree of several maps by a path given.
	 * @param path path of maps tree separated by  '/'.
	 * @param treeValues collection of maps (type: Map<String, Object>).
	 * @return value of the key requested.
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static String getValueFromMapsTree(String path, Map<String, Object> treeValues) {
		String value = null;
		if (assertStringValue(path) && treeValues != null && !treeValues.isEmpty()) {
			String[ ] keyNames = path.split(GeneralConstants.PATH_DELIMITER);
			Map<String, Object> mapTmp = treeValues;
			for (int i = 0; i < keyNames.length; i++) {
				Object mapValue = mapTmp.get(keyNames[i]);
				if (mapValue instanceof Map) {
					mapTmp = (Map) mapValue;
					continue;
				} else if (keyNames.length - 1 == i && mapValue instanceof String) {
					value = mapValue.toString();
					break;
				} else {
					break;
				}
			}

		}
		return value;
	}

	/**
	 * Reads and converts a bytes stream to byte array.
	 * @param input input stream to convert.
	 * @return byte array with data.
	 * @throws IOException If the first byte cannot be read for any reason other than the end of the file, if the input stream has been closed,
	 * or if some other I/O error occurs.
	 */
	public static byte[ ] getDataFromInputStream(InputStream input) throws IOException {
		if (input == null) {
			return new byte[0];
		}
		OutputStream out = new ByteArrayOutputStream();
		byte[ ] buffer = new byte[NumberConstants.INT_2048];
		int data = 0;

		try {
			while (0 < (data = input.read(buffer))) {
				out.write(buffer, 0, data);
			}
			return ((ByteArrayOutputStream) out).toByteArray();
		} finally {
			// Cerramos recursos
			UtilsResourcesCommons.safeCloseOutputStream(out);
		}
	}

	/**
	 * Checks if a value is null.
	 * @param values collection of values to validate.
	 * @return true if any parameter is null and false if all parameters are valid (not null).
	 */
	public static boolean checkNullValues(Object... values) {
		for (Object object: values) {
			if (object == null) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Prints the resulting  data in base64 format.
	 * @param result result bytes.
	 * @param logger logger object used for print.
	 */
	public static void printResult(byte[ ] result, Logger logger) {
		if (logger.isDebugEnabled()) {
			try {
				logger.debug(Language.getResIntegra(ILogConstantKeys.GU_LOG001));
				logger.debug(new String(Base64CoderCommons.encodeBase64(result)));
			} catch (TransformersException e) {
				logger.error(e);
			}
		}
	}

	/**
	 * Method that checks if an input parameter is <code>null</code>. If the input parameter is <code>null</code> the method will throw
	 * a {@link IllegalArgumentException}.
	 * @param inputParameter Parameter that represents the element to check.
	 * @param errorMsg Parameter that represents the error message associated to the exception if the input parameter is <code>null</code>.
	 */
	public static void checkInputParameterIsNotNull(Object inputParameter, String errorMsg) {
		if (inputParameter == null) {
			throw new IllegalArgumentException(errorMsg);
		}
	}
}
