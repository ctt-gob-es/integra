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
 * <b>File:</b><p>es.gob.afirma.utils.GenericUtils.java.</p>
 * <b>Description:</b><p>Class with generic utilities.</p>
 * <b>Project:</b><p@Firma and TS@ Web Services Integration Platform.</p>
 * <b>Date:</b><p>18/03/2011.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * <p>Class with generic utilities.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public final class GenericUtils {

    /**
     * Constructor method for the class GeneralUtils.java.
     */
    private GenericUtils() {
    }

    /**
     * Asserts whether a value is valid (not null or not empty).
     * @param value string to validate.
     * @return true if string is valid and false otherwise.
     */
    public static boolean assertStringValue(String value) {

	return GenericUtilsCommons.assertStringValue(value);
    }

    /**
     * Asserts whether a array is valid (not null and not empty).
     * @param data array to validate.
     * @return true if array is valid and false otherwise.
     */
    public static boolean assertArrayValid(byte[ ] data) {

	return GenericUtilsCommons.assertArrayValid(data);
    }

    /**
     * Retrieves a value from a tree of several maps by a path given.
     * @param path path of maps tree separated by  '/'.
     * @param treeValues collection of maps (type: Map<String, Object>).
     * @return value of the key requested.
     */
    public static String getValueFromMapsTree(String path, Map<String, Object> treeValues) {
	return GenericUtilsCommons.getValueFromMapsTree(path, treeValues);
    }

    /**
     * Reads and converts a bytes stream to byte array.
     * @param input input stream to convert.
     * @return byte array with data.
     * @throws IOException If the first byte cannot be read for any reason other than the end of the file, if the input stream has been closed,
     * or if some other I/O error occurs.
     */
    public static byte[ ] getDataFromInputStream(final InputStream input) throws IOException {
	return GenericUtilsCommons.getDataFromInputStream(input);
    }

    /**
     * Checks if a value is null.
     * @param values collection of values to validate.
     * @return true if any parameter is null and false if all parameters are valid (not null).
     */
    public static boolean checkNullValues(Object... values) {
	return GenericUtilsCommons.checkNullValues(values);
    }

    /**
     * Prints the resulting  data in base64 format.
     * @param result result bytes.
     * @param logger logger object used for print.
     */
    public static void printResult(byte[ ] result, Logger logger) {
	GenericUtilsCommons.printResult(result, logger);
    }
}
