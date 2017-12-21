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
 * <b>File:</b><p>es.gob.afirma.utils.DSSParseTransformer.UtilsFileSystem.java.</p>
 * <b>Description:</b><p>Utility class for reading and processing files.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/02/2011.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.utils;

import java.io.IOException;

/**
 * <p>Utility class for reading and processing files.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public final class UtilsFileSystem {

    /**
     * Constructor method for the class UtilsFileSystem.java.
     */
    private UtilsFileSystem() {
    }

    /**
     * Retrieves encoded Base64 file content. If file would be encoded it'll be returned without encoded.
     * @param filePathToRead absolute file path.
     * @return Base64 file content.
     */
    public static synchronized byte[ ] readFileFromFileSystemBase64Encoded(String filePathToRead) {
	return UtilsFileSystemCommons.readFileFromFileSystemBase64Encoded(filePathToRead);
    }

    /**
     * Reads a file from system by given path (absolute or relative to classpath) and encodes to Base64 format.
     * @param path file path.
     * @param isRelativePath true if path is relative to classpath and false if path is absolute.
     * @return content file encoded in base64. Returns a null value if an error happens
     */
    public static synchronized String readFileBase64Encoded(String path, boolean isRelativePath) {
	return UtilsFileSystemCommons.readFileBase64Encoded(path, isRelativePath);
    }

    /**
     * Method that obtains a String encoded on Base64 from the content of a file.
     * @param content Parameter that represents the content of a file.
     * @return the encoded Base64 String.
     */
    public static synchronized String getFileBase64Encoded(byte[ ] content) {
	return UtilsFileSystemCommons.getFileBase64Encoded(content);

    }

    /**
     * Reads a file from system by given path (absolute or relative to classpath) and encodes to Base64 format.
     * @param path file path.
     * @param isRelativePath true if path is relative to classpath and false if path is absolute.
     * @return content file encoded in base64. Returns a null value if an error happens
     */
    public static synchronized byte[ ] getArrayByteFileBase64Encoded(String path, boolean isRelativePath) {
	return UtilsFileSystemCommons.getArrayByteFileBase64Encoded(path, isRelativePath);
    }

    /**
     * Reads a file from system by given path (absolute or relative to classpath).
     * @param path file path.
     * @param isRelativePath true if path is relative to classpath and false if path is absolute.
     * @return content file. Returns a null value if an error happens
     */
    public static synchronized byte[ ] readFile(String path, boolean isRelativePath) {
	return UtilsFileSystemCommons.readFile(path, isRelativePath);
    }

    /**
     * Write data into a file. If file doesn't exist, it is created.
     * @param data information to include into file.
     * @param filename name of file to record.
     * @throws IOException if a error happens accessing to file.
     */
    public static void writeFile(byte[ ] data, String filename) throws IOException {
	UtilsFileSystemCommons.writeFile(data, filename);
    }

}
