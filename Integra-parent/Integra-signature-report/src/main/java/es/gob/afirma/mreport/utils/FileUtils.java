// Copyright (C) 2018, Gobierno de España
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
 * <b>File:</b><p>es.gob.signaturereport.tools.FileUtils.java.</p>
 * <b>Description:</b><p>Utility class for managing files.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 25/08/2020.
 */
package es.gob.afirma.mreport.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Blob;
import java.sql.SQLException;

import org.apache.log4j.Logger;
import org.apache.tika.Tika;
import org.apache.tika.mime.MimeType;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;

import es.gob.afirma.mreport.exceptions.UtilsException;
import es.gob.afirma.mreport.i18.ILogConstantKeys;
import es.gob.afirma.mreport.i18.Language;;

/** 
 * <p>Utility class for managing files.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/08/2020.
 */
public final class FileUtils {

	/**
	 * Attribute that represents the ODT media type. 
	 */
	public static final String ODT_MEDIA_TYPE = "application/vnd.oasis.opendocument.text";

	/**
	 * Attribute that represents the ODG media type. 
	 */
	public static final String ODG_MEDIA_TYPE = "application/vnd.oasis.opendocument.graphics";

	/**
	 * Attribute that represents the ODS media type. 
	 */
	public static final String ODS_MEDIA_TYPE = "application/vnd.oasis.opendocument.spreadsheet";

	/**
	 * Attribute that represents the ODP media type. 
	 */
	public static final String ODP_MEDIA_TYPE = "application/vnd.oasis.opendocument.presentation";

	/**
	 * Attribute that represents the ODC media type. 
	 */
	public static final String ODC_MEDIA_TYPE = "application/vnd.oasis.opendocument.chart";

	/**
	 * Attribute that represents the BMP media type. 
	 */
	public static final String BMP_MEDIA_TYPE = "image/x-ms-bmp";

	/**
	 * Attribute that represents the GIF media type. 
	 */
	public static final String GIF_MEDIA_TYPE = "image/gif";

	/**
	 * Attribute that represents the JPEG media type. 
	 */
	public static final String JPEG_MEDIA_TYPE = "image/jpeg";

	/**
	 * Attribute that represents the PNG media type. 
	 */
	public static final String PNG_MEDIA_TYPE = "image/png";

	/**
	 * Attribute that represents the PNG media type. 
	 */
	public static final String TIFF_MEDIA_TYPE = "image/tiff";

	/**
	 * Attribute that represents the PDF media type. 
	 */
	public static final String PDF_MEDIA_TYPE = "application/pdf";

	/**
	 * Attribute that represents the microsoft word media type. 
	 */
	public static final String MSOFFICE_DOC_MEDIA_TYPE = "application/msword";

	/**
	 * Attribute that represents the microsoft word media type (in open xml format). 
	 */
	public static final String MSOFFICE_DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

	/**
	 * Attribute that represents the microsoft powerpoint media type. 
	 */
	public static final String MSOFFICE_PPT_MEDIA_TYPE = "application/vnd.ms-powerpoint";

	/**
	 * Attribute that represents the microsoft powerpoint media type (in open xml format). 
	 */
	public static final String MSOFFICE_PPTX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.presentationml.presentation";

	/**
	 * Attribute that represents the microsoft excel media type. 
	 */
	public static final String MSOFFICE_XLS_MEDIA_TYPE = "application/vnd.ms-excel";

	/**
	 * Attribute that represents the microsoft excel media type (in open xml format). 
	 */
	public static final String MSOFFICE_XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

	/**
	 * Attribute that represents the text plain media type. 
	 */
	public static final String TXT_MEDIA_TYPE = "text/plain";

	/**
	 * Attribute that represents the RTF media type. 
	 */
	public static final String RTF_MEDIA_TYPE = "application/rtf";

	/**
	 * Attribute that represents the XML media type. 
	 */
	public static final String XML_MEDIA_TYPE = "application/xml";

	/**
	 * Attribute that represents the XSLT media type. 
	 */
	public static final String XSLT_MEDIA_TYPE = "application/xslt+xml";

	/**
	 * Attribute that represents the HTML media type. 
	 */
	public static final String HTML_MEDIA_TYPE = "text/html";

	/**
	 * Attribute that represents the facade class for accessing Tika functionality. 
	 */
	private static final Tika tika = new Tika();

	/**
	 * Attribute that represents the default buffer size. 
	 */
	private static final int DEFAULT_BUFFER_SIZE = 100000;

	/**
	 * Attribute that represents the object that manages the log of the class. 
	 */
	private static final Logger LOGGER = Logger.getLogger(FileUtils.class);

	/**
	 * Attribute that represents the four thousand number.
	 */
	private static final int MMMM = 4000;
	/**
	* Attribute that represents the extension used for the Binary Files. 
	*/
	public static final String DATA_FILE_EXTENSION = "data";

	/**
	 * Constructor method for the class FileUtils.java. 
	 */
	private FileUtils() {
		super();
	}

	/**
	 * Gets the file extension.
	 * @param file	File.
	 * @return 	File extension.
	 * @throws UtilsException	If an error occurs.
	 */
	public static String getFileExtension(byte[ ] file) throws UtilsException {
		String mediaType = getMediaType(file);
		return getFileExtension(mediaType);
	}

	/**
	 * Gets the file extension.
	 * @param mimeType MimeType.
	 * @return	File extension.
	 * @throws UtilsException	If an error occurs.
	 */
	public static String getFileExtension(String mimeType) throws UtilsException {
		try {
			MimeType mime = MimeTypes.getDefaultMimeTypes().forName(mimeType);
			if (mime != null) {
				String extension = mime.getExtension();
				return extension.substring(extension.indexOf(".") + 1);
			} else {
				return DATA_FILE_EXTENSION;
			}

		} catch (MimeTypeException e) {
			LOGGER.warn(Language.getResSigReport(ILogConstantKeys.UTIL_044) + e.getMessage());
			return DATA_FILE_EXTENSION;
		}
	}

	/**
	 * Checks if the  supplied file is a valid XML.
	 * @param file	File to check.
	 * @return		True if the file is a XML.
	 * @throws UtilsException	If an error occurs while processing the file.
	 */
	public static boolean isXML(byte[ ] file) throws UtilsException {
		String xmlStr = new String(file);
		xmlStr = xmlStr.trim();
		boolean valid = (xmlStr.charAt(0) == '<' && xmlStr.charAt(xmlStr.length() - 1) == '>');
		if (valid) {
			
			try (InputStream in = new ByteArrayInputStream(file);) {
				XMLUtils.getDocumentImpl(in);
			} catch (Exception e) {
				valid = false;
			} 
		}
		return valid;
	}

	/**
	 * Method that obtains a bytes array from a {@link Blob} object.
	 * @param fromBlob Parameter that represents the {@link Blob} object.
	 * @return a bytes array from a {@link Blob} object.
	 * @throws UtilsException If an error occurs.
	 */
	public static synchronized byte[ ] toByteArray(Blob fromBlob) throws UtilsException {
		if (fromBlob == null) {
			return new byte[ ] { };
		}
		
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();) {
			return toByteArrayImpl(fromBlob, baos);
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_033);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.UNKNOWN_ERROR, msg, e);
		}
	}

	/**
	 * Method that obtains a bytes array from a {@link Blob} object for a certain {@link ByteArrayOutputStream} object.
	 * @param fromBlob Parameter that represents the {@link Blob} object.
	 * @param baos Parameter that represents the {@link ByteArrayOutputStream} object.
	 * @return a bytes array from a {@link Blob} object.
	 * @throws SQLException If the method fails.
	 * @throws IOException If the method fails.
	 */
	private static synchronized byte[ ] toByteArrayImpl(Blob fromBlob, ByteArrayOutputStream baos) throws SQLException, IOException {
		byte[ ] buf = new byte[MMMM];
		
		try (InputStream is = fromBlob.getBinaryStream();) {
			for (;;) {
				int dataSize = is.read(buf);

				if (dataSize == -1) {
					break;
				}
				baos.write(buf, 0, dataSize);
			}
		} 
		
		return baos.toByteArray();
	}

	/**
	 * Method that returns the array of bytes of supplied file.
	 * @param templatePath	Path of file to get.
	 * @return		Array of bytes of file.
	 * @throws UtilsException	If an error occurs while the system is reading the file.
	 */
	public static byte[ ] getFile(String templatePath) throws UtilsException {
			
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); InputStream in = new FileInputStream(templatePath);) {
			
			byte[ ] buff = new byte[DEFAULT_BUFFER_SIZE];
			int r = -1;
			while ((r = in.read(buff)) > 0) {
				baos.write(buff, 0, r);
			}
			return baos.toByteArray();
		} catch (FileNotFoundException e1) {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_021, new Object[ ] { templatePath });
			LOGGER.error(msg, e1);
			throw new UtilsException(UtilsException.ACCESS_FILE_ERROR, msg, e1);
		} catch (IOException e) {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_021, new Object[ ] { templatePath });
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.ACCESS_FILE_ERROR, msg, e);
		} 
	}

	/**
	 * Detects the media type of the given document.
	 * @param document	The document stream.
	 * @return	Detected media type.
	 * @throws UtilsException 
	 */
	public static String getMediaType(byte[ ] document) throws UtilsException {
		return tika.detect(document);
	}

	/**
	 * Checks if the supplied MimeType is a supported image MimeType.
	 * @param mimeType	MimeType.
	 * @return	True if the supplied value is a supported image MimeType. Otherwise, false.
	 */
	public static boolean isImage(String mimeType) {
		return (mimeType != null) && (mimeType.equals(BMP_MEDIA_TYPE) || mimeType.equals(GIF_MEDIA_TYPE) || mimeType.equals(JPEG_MEDIA_TYPE) || mimeType.equals(PNG_MEDIA_TYPE) || mimeType.equals(TIFF_MEDIA_TYPE));
	}
	
	/**
	 * Checks if the supplied MimeType is a supported text plain file or XML file.
	 * @param mimeType	MimeType.
	 * @return	True if the supplied value is a supported text plain file or XML file. Otherwise, false.
	 */
	public static boolean isTextFile(String mimeType) {
		return (mimeType != null) && (mimeType.equals(XML_MEDIA_TYPE) || mimeType.equals(TXT_MEDIA_TYPE) || mimeType.equals(XSLT_MEDIA_TYPE) || mimeType.equals(HTML_MEDIA_TYPE));
	}
	
}
