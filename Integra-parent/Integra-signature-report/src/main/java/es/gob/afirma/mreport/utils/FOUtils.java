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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.signaturereport.tools.FOUtils.java.</p>
 * <b>Description:</b><p>Utility class for processing XSL-FO files.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>27/08/2020</p>
 * @author Spanish Government.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.mreport.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;

import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.FopFactoryConfig;
import org.apache.fop.apps.FormattingResults;
import org.apache.fop.apps.MimeConstants;
import es.gob.afirma.mreport.logger.Logger;

import es.gob.afirma.mreport.exceptions.UtilsException;
import es.gob.afirma.mreport.i18.ILogConstantKeys;
import es.gob.afirma.mreport.i18.Language;

/** 
 * <p>Utility class for processing XSL-FO files.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public final class FOUtils {

	/**
	 * Attribute that represents the object that manages the log of the class. 
	 */
	private static final Logger LOGGER = Logger.getLogger(FOUtils.class);

	/**
	 * Constructor method for the class FOUtils.java. 
	 */
	private FOUtils() {
	}

	/**
	 * Creates a PDF file from a XSL-FO document.
	 * @param foFile	XSL-FO document.
	 * @return	PDF File.
	 * @throws UtilsException If an error occurs.
	 */
	public static byte[ ] fo2pdf(byte[ ] foFile) throws UtilsException {
		FopFactory fopFactory = FopFactory.newInstance(new File(".").toURI());
		FOUserAgent fopUserAgent = fopFactory.newFOUserAgent();		
		
		byte[ ] pdf = null;
		try (ByteArrayOutputStream out = new ByteArrayOutputStream();
				InputStream in = new ByteArrayInputStream(foFile);) {
			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, fopUserAgent, out);
			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();
			
			Source src = new StreamSource(in);
			Result res = new SAXResult(fop.getDefaultHandler());
			transformer.transform(src, res);
			pdf = out.toByteArray();
			if (pdf != null) {
				FormattingResults foResults = fop.getResults();
				LOGGER.debug(Language.getFormatResSigReport(ILogConstantKeys.UTIL_010, new Object[ ] { String.valueOf(foResults.getPageCount()) }));
			}
			return pdf;
		} catch (TransformerException e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_034);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.INVALID_FO_FILE, msg,e);
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_011);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.UNKNOWN_ERROR, msg,e);
		} 
	}
}
