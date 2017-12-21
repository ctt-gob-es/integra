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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsSignatureCommons.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>07/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 07/11/2014.
 */
package es.gob.afirma.utils;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.SigningException;

/**
 * <p>Class that contains methods related to the manage of signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 07/11/2014.
 */
public final class UtilsSignatureCommons implements IUtilsSignature {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsSignatureCommons.class);

	/**
	 * Constructor method for the class SignatureUtils.java.
	 */
	private UtilsSignatureCommons() {
	}

	/**
	 * Method that obtains an object as a representation of a XML document.
	 * @param xmlDocument Parameter that represents the XML document.
	 * @return an object as a representation of the XML document.
	 * @throws SigningException If the XML document has a bad format.
	 */
	public static Document getDocumentFromXML(byte[ ] xmlDocument) throws SigningException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.US_LOG076));
		try {
			// Comprobamos que se han indicado parámetros de entrada
			GenericUtilsCommons.checkInputParameterIsNotNull(xmlDocument, Language.getResIntegra(ILogConstantKeys.US_LOG037));
			try {
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				dbf.setNamespaceAware(true);
				dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);
				DocumentBuilder db = dbf.newDocumentBuilder();
				return db.parse(new java.io.ByteArrayInputStream(xmlDocument));
			} catch (Exception e) {
				String errorMsg = Language.getResIntegra(ILogConstantKeys.US_LOG036);
				LOGGER.error(errorMsg, e);
				throw new SigningException(errorMsg, e);
			}
		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.US_LOG077));
		}
	}

	/**
	 * Method that checks if the verification date parameter is into the certificate validity period.
	 * @param certificate Parameter that represents the certificate to validate.
	 * @param verificationDate Parameter that represents the validation date.
	 * @throws SigningException If the certificate is expired or not yet valid.
	 */
	public static void checkValityPeriod(X509Certificate certificate, Date verificationDate) throws SigningException {
		try {
			// Comprobamos el periodo de validez del certificado
			certificate.checkValidity(verificationDate);
		} catch (CertificateExpiredException e) {
			// Certificado caducado
			String msg = Language.getResIntegra(ILogConstantKeys.US_LOG005);
			LOGGER.error(msg, e);
			throw new SigningException(msg, e);
		} catch (CertificateNotYetValidException e) {
			String msg = Language.getResIntegra(ILogConstantKeys.US_LOG085);
			LOGGER.error(msg, e);
			throw new SigningException(msg, e);
		}
	}

}
