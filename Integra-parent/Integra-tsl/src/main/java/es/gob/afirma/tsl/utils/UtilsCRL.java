// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsCRL.java.</p>
 * <b>Description:</b><p>Utilities class that provides functionality to manage and work with X.509 CRL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 18/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 18/04/2022.
 */
package es.gob.afirma.tsl.utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.log4j.Logger; 
import es.gob.afirma.tsl.logger.IntegraLogger;

import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;
import iaik.x509.X509CRL;
/** 
 * <p>Utilities class that provides functionality to manage and work with X.509 CRL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 18/04/2022.
 */
public final class UtilsCRL {
	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsCRL.class);

	/**
	 * Constructor method for the class UtilsCRL.java.
	 */
	private UtilsCRL() {
		super();
	}

	/**
	 * Builds a X.509 CRL from the input byte array.
	 * @param crlByteArray Byte array that represents a X.509 CRL.
	 * @return a X.509 CRL builded from the input byte array, or <code>null</code>
	 * if the input array is <code>null</code> or empty.
	 * @throws CommonUtilsException In case of some error building the X.509 CRL.
	 */
	public static X509CRL buildX509CRLfromByteArray(byte[ ] crlByteArray) throws CommonUtilsException {

		X509CRL result = null;

		// Si el array de bytes no es nulo ni vacío...
		if (crlByteArray != null && crlByteArray.length > 0) {

			// Creamos un input stream.
			ByteArrayInputStream bais = new ByteArrayInputStream(crlByteArray);
			// Intentamos parsear la CRL...
			try {
				result = buildX509CRLfromByteArray(bais);
			} finally {
				UtilsResourcesCommons.safeCloseInputStream(bais);
			}

		}

		// Devolvemos el resultado obtenido.
		return result;

	}

	/**
	 * Builds a X.509 CRL from the input stream.
	 * This method does not close the input stream.
	 * @param isCRL Input stream that represents a X.509 CRL.
	 * @return a X.509 CRL builded from the input stream, or <code>null</code>
	 * if the input stream is <code>null</code>.
	 * @throws CommonUtilsException In case of some error building the X.509 CRL.
	 */
	public static X509CRL buildX509CRLfromByteArray(InputStream isCRL) throws CommonUtilsException {

		X509CRL result = null;

		// Si el input stream no es nulo...
		if (isCRL != null) {

			// Intentamos construir el X.509 CRL...
			try {
				CertificateFactory cf = CertificateFactory.getInstance(UtilsCertificateTsl.X509_TYPE);
				result = (X509CRL) cf.generateCRL(isCRL);
			} catch (CertificateException e) {
				throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_CRL_000), e);
			} catch (CRLException e) {
				throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_CRL_001), e);
			}

		}

		// Devolvemos el resultado obtenido.
		return result;

	}




}
