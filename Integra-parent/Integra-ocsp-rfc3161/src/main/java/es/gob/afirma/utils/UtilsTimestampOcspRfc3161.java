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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsTimestampPdfBc.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 05/11/2014.
 */
package es.gob.afirma.utils;

import java.io.IOException;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.rfc3161TSAServiceInvoker.RFC3161TSAServiceInvoker;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;

/**
 * <p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 05/11/2014.
 */
public final class UtilsTimestampOcspRfc3161 {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	public static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsTimestampOcspRfc3161.class);

	/**
	 * Constructor method for the class TimestampUtils.java.
	 */
	private UtilsTimestampOcspRfc3161() {
	}

	/**
	 * Method that checks if the input parameters are not null and not empty, and throws {@link IllegalArgumentException} on that case.
	 * @param dataToStamp Parameter that represents the data to stamp.
	 * @param applicationID Parameter that represents the identifier of the client application.
	 * @param tsaCommunicationMode Parameter that represents the protocol defined to communicate with TS@. The allowed values are:
	 * <ul>
	 * <li>{@link #TSA_RFC3161_TCP_COMMUNICATION} for TCP communication.</li>
	 * <li>{@link #TSA_RFC3161_HTTPS_COMMUNICATION} for HTTPS communication.</li>
	 * <li>{@link #TSA_RFC3161_SSL_COMMUNICATION} for SSL communication.</li>
	 * </ul>
	 */
	private static void checkInputParamsGetTimestampFromRFC3161Service(byte[ ] dataToStamp, String applicationID, String tsaCommunicationMode) {
		GenericUtilsCommons.checkInputParameterIsNotNull(dataToStamp, Language.getResIntegra(ILogConstantKeys.TSU_LOG032));
		if (applicationID == null || applicationID.trim().isEmpty()) {
			String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG034);
			LOGGER.error(errorMsg);
			throw new IllegalArgumentException(errorMsg);
		}
		GenericUtilsCommons.checkInputParameterIsNotNull(tsaCommunicationMode, Language.getResIntegra(ILogConstantKeys.TSU_LOG036));
	}

	/**
	 * Method that obtains an ASN.1 timestamp from TS@ RFC 3161 service.
	 * @param dataToStamp Parameter that represents the data to stamp.
	 * @param applicationID Parameter that represents the identifier of the client application.
	 * @param tsaCommunicationMode Parameter that represents the protocol defined to communicate with TS@. The allowed values are:
	 * <ul>
	 * <li>{@link #TSA_RFC3161_TCP_COMMUNICATION} for TCP communication.</li>
	 * <li>{@link #TSA_RFC3161_HTTPS_COMMUNICATION} for HTTPS communication.</li>
	 * <li>{@link #TSA_RFC3161_SSL_COMMUNICATION} for SSL communication.</li>
	 * </ul>
	 * @return an object that represents the ASN.1 timestamp.
	 * @param idClient Parameter that represents the client application identifier.
	 * @throws SigningException If the method fails.
	 */
	public static TimeStampToken getTimestampFromRFC3161Service(byte[ ] dataToStamp, String applicationID, String tsaCommunicationMode, String idClient) throws SigningException {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG037));

		// Comprobamos que los parámetros de entrada no son nulos
		checkInputParamsGetTimestampFromRFC3161Service(dataToStamp, applicationID, tsaCommunicationMode);
		try {
			// Instanciamos la clase encargada de llevar a cabo la
			// invocación
			String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG009);
			try {
				RFC3161TSAServiceInvoker invoker = new RFC3161TSAServiceInvoker();
				String protocol = null;
				// Si el modo de comunicación es TCP
				if (tsaCommunicationMode.equals(IUtilsTimestamp.TSA_RFC3161_TCP_COMMUNICATION)) {
					LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG010));
					protocol = TSAServiceInvokerConstants.RFC3161Protocol.TCP;
				}
				// Si el modo de comunicación es HTTPS
				else if (tsaCommunicationMode.equals(IUtilsTimestamp.TSA_RFC3161_HTTPS_COMMUNICATION)) {
					LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG011));
					protocol = TSAServiceInvokerConstants.RFC3161Protocol.HTTPS;
				}
				// Si el modo de comunicación es SSL
				else if (tsaCommunicationMode.equals(IUtilsTimestamp.TSA_RFC3161_SSL_COMMUNICATION)) {
					LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG012));
					protocol = TSAServiceInvokerConstants.RFC3161Protocol.SSL;
				}
				// Si el modo de comunicación no está reconocido
				else {
					String propertiesName = IIntegraConstants.PROPERTIES_FILE;
					errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG013, new Object[ ] { tsaCommunicationMode, propertiesName });
					LOGGER.error(errorMsg);
					throw new SigningException(errorMsg);
				}
				// Invocamos al servicio
				errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG004);
				byte[ ] response = invoker.generateTimeStampToken(protocol, applicationID, dataToStamp, idClient);
				errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG008);
				TimeStampResponse tsp = new TimeStampResponse(response);
				// Comprobamos que la respuesta sea correcta
				if (tsp.getFailInfo() != null) {
					// Si se ha producido un error, accedemos al mensaje de
					// error y
					// lanzamos una excepción
					errorMsg = Language.getFormatResIntegra(ILogConstantKeys.TSU_LOG006, new Object[ ] { tsp.getStatusString() });
					LOGGER.error(errorMsg);
					throw new SigningException(errorMsg);
				}
				return tsp.getTimeStampToken();
			} catch (TSAServiceInvokerException e) {
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			} catch (TSPException e) {
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			} catch (IOException e) {
				LOGGER.error(errorMsg);
				throw new SigningException(errorMsg, e);
			}
		} finally {
			LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG038));
		}
	}

	/**
	 * Method that obtains an ASN.1 timestamp from TS@ RFC 3161 service.
	 * @param dataToStamp Parameter that represents the data to stamp.
	 * @param applicationID Parameter that represents the identifier of the client application.
	 * @param tsaCommunicationMode Parameter that represents the protocol defined to communicate with TS@. The allowed values are:
	 * <ul>
	 * <li>{@link #TSA_RFC3161_TCP_COMMUNICATION} for TCP communication.</li>
	 * <li>{@link #TSA_RFC3161_HTTPS_COMMUNICATION} for HTTPS communication.</li>
	 * <li>{@link #TSA_RFC3161_SSL_COMMUNICATION} for SSL communication.</li>
	 * </ul>
	 * @return an object that represents the ASN.1 timestamp.
	 * @throws SigningException If the method fails.
	 */
	public static TimeStampToken getTimestampFromRFC3161Service(byte[ ] dataToStamp, String applicationID, String tsaCommunicationMode) throws SigningException {
		return getTimestampFromRFC3161Service(dataToStamp, applicationID, tsaCommunicationMode, null);
	}
}
