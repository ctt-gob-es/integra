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
// https://eupl.eu/1.1/es/

/**
 * <b>File:</b><p>es.gob.afirma.utils.UtilsTimestampPdfBc.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.rfc3161TSAServiceInvoker.RFC3161TSAServiceInvoker;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerConstants;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;

/**
 * <p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public final class UtilsTimestampOcspRfc3161 {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	public static final Logger LOGGER = Logger.getLogger(UtilsTimestampOcspRfc3161.class);

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
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_TCP_COMMUNICATION} for TCP communication.</li>
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_HTTPS_COMMUNICATION} for HTTPS communication.</li>
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_SSL_COMMUNICATION} for SSL communication.</li>
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
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_TCP_COMMUNICATION} for TCP communication.</li>
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_HTTPS_COMMUNICATION} for HTTPS communication.</li>
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_SSL_COMMUNICATION} for SSL communication.</li>
	 * </ul>
	 * @return an object that represents the ASN.1 timestamp.
	 * @param idClient Parameter that represents the client application identifier.
	 * @throws SigningException If the method fails.
	 */
	public static TimeStampToken getTimestampFromRFC3161Service(byte[ ] dataToStamp, String applicationID, String tsaCommunicationMode, String idClient) throws SigningException {
		LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG037));

		// Comprobamos que los parametros de entrada no son nulos
		checkInputParamsGetTimestampFromRFC3161Service(dataToStamp, applicationID, tsaCommunicationMode);
		try {
			// Instanciamos la clase encargada de llevar a cabo la
			// invocación
			String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG009);
			try {
				RFC3161TSAServiceInvoker invoker = new RFC3161TSAServiceInvoker();
				String protocol = null;
				// Si el modo de comunicacion es TCP
				if (tsaCommunicationMode.equals(IUtilsTimestamp.TSA_RFC3161_TCP_COMMUNICATION)) {
					LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG010));
					protocol = TSAServiceInvokerConstants.RFC3161Protocol.TCP;
				}
				// Si el modo de comunicacion es HTTPS
				else if (tsaCommunicationMode.equals(IUtilsTimestamp.TSA_RFC3161_HTTPS_COMMUNICATION)) {
					LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG011));
					protocol = TSAServiceInvokerConstants.RFC3161Protocol.HTTPS;
				}
				// Si el modo de comunicacion es SSL
				else if (tsaCommunicationMode.equals(IUtilsTimestamp.TSA_RFC3161_SSL_COMMUNICATION)) {
					LOGGER.debug(Language.getResIntegra(ILogConstantKeys.TSU_LOG012));
					protocol = TSAServiceInvokerConstants.RFC3161Protocol.SSL;
				}
				// Si el modo de comunicacion no está reconocido
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
					// lanzamos una excepcion
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
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_TCP_COMMUNICATION} for TCP communication.</li>
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_HTTPS_COMMUNICATION} for HTTPS communication.</li>
	 * <li>{@link es.gob.afirma.utils.IUtilsTimestamp#TSA_RFC3161_SSL_COMMUNICATION} for SSL communication.</li>
	 * </ul>
	 * @return an object that represents the ASN.1 timestamp.
	 * @throws SigningException If the method fails.
	 */
	public static TimeStampToken getTimestampFromRFC3161Service(byte[ ] dataToStamp, String applicationID, String tsaCommunicationMode) throws SigningException {
		return getTimestampFromRFC3161Service(dataToStamp, applicationID, tsaCommunicationMode, null);
	}

	/**
	 * Method that connects to an external RFC3161 TSA over HTTPS, requests a timestamp and
	 * returns the certificate used by the TSA to sign the returned TimeStampToken.
	 * <p>
	 * This method performs a POST of an ASN.1 TimeStampRequest to the URL formed by
	 * https://{host}:{port}{context} with Content-Type "application/timestamp-query".
	 * </p>
	 * @param host Hostname of the TSA (for example "psis.aoc.cat").
	 * @param port TCP port of the TSA (for example 443).
	 * @param context Context path of the TSA service (for example "/psis/catcert/tsp").
	 * @param policyOID OID of the timestamp policy to request (may be null or empty).
	 * @param hashAlgorithm Hash algorithm to use for the request (e.g. "SHA-256").
	 * @return X509Certificate that signed the TimeStampToken returned by the TSA.
	 * @throws SigningException If any error occurs building the request, contacting the TSA or parsing the response.
	 */
	public static X509Certificate getSigningCertificateFromExternalTSA(final String host, final int port, final String context,
			final String policyOID, final String hashAlgorithm) throws SigningException {
			LOGGER.info("Obteniendo certificado firmante del TSA externo: " + host + ":" + port + context);
			try {
				// Build TimeStampRequest
				TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
				reqgen.setCertReq(true);

				if (policyOID != null && !policyOID.trim().isEmpty()) {
					reqgen.setReqPolicy(policyOID);
				}

				// Use a small fixed nonce payload (content does not matter for certificate retrieval)
				byte[] data = "integra-tsa-cert-retrieval".getBytes("UTF-8");

				String algOid = translateHashAlgorithmToOid(hashAlgorithm);

				MessageDigest md = MessageDigest.getInstance(normalizeJavaHashName(hashAlgorithm));
				byte[] digest = md.digest(data);

				TimeStampRequest req = reqgen.generate(algOid, digest);
				byte[] requestBytes = req.getEncoded();

				// Build URL
				String contextNormalized = (context == null) ? "" : context;
				if (!contextNormalized.startsWith("/")) {
					contextNormalized = "/" + contextNormalized;
				}
				URL url = new URL("https", host, port, contextNormalized);

				// Open connection
				HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
				// Accept any hostname (behaviour consistent with existing invoker)
				conn.setHostnameVerifier(new HostnameVerifier() {
					@Override
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
				});

				conn.setDoOutput(true);
				conn.setDoInput(true);
				conn.setUseCaches(false);
				conn.setRequestProperty("Content-Type", "application/timestamp-query");
				conn.setRequestProperty("Content-Transfer-Encoding", "binary");

				OutputStream out = null;
				InputStream in = null;
				ByteArrayOutputStream baos = null;
				try {
					out = conn.getOutputStream();
					out.write(requestBytes);
					out.flush();

					in = conn.getInputStream();
					baos = new ByteArrayOutputStream();
					byte[] buffer = new byte[1024];
					int read = -1;
					while ((read = in.read(buffer)) != -1) {
						baos.write(buffer, 0, read);
					}
					byte[] responseBytes = baos.toByteArray();

					TimeStampResponse tsr = new TimeStampResponse(responseBytes);
					if (tsr.getFailInfo() != null) {
						throw new SigningException("TSA returned failure: " + tsr.getStatusString());
					}
					TimeStampToken tst = tsr.getTimeStampToken();
					if (tst == null) {
						throw new SigningException("TSA did not return a TimeStampToken");
					}

					// Extract signing certificate directly to avoid module dependency
					try {
						Store<X509CertificateHolder> store = tst.getCertificates();
						Collection<X509CertificateHolder> collectionSigningCertificate = store.getMatches(tst.getSID());

						if (collectionSigningCertificate == null || collectionSigningCertificate.size() != 1) {
							throw new SigningException(Language.getResIntegra(ILogConstantKeys.TSU_LOG015));
						}

						X509CertificateHolder certHolder = collectionSigningCertificate.iterator().next();
						return new JcaX509CertificateConverter()
								.setProvider(BouncyCastleProvider.PROVIDER_NAME)
								.getCertificate(certHolder);
					} catch (StoreException e) {
						String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG122);
						LOGGER.error(errorMsg);
						throw new SigningException(errorMsg, e);
					} catch (CertificateException e) {
						String errorMsg = Language.getResIntegra(ILogConstantKeys.TSU_LOG123);
						LOGGER.error(errorMsg);
						throw new SigningException(errorMsg, e);
					}

				} finally {
					UtilsResourcesCommons.safeCloseOutputStream(out);
					UtilsResourcesCommons.safeCloseInputStream(in);
					UtilsResourcesCommons.safeCloseOutputStream(baos);
				}

			} catch (IOException e) {
				throw new SigningException("I/O error contacting TSA", e);
			} catch (Exception e) {
				throw new SigningException("Error obtaining signing certificate from TSA", e);
			}
		}

		private static String normalizeJavaHashName(String hashAlgorithm) {
			if (hashAlgorithm == null) {
				return "SHA-256";
			}
			String s = hashAlgorithm.replace("-", "").toUpperCase();
			if (s.equals("SHA256") || s.equals("SHA256")) {
				return "SHA-256";
			} else if (s.equals("SHA1") || s.equals("SHA")) {
				return "SHA-1";
			} else if (s.equals("SHA512")) {
				return "SHA-512";
			} else if (s.equals("RIPEMD160")) {
				return "RIPEMD160";
			}
			return hashAlgorithm;
		}

		private static String translateHashAlgorithmToOid(String hashAlgorithm) throws SigningException {
			if (hashAlgorithm == null) {
				return TSPAlgorithms.SHA256.getId();
			}
			String s = hashAlgorithm.replace("-", "").toUpperCase();
			if (s.equals("SHA256")) {
				return TSPAlgorithms.SHA256.getId();
			} else if (s.equals("SHA1") || s.equals("SHA")) {
				return TSPAlgorithms.SHA1.getId();
			} else if (s.equals("SHA512")) {
				return TSPAlgorithms.SHA512.getId();
			} else if (s.equals("RIPEMD160")) {
				return TSPAlgorithms.RIPEMD160.getId();
			}
			throw new SigningException("Unsupported hash algorithm: " + hashAlgorithm);
		}
}