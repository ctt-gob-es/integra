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
 * <b>File:</b><p>es.gob.afirma.ocsp.OCSPClient.java.</p>
 * <b>Description:</b><p>Class that represents an OCSP client. It is implementing the RFC 2560 also taking care to support the lightweight profile
 * recommendations defined in the RFC 5019.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2014.
 */
package es.gob.afirma.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.bouncycastle.util.encoders.Base64;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.signature.SignatureConstants;
import es.gob.afirma.utils.GenericUtilsCommons;
import es.gob.afirma.utils.IUtilsKeystore;
import es.gob.afirma.utils.NumberConstants;
import es.gob.afirma.utils.UtilsCertificateCommons;
import es.gob.afirma.utils.UtilsFileSystemCommons;
import es.gob.afirma.utils.UtilsKeystoreCommons;
import es.gob.afirma.utils.UtilsResourcesCommons;

/**
 * <p>Class that represents an OCSP client. It is implementing the RFC 2560 also taking care to support the lightweight profile
 * recommendations defined in the RFC 5019.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/11/2014.
 */
public final class OCSPClient {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(OCSPClient.class);

	/**
	 * Attribute that represents the US-ASCII charset.
	 */
	private static final Charset ASCII = Charset.forName("US-ASCII");

	static {
		// Añadimos el proveedor criptográfico Bouncycastle en caso de que no
		// esté incluído
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * Constructor method for the class OCSPClient.java.
	 */
	private OCSPClient() {
	}

	/**
	 * Method that validates a certificate against an OCSP responder.
	 * @param certificateToValidate Parameter that represents the certificate to validate.
	 * @param idClient Parameter that represents the client application identifier.
	 * @return an object that contains the response of the OCSP responder and the date when the cached response expires on the OCSP responder.
	 * @throws OCSPClientException If the method fails.
	 */
	public static OCSPEnhancedResponse validateCertificate(X509Certificate certificateToValidate, String idClient) throws OCSPClientException {
		LOGGER.info(Language.getResIntegra(ILogConstantKeys.OC_LOG001));
		try {
			// Comprobamos que los parámetros de entrada son correctos
			GenericUtilsCommons.checkInputParameterIsNotNull(certificateToValidate, Language.getResIntegra(ILogConstantKeys.OC_LOG003));

			// Accedemos al archivo con las propiedades asociadas a la
			// comunicación con un servidor OCSP
			Properties ocspProperties = new IntegraProperties().getIntegraProperties(idClient);

			// Rescatamos del archivo de propiedades la URL de acceso
			// al servicio OCSP
			String ocspResponderURLString = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_URL);

			// Comprobamos que la URL de acceso al servicio OCSP no sea nula ni
			// vacía
			checkIsNotNullAndNotEmpty(ocspResponderURLString, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG041, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

			// Comprobamos que la URL de acceso al servicio OCSP tenga un valor
			// válido
			URL ocspResponder = null;
			try {
				ocspResponder = new URL(ocspResponderURLString);
			} catch (MalformedURLException e) {
				String msgError = Language.getResIntegra(ILogConstantKeys.OC_LOG042);
				LOGGER.error(msgError, e);
				throw new OCSPClientException(msgError, e);
			}

			// Rescatamos del archivo de propiedades la ruta del almacén de
			// claves donde se ubican los certificados raíz emisores de los
			// certificados
			// a validar
			String keystoreCAPath = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_ISSUER_KEYSTORE_PATH);

			// Comprobamos que la ruta del almacén de claves donde se ubican los
			// certificados raíz emisores de los certificados a validar no es
			// nula ni vacía
			checkIsNotNullAndNotEmpty(keystoreCAPath, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG043, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

			// Rescatamos el tipo del almacén de claves donde se ubican los
			// certificados raíz emisores de los certificados
			String keystoreCAType = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_ISSUER_KEYSTORE_TYPE);

			// Comprobamos que el tipo del almacén de claves donde se ubican los
			// certificados raíz emisores de los certificados a validar no es
			// nulo ni vacío
			checkIsNotNullAndNotEmpty(keystoreCAType, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG051, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

			// Comprobamos que el tipo de almacén de claves está soportado
			checkKeystoreType(keystoreCAType, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG052, new Object[ ] { keystoreCAType }));

			// Rescatamos la contraseña del almacén de claves donde se ubican
			// los certificados raíz emisores de los certificados a validar
			String keystoreCAPassword = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_ISSUER_KEYSTORE_PASSWORD);

			// Comprobamos que la contraseña del almacén de claves donde se
			// ubican los certificados raíz emisores de los certificados a
			// validar no es nula ni vacía
			checkIsNotNullAndNotEmpty(keystoreCAPassword, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG053, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

			// Accedemos al almacén de claves y obtenemos la lista con todos los
			// certificados almacenados
			byte[ ] keystoreCABytes = getBytesFromFile(keystoreCAPath);
			List<X509Certificate> listCACertificates = null;
			try {
				listCACertificates = UtilsKeystoreCommons.getListCertificates(keystoreCABytes, keystoreCAPassword, keystoreCAType);
			} catch (Exception e) {
				throw new OCSPClientException(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG054, new Object[ ] { keystoreCAPath }), e);
			}

			// Buscamos en la lista de certificado aquél que sea emisor del
			// certificado a validar
			X509Certificate issuerCertificate = getIssuer(certificateToValidate, listCACertificates, keystoreCAPath);

			// Obtenemos el indicador para saber si se debe firmar la
			// petición OCSP
			String signOCSPRequestStr = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_SIGN_REQUEST);

			// Comprobamos que el indicador para saber si se debe firmar la
			// petición
			// OCSP no es nulo ni vacío
			checkIsNotNullAndNotEmpty(signOCSPRequestStr, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG044, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

			X509Certificate clientCertificate = null;
			PrivateKey clientPrivateKey = null;

			// Si es necesario firmar la petición OCSP
			if (signOCSPRequestStr.equals(Boolean.toString(true))) {
				// Rescatamos la ruta al almacén de claves donde se
				// encuentra almacenada la clave privada a usar para firmar
				// la petición OCSP
				String keystorePath = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_REQUEST_KEYSTORE_PATH);

				// Comprobamos que la ruta al almacén de claves donde se
				// encuentra
				// almacenada la clave privada a usar para firmar
				// la petición OCSP no es nula ni vacía
				checkIsNotNullAndNotEmpty(keystorePath, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG045, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

				// Rescatamos el tipo de almacén de claves donde se
				// encuentra almacenada la clave privada a usar para firmar la
				// petición OCSP
				String keystoreType = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_REQUEST_KEYSTORE_TYPE);

				// Comprobamos que el tipo de almacén de claves donde se
				// encuentra
				// almacenada la clave privada a usar para firmar la petición
				// OCSP
				// no es nulo ni vacío
				checkIsNotNullAndNotEmpty(keystorePath, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG046, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

				// Comprobamos que el tipo de almacén de claves está soportado
				checkKeystoreType(keystoreType, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG047, new Object[ ] { keystoreType }));

				// Rescatamos la contraseña del almacén de claves donde
				// se encuentra
				// almacenada la clave privada a usar para firmar la petición
				// OCSP
				String keystorePassword = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_REQUEST_KEYSTORE_PASSWORD);

				// Comprobamos que la contraseña del almacén de claves donde se
				// encuentra almacenada la clave privada a usar para firmar la
				// petición OCSP no es nula ni vacía
				checkIsNotNullAndNotEmpty(keystorePassword, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG048, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

				// Rescatamos el alias de la clave privada a usar para
				// firmar la petición OCSP
				String privateKeyAlias = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_REQUEST_PRIVATE_KEY_ALIAS);
				// Comprobamos que el alias de la clave privada a usar para
				// firmar
				// la petición OCSP no es nulo ni vacío
				checkIsNotNullAndNotEmpty(privateKeyAlias, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG049, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

				// Rescatamos la contraseña de la clave privada a usar
				// para firmar la petición OCSP
				String privateKeyPassword = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_REQUEST_PRIVATE_KEY_PASSWORD);

				// Comprobamos que la contraseña de la clave privada a usar para
				// firmar la petición OCSP no es nula ni vacía
				checkIsNotNullAndNotEmpty(privateKeyPassword, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG050, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

				// Accedemos al almacén de claves para rescatar la clave privada
				// y
				// el certificado usados para firmar la petición OCSP
				byte[ ] keystoreBytes = getBytesFromFile(keystorePath);
				try {
					clientPrivateKey = UtilsKeystoreCommons.getPrivateKeyEntry(keystoreBytes, keystorePassword, privateKeyAlias, keystoreType, privateKeyPassword);
					clientCertificate = UtilsCertificateCommons.generateCertificate(UtilsKeystoreCommons.getCertificateEntry(keystoreBytes, keystorePassword, privateKeyAlias, keystoreType));
				} catch (Exception e) {
					throw new OCSPClientException(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG008, new Object[ ] { privateKeyAlias, keystorePath }), e);
				}
			}
			// Si no es necesario firmar la petición OCSP
			else if (signOCSPRequestStr.equals(Boolean.toString(false))) {
				clientCertificate = null;
				clientPrivateKey = null;
			}
			// Si el valor introducido no es válido
			else {
				throw new OCSPClientException(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG007, new Object[ ] { signOCSPRequestStr }));
			}

			// Rescatamos del archivo de propiedades el identificador
			// de la aplicación cliente para comunicarnos con el servidor OCSP
			String applicationID = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_APP_ID);

			// Obtenemos el número de serie del certificado a validar
			BigInteger serialNumber = certificateToValidate.getSerialNumber();

			// En caso de que se haya indicado el certificado para la
			// autenticación OCSP, definimos su cadena de certificación
			X509Certificate[ ] clientCertChain = null;
			if (clientCertificate != null) {
				clientCertChain = new X509Certificate[1];
				clientCertChain[0] = clientCertificate;
			}

			// Creamos la petición OCSP
			OCSPReq ocspRequest = getOCSPRequest(issuerCertificate, serialNumber, applicationID, clientCertChain, clientPrivateKey);

			// Obtenemos el tiempo de vida definido para las
			// peticiones OCSP
			String timeoutStr = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_TIMEOUT);

			// Comprobamos que el tiempo de vida definido para las peticiones
			// OCSP no es nulo
			if (timeoutStr == null) {
				String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.OC_LOG010, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
				LOGGER.error(errorMsg);
				throw new OCSPClientException(errorMsg);
			}
			// Comprobamos que el tiempo de vida definido para las peticiones
			// OCSP no es nulo tiene un valor correcto
			Integer timeout = null;
			try {
				timeout = Integer.parseInt(timeoutStr);
			} catch (NumberFormatException e) {
				String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.OC_LOG011, new Object[ ] { timeoutStr });
				LOGGER.error(errorMsg, e);
				throw new OCSPClientException(errorMsg, e);
			}

			// Obtenemos la respuesta OCSP
			return getOCSPResponse(ocspResponder, ocspRequest, timeout, ocspProperties);

		} finally {
			LOGGER.info(Language.getResIntegra(ILogConstantKeys.OC_LOG002));
		}
	}

	/**
	 * Method that validates a certificate against an OCSP responder.
	 * @param certificateToValidate Parameter that represents the certificate to validate.
	 * @return an object that contains the response of the OCSP responder and the date when the cached response expires on the OCSP responder.
	 * @throws OCSPClientException If the method fails.
	 */
	public static OCSPEnhancedResponse validateCertificate(X509Certificate certificateToValidate) throws OCSPClientException {
		return validateCertificate(certificateToValidate, null);
	}

	/**
	 * Method that obtains the issuer certificate of certain certificate from a list of possible issuers.
	 * @param certificate Parameter that represents the certificate used to search his issuer.
	 * @param listCertificates Parameter that represents the list of possible issuers.
	 * @param keystoreCAPath Parameter that represents the path of the keystore which contains the possible issuers.
	 * @return an object that represents the issuer certificate.
	 * @throws OCSPClientException If the issuer certificate wasn't found.
	 */
	private static X509Certificate getIssuer(X509Certificate certificate, List<X509Certificate> listCertificates, String keystoreCAPath) throws OCSPClientException {
		// Buscamos en la lista de certificados CA aquél cuyo asunto coincida
		// con el emisor del certificado
		boolean enc = false;
		X509Certificate certificateCA = null;
		int i = 0;
		while (!enc && i < listCertificates.size()) {
			X509Certificate possibleCertificateCA = listCertificates.get(i);
			try {
				// Comprobamos si es la CA correcta
				certificate.verify(possibleCertificateCA.getPublicKey());
				enc = true;
				certificateCA = possibleCertificateCA;
			} catch (Exception e) {
				// Si se produce una excepción es que el certificado no es
				// CA del que estamos validando
			}
			i++;
		}
		// Si no hemos encontrado la CA, entonces el certificado no está
		// reconocido
		if (!enc) {
			String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.OC_LOG005, new Object[ ] { keystoreCAPath });
			LOGGER.error(errorMsg);
			throw new OCSPClientException(errorMsg);
		}
		return certificateCA;
	}

	/**
	 * Method that obtains a file as a bytes array.
	 * @param filePath Parameter that represents the path of the file.
	 * @return the bytes array of the file.
	 * @throws OCSPClientException If the file does not exist, is a directory rather than a regular file, or for some other reason cannot be
	 * opened for reading.
	 */
	private static byte[ ] getBytesFromFile(String filePath) throws OCSPClientException {
		InputStream fis = null;
		try {
			fis = new FileInputStream(filePath);
			return GenericUtilsCommons.getDataFromInputStream(fis);
		} catch (IOException e) {
			throw new OCSPClientException(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG004, new Object[ ] { filePath }), e);
		} finally {
			UtilsResourcesCommons.safeCloseInputStream(fis);
		}
	}

	/**
	 * Method that obtains an OCSP response from the OCSP responder.
	 * @param urlResponder Parameter that represents the URL of the OCSP responder.
	 * @param ocspRequest Parameter that represents the OCSP request.
	 * @param timeout Parameter that represents the timeout for the communication with the OCSP responder.
	 * @param ocspProperties Parameter that represents the configuration file for communicating with an OCSP server.
	 * @return an object that represents the OCSP response.
	 * @throws OCSPClientException If the method fails.
	 */
	private static OCSPEnhancedResponse getOCSPResponse(URL urlResponder, OCSPReq ocspRequest, int timeout, Properties ocspProperties) throws OCSPClientException {
		DataOutputStream wr = null;
		boolean wrIsClosed = false;
		InputStream in = null;
		ByteArrayOutputStream ou = null;
		HttpURLConnection con = null;
		Date maxCache = null;
		byte[ ] requestBytes;
		try {
			requestBytes = ocspRequest.getEncoded();
		} catch (IOException e) {
			String errorMsg = Language.getResIntegra(ILogConstantKeys.OC_LOG030);
			LOGGER.error(errorMsg, e);
			throw new OCSPClientException(errorMsg, e);
		}
		try {

			// Establecemos el método de comunicación con el servidor OCSP. Si
			// la petición es menor de 255 bytes se hará por GET, en caso
			// contrario
			// se hará por POST.
			String getUrl = getHttpGetUrl(urlResponder, requestBytes, ocspProperties);

			if (getUrl == null) {
				con = doPost(urlResponder, requestBytes, timeout, ocspProperties);
			} else {
				URL u = new URL(getUrl);
				// con = (HttpURLConnection) u.openConnection(new
				// Proxy(Proxy.Type.HTTP, new InetSocketAddress("10.148.56.107",
				// 8080)));
				con = (HttpURLConnection) u.openConnection();
				con.setDoOutput(true);
				con.setRequestMethod("GET");
				con.setRequestProperty("Content-Type", "application/ocsp-request");
				con.setRequestProperty("Accept", "application/ocsp-response");
				con.setRequestProperty("charset", SignatureConstants.UTF8_ENCODING);
				con.setRequestProperty("Content-Length", Integer.toString(requestBytes.length));
				configureHttpConnection(con, timeout, ocspProperties);
			}

			wr = new DataOutputStream(con.getOutputStream());
			wr.write(requestBytes);
			wr.flush();
			wr.close();
			wrIsClosed = true;

			// Comprobamos que la conexión se estableció correctamente
			if (con.getResponseCode() / NumberConstants.INT_100 != 2) {
				// Error de conexión
				String errorMsg = Language.getFormatResIntegra(ILogConstantKeys.OC_LOG032, new Object[ ] { con.getResponseMessage() });
				LOGGER.error(errorMsg);
				throw new OCSPClientException(errorMsg);
			}
			in = (InputStream) con.getContent();
			ou = new ByteArrayOutputStream();
			byte[ ] buffer = new byte[NumberConstants.INT_256];
			int len = -1;
			while ((len = in.read(buffer)) > 0) {
				ou.write(buffer, 0, len);
			}
			byte[ ] response = ou.toByteArray();

			// Obtenemos la fecha en que la respuesta cacheada expira
			maxCache = getNextUpdateFromCacheHeader(con.getHeaderField("cache-control"));

			// Obtenemos el objeto que representa la respuesta OCSP
			OCSPResp ocspResponse = new OCSPResp(response);

			// Instanciamos el objeto a devolver
			OCSPEnhancedResponse result = new OCSPEnhancedResponse();

			result.setMaxAge(maxCache);
			result.setStatus(ocspResponse.getStatus());

			BasicOCSPResp basicResponse = null;
			try {
				basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
			} catch (OCSPException e) {
				result.setErrorMsg(Language.getResIntegra(ILogConstantKeys.OC_LOG034));
			}
			// Validamos la respuesta OCSP, en caso de estar firmada
			if (isValidResponse(basicResponse, result, ocspProperties)) {
				SingleResp[ ] responses = basicResponse.getResponses();
				SingleResp resp = responses[0];
				// Procesamos la respuesta OCSP
				processOCSPResponse(resp.getCertStatus(), result);
			}
			return result;
		} catch (IOException e) {
			String errorMsg = Language.getResIntegra(ILogConstantKeys.OC_LOG031);
			LOGGER.error(errorMsg, e);
			throw new OCSPClientException(errorMsg, e);
		} finally {
			if (!wrIsClosed) {
				UtilsResourcesCommons.safeCloseOutputStream(wr);
			}
			UtilsResourcesCommons.safeCloseOutputStream(ou);
			UtilsResourcesCommons.safeCloseInputStream(in);
		}
	}

	/**
	 * Method that verifies if the status of the certificate is correct or not.
	 * @param status Parameter that represents the status of the certificate.
	 * @param result Parameter that represents an OCSP response with the date when the cached OCSP response expires, as defined on the lightweight
	 * profile recommendations defined in the RFC 5019.
	 */
	private static void processOCSPResponse(Object status, OCSPEnhancedResponse result) {
		// Comprobamos el estado de la respuesta OCSP
		if (status != null) {
			// Estado revocado
			if (status instanceof RevokedStatus) {
				RevokedStatus revStatus = (RevokedStatus) status;
				// Obtenemos la fecha de revocación y la asociamos al resultado
				result.setRevocationDate(revStatus.getRevocationTime());
			}
			// Estado desconocido
			else if (status instanceof UnknownStatus) {
				result.setErrorMsg(Language.getResIntegra(ILogConstantKeys.OC_LOG033));
			}
		}
	}

	/**
	 * Method that verifies if a signed OCSP response is genuine (true) or not (false).
	 * @param ocspResp Parameter that represents the OCSP response.
	 * @param result Parameter that represents an OCSP response with the date when the cached OCSP response expires, as defined on the lightweight
	 * profile recommendations defined in the RFC 5019.
	 * @param ocspProperties Parameter that represents the configuration file for communicating with an OCSP server.
	 * @return a boolean that indicates if a signed OCSP response is genuine (true) or not (false).
	 */
	private static boolean isValidResponse(BasicOCSPResp ocspResp, OCSPEnhancedResponse result, Properties ocspProperties) {
		OutputStream vOut = null;
		String errorMsg = Language.getResIntegra(ILogConstantKeys.OC_LOG035);
		boolean isValid = true;
		try {
			// Obtenemos el certificado de la respuesta, en caso de que esté
			// firmada
			X509Certificate[ ] responderCerts = ocspResp.getCerts(BouncyCastleProvider.PROVIDER_NAME);
			if (responderCerts != null && responderCerts.length > 0) {
				// Obtenemos el certificado del servidor OCSP contenido en la
				// respuesta OCSP
				X509Certificate responderCert = responderCerts[0];

				// Rescatamos del archivo de propiedades la ruta del
				// certificado con el que firma las respuestas el servidor OCSP
				String responseCertificatePath = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_RESPONSE_CERTIFICATE_PATH);

				// Comprobamos que la ruta del certificado con el que firma las
				// respuestas el servidor OCSP no es nula ni vacía
				if (!GenericUtilsCommons.assertStringValue(responseCertificatePath)) {
					errorMsg = Language.getFormatResIntegra(ILogConstantKeys.OC_LOG039, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
					throw new OCSPClientException();
				}

				// Obtenemos el objeto X509Certificate del certificado con el
				// que firma las respuestas el servidor OCSP
				errorMsg = Language.getFormatResIntegra(ILogConstantKeys.OC_LOG040, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE });
				byte[ ] responseCertificateBytes = UtilsFileSystemCommons.readFile(responseCertificatePath, false);
				if (responseCertificateBytes == null) {
					throw new OCSPClientException();
				}
				X509Certificate responseCertificate = UtilsCertificateCommons.generateCertificate(responseCertificateBytes);

				// Comprobamos si ambos certificados son iguales
				if (!UtilsCertificateCommons.equals(responseCertificate, responderCert)) {
					isValid = false;
					result.setErrorMsg(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG036, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
				} else {
					// Comprobamos si la firma de la respuesta es válida
					errorMsg = Language.getResIntegra(ILogConstantKeys.OC_LOG037);
					if (!ocspResp.verify(responseCertificate.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME)) {
						isValid = false;
						result.setErrorMsg(Language.getResIntegra(ILogConstantKeys.OC_LOG038));
					}
				}
			}
		} catch (Exception e) {
			LOGGER.error(errorMsg, e);
			result.setErrorMsg(errorMsg);
			isValid = false;
		} finally {
			UtilsResourcesCommons.safeCloseOutputStream(vOut);
		}
		return isValid;
	}

	/**
	 * Method that obtains the time when a cached response expires from an OCSP response.
	 * @param cc Parameter that represents the content of <code>cache-control</code> element of the OCSP response header.
	 * @return the time when a cached response expires from an OCSP response or <code>null</code> if the OCSP response doesn't contain the
	 * <code>cache-control</code> element.
	 */
	private static Date getNextUpdateFromCacheHeader(String cc) {
		if (cc == null) {
			return null;
		}
		int i = cc.indexOf("max-age=");
		if (i == -1) {
			return null;
		}
		i += NumberConstants.INT_8;
		int j = cc.indexOf(',', i);
		if (j == -1) {
			j = cc.length();
		}
		String deltaS = cc.substring(i, j).trim();
		int delta;
		try {
			delta = Integer.parseInt(deltaS);
		} catch (NumberFormatException e) {
			return null;
		}
		return new Date(System.currentTimeMillis() + delta * NumberConstants.LONG_1000);
	}

	/**
	 * Method that configures the connection with the OCSP responder via HTTP or HTTPS.
	 * @param con Parameter that represents the URLConnection to the OCSP responder.
	 * @param timeout Parameter that represents the timeout for the communication with the OCSP responder.
	 * @param ocspProperties Parameter that represents the configuration file for communicating with an OCSP server.
	 * @throws OCSPClientException If the method fails.
	 */
	private static void configureHttpConnection(HttpURLConnection con, int timeout, Properties ocspProperties) throws OCSPClientException {
		if (con instanceof HttpsURLConnection) {
			HttpsURLConnection httpsCon = (HttpsURLConnection) con;
			SSLSocketFactory sf = getSSLSocketFactory(ocspProperties);
			httpsCon.setSSLSocketFactory(sf);
		}
		con.setConnectTimeout(timeout);
		con.setReadTimeout(timeout);
	}

	/**
	 * Method that obtains the SSL socket factory.
	 * @param ocspProperties Parameter that represents the configuration file for communicating with an OCSP server.
	 * @return the SSL socket factory.
	 * @throws OCSPClientException If the method fails.
	 */
	private static SSLSocketFactory getSSLSocketFactory(Properties ocspProperties) throws OCSPClientException {
		// Rescatamos la ruta al almacén de confianza para
		// conexiones seguras
		String trustsorePath = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_TRUSTEDSTORE_PATH);

		// Comprobamos que la ruta al almacén de confianza para conexiones
		// seguras no es nula ni vacía
		checkIsNotNullAndNotEmpty(trustsorePath, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG014, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG015, new Object[ ] { trustsorePath }));

		// Rescatamos la clave del almacén de confianza
		String truststorePassword = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_TRUSTEDSTORE_PASSWORD);

		// Comprobamos que la clave del almacén de confianza no sea nula ni
		// vacía
		checkIsNotNullAndNotEmpty(truststorePassword, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG016, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

		String errorMsg = null;
		try {
			// Cargamos el almacén de confianza
			errorMsg = Language.getResIntegra(ILogConstantKeys.OC_LOG017);
			KeyStore cer = UtilsKeystoreCommons.loadKeystore(trustsorePath, truststorePassword, IUtilsKeystore.JKS);

			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(cer);

			SSLContext ctx = SSLContext.getInstance("SSL");

			// Obtenemos el indicador para saber si es necesaria la
			// autenticación del cliente
			String authClientStr = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_HTTPS_USE_AUTH_CLIENT);
			// Comprobamos que el indicador para saber si es necesaria la
			// autenticación del cliente no es nulo ni vacío
			checkIsNotNullAndNotEmpty(authClientStr, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG018, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

			// Si es necesaria la autenticación cliente
			if (authClientStr.equals(Boolean.toString(true))) {
				LOGGER.info(Language.getResIntegra(ILogConstantKeys.OC_LOG019));

				// Rescatamos la ruta al almacén de claves al
				// almacén de claves
				// donde se encuentra almacenada la clave privada a usar para la
				// autenticación HTTPS
				String keystorePath = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_HTTPS_KEYSTORE_PATH);

				// Comprobamos que la ruta al almacén de claves al almacén de
				// claves donde se encuentra almacenada la clave privada a usar
				// para la
				// autenticación HTTPS no sea nula ni vacía
				checkIsNotNullAndNotEmpty(keystorePath, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG020, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

				LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG021, new Object[ ] { keystorePath }));

				// Rescatamos el tipo de almacén de claves donde se
				// encuentra almacenada la clave privada a usar para la
				// autenticación
				// HTTPS
				String keystoreType = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_HTTPS_KEYSTORE_TYPE);

				// Comprobamos que el tipo de almacén de claves donde se
				// encuentra almacenada la clave privada a usar para la
				// autenticación
				// HTTPS no es nulo ni vacío
				checkIsNotNullAndNotEmpty(keystoreType, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG022, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

				// Comprobamos que el tipo de almacén de claves está soportado
				checkKeystoreType(keystoreType, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG023, new Object[ ] { keystoreType }));
				LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG024, new Object[ ] { keystoreType }));

				// Rescatamos la contraseña del almacén de claves
				// donde se encuentra
				// almacenada la clave privada a usar para la autenticación
				// HTTPS
				String keystorePassword = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_HTTPS_KEYSTORE_PASSWORD);

				// Comprobamos que la contraseña del almacén de claves donde se
				// encuentra almacenada la clave privada a usar para la
				// autenticación HTTPS no es nula ni vacía
				checkIsNotNullAndNotEmpty(keystorePassword, Language.getFormatResIntegra(ILogConstantKeys.OC_LOG025, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE }));

				// Obtenemos el almacén de claves para la autenticación cliente
				errorMsg = Language.getResIntegra(ILogConstantKeys.OC_LOG026);
				KeyStore ks = UtilsKeystoreCommons.loadKeystore(keystorePath, keystorePassword, keystoreType);
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(ks, keystorePassword.toCharArray());
				errorMsg = Language.getResIntegra(ILogConstantKeys.OC_LOG027);
				ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			}
			// Si NO es necesaria la autenticación cliente
			else if (authClientStr.equals(Boolean.toString(false))) {
				LOGGER.info(Language.getResIntegra(ILogConstantKeys.OC_LOG028));
				errorMsg = Language.getResIntegra(ILogConstantKeys.OC_LOG027);
				ctx.init(null, tmf.getTrustManagers(), null);
			} else {
				throw new OCSPClientException(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG029, new Object[ ] { authClientStr }));
			}

			return ctx.getSocketFactory();
		} catch (IOException e) {
			LOGGER.error(errorMsg, e);
			throw new OCSPClientException(errorMsg, e);
		} catch (KeyStoreException e) {
			LOGGER.error(errorMsg, e);
			throw new OCSPClientException(errorMsg, e);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error(errorMsg, e);
			throw new OCSPClientException(errorMsg, e);
		} catch (CertificateException e) {
			LOGGER.error(errorMsg, e);
			throw new OCSPClientException(errorMsg, e);
		} catch (UnrecoverableKeyException e) {
			LOGGER.error(errorMsg, e);
			throw new OCSPClientException(errorMsg, e);
		} catch (KeyManagementException e) {
			LOGGER.error(errorMsg, e);
			throw new OCSPClientException(errorMsg, e);
		}
	}

	/**
	 * Method that verifies if a value is not empty and not null.
	 * @param value Parameter that represents the value to check.
	 * @param errorMsg Parameter that represents the error message to include inside of the exception where the value is empty or null.
	 * @throws OCSPClientException If the value is empty or null.
	 */
	private static void checkIsNotNullAndNotEmpty(String value, String errorMsg) throws OCSPClientException {
		if (!GenericUtilsCommons.assertStringValue(value)) {
			LOGGER.error(errorMsg);
			throw new OCSPClientException(errorMsg);
		}
	}

	/**
	 * Method that verifies if the type of a keystore has a correct value. The allowed
	 * values are:
	 * <ul>
	 * <li>{@link UtilsKeystoreCommons#PKCS12}</li>
	 * <li>{@link UtilsKeystoreCommons#JCEKS}</li>
	 * <li>{@link UtilsKeystoreCommons#JKS}</li>
	 * </ul>
	 * @param keystoreType Parameter that represents the type of the keystore.
	 * @param msg Parameter that represents the error message if the type of the keystore is incorrect.
	 * @throws OCSPClientException If the type of the keystore is incorrect.
	 */
	private static void checkKeystoreType(String keystoreType, String msg) throws OCSPClientException {
		if (!keystoreType.equals(IUtilsKeystore.PKCS12) && !keystoreType.equals(IUtilsKeystore.JCEKS) && !keystoreType.equals(IUtilsKeystore.JKS)) {
			throw new OCSPClientException(msg);
		}
	}

	/**
	 * Method that obtains the URLConnection with support for HTTP to the OCSP responder.
	 * @param urlResponder Parameter that represents the URL of the OCSP responder.
	 * @param request Parameter that represents the OCSP request.
	 * @param timeout Parameter that represents the timeout for the communication with the OCSP responder.
	 * @param ocspProperties Parameter that represents the configuration file for communicating with an OCSP server.
	 * @return an object that represents the URLConnection with support for HTTP to the OCSP responder.
	 * @throws OCSPClientException If the method fails.
	 */
	private static HttpURLConnection doPost(URL urlResponder, byte[ ] request, int timeout, Properties ocspProperties) throws OCSPClientException {
		try {
			HttpURLConnection con = (HttpURLConnection) urlResponder.openConnection();
			configureHttpConnection(con, timeout, ocspProperties);
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/ocsp-request");
			con.setRequestProperty("Accept", "application/ocsp-response");
			con.setRequestProperty("charset", SignatureConstants.UTF8_ENCODING);
			con.setRequestProperty("Content-Length", Integer.toString(request.length));
			return con;
		} catch (IOException e) {
			String msg = Language.getResIntegra(ILogConstantKeys.OC_LOG013);
			LOGGER.error(msg, e);
			throw new OCSPClientException(msg, e);
		}
	}

	/**
	 * Method that obtains the URL for HTTP connection, only if the request is less than or equal to 255 bytes in total.
	 * @param urlResponder Parameter that represents the URL of the OCSP responder.
	 * @param request Parameter that represents the OCSP request.
	 * @param ocspProperties Parameter that represents the configuration file for communicating with an OCSP server.
	 * @return the URL for HTTP connection or <code>null</code> if the request is less than or equal to 255 bytes in total.
	 * @throws OCSPClientException If the named encoding is not supported.
	 */
	private static String getHttpGetUrl(URL urlResponder, byte[ ] request, Properties ocspProperties) throws OCSPClientException {
		// Obtenemos el indicador para saber si se debe realizar la
		// petición OCSP mediante GET (true) o POST (false)
		String useGETMethodStr = (String) ocspProperties.get(IOCSPConstants.KEY_OCSP_USE_GET);

		// Si se debe realizar la petición OCSP mediante GET
		if (useGETMethodStr.equals(Boolean.toString(true))) {
			byte[ ] base64 = Base64.encode(request);
			String ret = new String(base64, ASCII);

			try {
				ret = URLEncoder.encode(ret, ASCII.name());
			} catch (UnsupportedEncodingException e) {
				String msg = Language.getResIntegra(ILogConstantKeys.OC_LOG012);
				LOGGER.error(msg, e);
				throw new OCSPClientException(msg, e);
			}
			String url = urlResponder.toExternalForm();
			if (url.endsWith("/")) {
				ret = url + ret;
			} else {
				ret = url + "/" + ret;
			}

			if (ret.length() > NumberConstants.INT_255) {
				return null;
			}
			return ret;
		}
		// Si se debe realizar la petición OCSP mediante POST
		else if (useGETMethodStr.equals(Boolean.toString(false))) {
			return null;
		}
		// Si el valor introducido no es válido
		else {
			throw new OCSPClientException(Language.getFormatResIntegra(ILogConstantKeys.OC_LOG006, new Object[ ] { IIntegraConstants.DEFAULT_PROPERTIES_FILE, useGETMethodStr }));
		}
	}

	/**
	 * Method that generates an OCSP request.
	 * @param certificateCA Parameter that represents the issuer of the certificate to validate.
	 * @param serialNumber Parameter that represents the serial number of the certificate to validate.
	 * @param applicationID Parameter that represents the client application identifier.
	 * @param clientCertChain Parameter that represents the certification chain of the certificate used for the connection with the OCSP responder.
	 * @param clientPk Parameter that represents the private key of the certificate used for the connection with the OCSP responder.
	 * @return an object that represents the OCSP request.
	 * @throws OCSPClientException If the method fails.
	 */
	private static OCSPReq getOCSPRequest(X509Certificate certificateCA, BigInteger serialNumber, String applicationID, X509Certificate[ ] clientCertChain, PrivateKey clientPk) throws OCSPClientException {
		try {
			CertificateID id = new CertificateID(CertificateID.HASH_SHA1, certificateCA, serialNumber);

			OCSPReqGenerator gen = new OCSPReqGenerator();
			gen.addRequest(id);

			// Si se ha indicado el identificador de aplicación se establece en
			// el campo requestorName
			if (applicationID != null) {
				gen.setRequestorName(new GeneralName(GeneralName.rfc822Name, applicationID));
			}
			// Añadimos la extensión NONCE
			BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
			List<ASN1ObjectIdentifier> oids = new ArrayList<ASN1ObjectIdentifier>();
			List<X509Extension> values = new ArrayList<X509Extension>();
			oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
			gen.setRequestExtensions(new X509Extensions(new Vector<ASN1ObjectIdentifier>(oids), new Vector<X509Extension>(values)));

			// Firmamos la petición OCSP en caso de que se haya indicado la
			// cadena de certificación y la clave privada del certificado
			// cliente
			if (clientCertChain != null && clientPk != null) {
				return gen.generate(SignatureConstants.SIGN_ALGORITHM_SHA1WITHRSA, clientPk, clientCertChain, BouncyCastleProvider.PROVIDER_NAME);
			} else {
				return gen.generate();
			}
		} catch (Exception e) {
			String msg = Language.getResIntegra(ILogConstantKeys.OC_LOG009);
			LOGGER.error(msg, e);
			throw new OCSPClientException(msg, e);
		}
	}

}
