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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsHTTP.java.</p>
 * <b>Description:</b><p>Utilities class relating to connections and HTTP/S protocol.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 17/11/2020.
 */
package es.gob.afirma.tsl.utils;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.StandardHttpRequestRetryHandler;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.log4j.Logger;


import es.gob.afirma.i18n.Language;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.utils.connection.auth.JCIFSNTLMSchemeFactory;
import es.gob.afirma.tsl.utils.connection.ssh.IntegraSSLSocketFactory;
import es.gob.afirma.utils.NumberConstants;
import es.gob.afirma.utils.UtilsResourcesCommons;

/** 
 * <p>Utilities class relating to connections and HTTP/S protocol.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 17/11/2020.
 */
public final class UtilsHTTP {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(UtilsHTTP.class);

    /**
     * Constant attribute that represents the representation string of the scheme http.
     */
    public static final String HTTP_SCHEME = "http";

    /**
     * Constant attribute that represents the representation string of the scheme https.
     */
    public static final String HTTPS_SCHEME = "https";

    /**
     * Constant attribute that represents the Apache-HttpClient User-Agent Header.
     */
    public static final String HTTP_HEADER_USER_AGENT_HTTPCLIENT = "Apache-HttpClient";

    /**
     * Constant attribute that represents the Jakarta Commons-HttpClient User-Agent Header.
     */
    public static final String HTTP_HEADER_USER_AGENT_JAKARTA = "Jakarta Commons-HttpClient";

    /**
     * Constant attribute that represents the value of the output 'Content-type' for http request by post.
     */
    public static final String OUTPUT_CONTENT_TYPE_OCSP_RESPONSE = "application/ocsp-response";
    /**
     * Constant attribute that represents the "User-Agent" header.
     */
    public static final String HEADER_USER_AGENT = "User-Agent";

    /**
     * Constant attribute that represents the "Accept-Encoding" header.
     */
    public static final String HEADER_ACCEPT_ENCODING = "Accept-Encoding";

    /**
     * Constructor method for the class UtilsHTTP.java.
     */
    private UtilsHTTP() {
	super();
    }

    /**
     * This method determines whether a given URI scheme is HTTP or HTTPS.
     * @param uriString String representation of the URI to analyze.
     * @param checkMode Int that determines the check mode operation:
     * <ul>
     * <li> 0: Check if the URI is HTTP OR HTTPS.</li>
     * <li> 1: Check if the URI is HTTP.</li>
     * <li> 2: Check if the URI is HTTPS.</li>
     * </ul>
     * @return <i>true</i> if the scheme of the URI is HTTP or HTTPS, otherwise <i>false</i>.
     */
    public static boolean isUriOfSchemeHTTP(String uriString, int checkMode) {

	boolean result = false;

	if (!UtilsStringChar.isNullOrEmptyTrim(uriString)) {

	    try {

		URI uri = new URI(uriString);
		result = isUriOfSchemeHTTP(uri, checkMode);

	    } catch (URISyntaxException e) {
		result = false;
	    }

	}

	return result;

    }

    /**
     * This method determines whether a given URI scheme is HTTP or HTTPS.
     * @param uri Representation of the URI to analyze.
     * @param checkMode Int that determines the check mode operation:
     * <ul>
     * <li> 0: Check if the URI is HTTP OR HTTPS.</li>
     * <li> 1: Check if the URI is HTTP.</li>
     * <li> 2: Check if the URI is HTTPS.</li>
     * </ul>
     * @return <i>true</i> if the scheme of the URI is HTTP or HTTPS, otherwise <i>false</i>.
     */
    public static boolean isUriOfSchemeHTTP(URI uri, int checkMode) {

	boolean result = false;

	if (uri != null) {

	    String scheme = uri.getScheme();
	    if (!UtilsStringChar.isNullOrEmptyTrim(scheme)) {

		switch (checkMode) {
		    case 0:
			result = scheme.equalsIgnoreCase(HTTP_SCHEME) || scheme.equalsIgnoreCase(HTTPS_SCHEME);
			break;
		    case 1:
			result = scheme.equalsIgnoreCase(HTTP_SCHEME);
			break;
		    case 2:
			result = scheme.equalsIgnoreCase(HTTPS_SCHEME);
			break;
		    default:
			break;
		}

	    }

	}

	return result;

    }

    /**
     * Auxiliar method that sets some HTTP Headers (at least {@link HttpHeaders#USER_AGENT} and {@link HttpHeaders#ACCEPT_ENCODING}).
     * @param method HTTP Request in which sets the headers.
     * @param isForOcspRequest flag that indicates if it is for a ocsp request (<code>true</code>) or not (<code>false</code>).
     * @param headersMap Parameter that represents a map with the specific headers.
     */
    private static void forceSetHttpHeadersInHttpClientMethod(HttpRequestBase method, boolean isForOcspRequest, Map<String, String> headersMap) {

	// Si no se han pasado las cabeceras a establecer...
	if (headersMap == null) {

	    // Si es para una petición OCSP...
	    if (isForOcspRequest) {
		// Se indica "Jakarta Commons-HttpClient"
		method.setHeader(HttpHeaders.USER_AGENT, HTTP_HEADER_USER_AGENT_JAKARTA);
	    } else {
		// Si no, se indica "Apache-HttpClient"
		method.setHeader(HttpHeaders.USER_AGENT, HTTP_HEADER_USER_AGENT_HTTPCLIENT);
	    }

	} else {

	    // Si se han pasado, las recorremos y vamos añadiendo
	    // a los headers.
	    Set<String> headerKeys = headersMap.keySet();
	    for (String headerKey: headerKeys) {
		method.setHeader(headerKey, headersMap.get(headerKey));
	    }

	}

    }

    /**
     * Method that makes a HTTP POST request to certain URL and obtains the response as a bytes array. The input data will be imposed
     * as <code>RequestEntity</code> using the <code>HttpClient</code> library provided by Jakarta.
     * @param uriString Parameter that represents the connection path to the resource.
     * @param connectionTimeout Parameter that represents the timeout for the connection.
     * @param readTimeout Parameter that represents the timeout for the data reading.
     * @param inputData Parameter that represents the data to insert inside the <code>RequestEntity</code>.
     * @param inputContentType Parameter that represents the content-type of the request.
     * @param outputContentType Parameter that represents the content-type of the response.
     * @param user Parameter that represents the user for authentication.
     * @param password Parameter that represents the password for authentication.
     * @return a bytes array that represents the content of the resource indicated in the URL.
     * @throws CommonUtilsException If there is some error with the input parameters or the connection.
     */
    public static byte[ ] getResponseByHttpPostWithEntity(String uriString, int connectionTimeout, int readTimeout, byte[ ] inputData, String inputContentType, String outputContentType, String user, String password) throws CommonUtilsException {

	// Array de bytes que devolveremos:
	byte[ ] result = null;
	HttpPost method = new HttpPost(uriString);
	CloseableHttpClient client = null;
	InputStream in = null;
	CloseableHttpResponse response = null;

	if (inputData == null) {
	    throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_008));
	}

	method.setEntity(new ByteArrayEntity(inputData));

	if (!UtilsStringChar.isNullOrEmpty(inputContentType)) {
	    method.setHeader(HttpHeaders.CONTENT_TYPE, inputContentType);
	}
	if (!UtilsStringChar.isNullOrEmpty(outputContentType)) {
	    method.setHeader(HttpHeaders.ACCEPT, outputContentType);
	}

	// Forzamos a establecer ciertos "Headers".
	forceSetHttpHeadersInHttpClientMethod(method, true, null);

	String host = method.getURI().getHost();
	int port = method.getURI().getPort();
	String protocol = method.getURI().getScheme();

	HttpHost target = new HttpHost(host, port, protocol);

	// Creamos el gestor de credenciales.
	CredentialsProvider credsProvider = new BasicCredentialsProvider();
	// Obtenemos la configuración del proxy.
	HttpHost proxy = UtilsProxy.setUpProxyConfigurationInHttpClient(credsProvider, method, uriString);

	// Construimos las credenciales y la factoría SSL si son necesarios.
	client = buildCredentialsAndSSLSocketFactoryIfIsNecessary(credsProvider, user, password, host, port, protocol);

	// Establecemos el timeout de conexión.
	// Establecemos el timeout de lectura de datos.
	// Establecemos el proxy si es necesario.

	RequestConfig requestConfig = RequestConfig.custom().setSocketTimeout(readTimeout).setConnectTimeout(connectionTimeout).setRedirectsEnabled(true).setProxy(proxy).build();

	method.setConfig(requestConfig);

	try {

	    if (client != null) {
		LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_009, new Object[ ] { uriString }));
		// Se ejecuta la conexión con el método creado.
		response = client.execute(target, method);

		// Si todo ha ido bien...
		if (response == null) {

		    throw new ClientProtocolException(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_006));

		} else {

		    if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

			LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_010));

			HttpEntity entity = response.getEntity();
			if (entity != null) {

			    // Cogemos el stream del 'body' de respuesta.
			    in = entity.getContent();

			    // Obtenemos el tamaño de los datos para crear el
			    // array.
			    int length = (int) entity.getContentLength();

			    // Comprobamos que el tipo de la respuesta es el
			    // adecuado.
			    if (entity.getContentType() != null && (entity.getContentType().getValue() == null || !entity.getContentType().getValue().equals(OUTPUT_CONTENT_TYPE_OCSP_RESPONSE))) {
				LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_012, new Object[ ] { OUTPUT_CONTENT_TYPE_OCSP_RESPONSE, entity.getContentType().getValue() }));
			    }

			    LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_011));

			    // Si el tamaño de los datos es -1 es porque se
			    // trata de una
			    // descarga de un DirectoryList que no tiene
			    // 'ContentLength'
			    // por lo que hay que omitir este dato y realizar la
			    // descarga
			    // sin este.
			    if (length == -1) {

				// Creamos un BufferedInputStream para realizar
				// la
				// lectura
				// de los datos.
				BufferedInputStream bis = new BufferedInputStream(in);
				// Creamos un buffer intermedio.
				byte[ ] buffer = new byte[NumberConstants.INT_1024];
				// Creamos un ByteArrayOutputStream para ir
				// almacenando
				// los
				// datos.
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				// Creamos un contador de bytes para limitar la
				// descarga.
				int contadorBytes = 0;
				try {
				    // Leemos todos los datos mientras no
				    // superen el
				    // límite
				    // establecido.
				    int readed = bis.read(buffer);
				    contadorBytes = readed;
				    while (readed > 0 && contadorBytes <= UtilsConnection.getMaxSizeConnection()) {
					baos.write(buffer, 0, readed);
					readed = bis.read(buffer);
					contadorBytes += readed;
				    }
				} finally {
				    // Cerramos recursos
				    UtilsResourcesCommons.safeCloseOutputStream(baos);
				    UtilsResourcesCommons.safeCloseInputStream(bis);
				}
				// Si hemos excedido el tamaño máximo permitido
				// en las
				// descargas lanzamos excepción.
				if (contadorBytes > UtilsConnection.getMaxSizeConnection()) {
				    throw new ClientProtocolException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_001, new Object[ ] { UtilsConnection.getMaxSizeConnection() }));
				}

				result = baos.toByteArray();

			    } else {

				if (length > UtilsConnection.getMaxSizeConnection()) {
				    throw new ClientProtocolException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_002, new Object[ ] { length, UtilsConnection.getMaxSizeConnection() }));
				}

				// Creamos el array resultante.
				result = new byte[length];

				// Leemos los datos y los almacenamos en el
				// array de
				// bytes
				// de respuesta.
				int bytesLeidos = in.read(result, 0, length);
				while (bytesLeidos < length) {
				    bytesLeidos = in.read(result, bytesLeidos, length - bytesLeidos) + bytesLeidos;
				}

				// Si la cantidad de bytes leidos es distinta a
				// la de
				// los
				// datos del stream... excepción.
				if (bytesLeidos != length) {
				    throw new ClientProtocolException(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_003));
				}
			    }

			    LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_004));
			}
		    }
		    // En cambio, si no se ha ejecutado correctamente la
		    // conexión o ha
		    // habido algún problema...
		    else {

			throw new ClientProtocolException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_005, new Object[ ] { response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase() }));

		    }

		}

	    }

	} catch (IOException e) {

	    // Relanzamos la excepción.
	    throw new CommonUtilsException(e.getMessage(), e);

	} finally {
	    // En cualquier caso cerramos el recurso.
	    UtilsResourcesCommons.safeCloseInputStream(in);

	    try {
		if (response != null) {
		    response.close();
		}
		if (client != null) {
		    client.close();
		}
	    } catch (IOException e) {
		LOGGER.warn(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_013), e);
	    } finally {
		response = null;
		client = null;
	    }

	}

	if (result == null) {
	    throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_014, new Object[ ] { uriString }));
	}

	return result;

    }

    /**
     * Build the credentials and the SSLSocketFactory if these are needed for the connection, and returns the
     * http client to use.
     * @param credsProvider Credentials manager in which sets the user/password configuration.
     * @param user User name necessary for the connection. It could be <code>null</code>.
     * @param password Password associated to the user. It could be <code>null</code>.
     * @param host Hostname or IP to assign the use of the credentials. It could be <code>null</code>.
     * @param port Port associated to the host. It could be <code>null</code>.
     * @param protocol Protocol for the connection (HTTP or HTTPS).
     * @return a closeable http client connection.
     */
    private static CloseableHttpClient buildCredentialsAndSSLSocketFactoryIfIsNecessary(CredentialsProvider credsProvider, String user, String password, String host, int port, String protocol) {

	CloseableHttpClient result = null;

	// Comprobamos si es necesario establecer credenciales
	if (user != null && password != null) {
	    credsProvider.setCredentials(new AuthScope(host, port), new UsernamePasswordCredentials(user, password));
	}

	// Confiamos en cualquier conexión segura de destino...
	try {
	    Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider> create().register(AuthSchemes.NTLM, new JCIFSNTLMSchemeFactory()).register(AuthSchemes.BASIC, new BasicSchemeFactory()).build();
	    if (protocol.equalsIgnoreCase(HTTPS_SCHEME)) {
		// desactivamos la validación ssl
		SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {

		    public boolean isTrusted(X509Certificate[ ] arg0, String arg1) throws CertificateException {
			return true;
		    }
		}).build();
		result = HttpClients.custom().setSSLSocketFactory(new IntegraSSLSocketFactory(sslContext)).setDefaultAuthSchemeRegistry(authSchemeRegistry).setRetryHandler(new StandardHttpRequestRetryHandler(0, false)).setDefaultCredentialsProvider(credsProvider).setSSLHostnameVerifier(new NoopHostnameVerifier()).build();
	    } else {
		result = HttpClients.custom().setDefaultAuthSchemeRegistry(authSchemeRegistry).setRetryHandler(new StandardHttpRequestRetryHandler(0, false)).setDefaultCredentialsProvider(credsProvider).build();
	    }

	} catch (KeyManagementException | NoSuchAlgorithmException
		| KeyStoreException e) {
	    // vacío intencionadamente
	}

	return result;

    }

    /**
     * Method that allows download the data from a URI using the <code>HttpClient</code> library.
     * @param uriString Parameter that represents the connection path (URI) to the resource.
     * @param connectionTimeout Parameter that represents the timeout for the connection.
     * @param readTimeout Parameter that represents the timeout for the data reading.
     * @param user Parameter that represents the user for authentication.
     * @param password Parameter that represents the password for authentication.
     * @param headersMap Parameter that represents a list of specific headers for the HTTP/S connection.
     * @return a byte array that represents the content of the resource obtained from the URI.
     * @throws CommonUtilsException In case of some error getting the resource.
     */
    public static byte[ ] getDataFromURI(String uriString, int connectionTimeout, int readTimeout, String user, String password, Map<String, String> headersMap) throws CommonUtilsException {

	try {

	    return getDataWithHttpClient(uriString, connectionTimeout, readTimeout, user, password, headersMap);

	} catch (CommonUtilsException e) {

	    // Relanzamos la excepción.
	    throw e;

	}

    }

    /**
     * Method that allows download the data from a URI using the <code>HttpClient</code> library.
     * @param uriString Parameter that represents the connection path (URI) to the resource.
     * @param connectionTimeout Parameter that represents the timeout for the connection.
     * @param readTimeout Parameter that represents the timeout for the data reading.
     * @param user Parameter that represents the user for authentication.
     * @param password Parameter that represents the password for authentication.
     * @param headersMap Parameter that represents a list of specific headers for the HTTP/S connection.
     * @throws CommonUtilsException In case of some error getting the resource.
     * @return a byte array that represents the content of the resource obtained from the URI.
     */
    private static byte[ ] getDataWithHttpClient(String uriString, int connectionTimeout, int readTimeout, String user, String password, Map<String, String> headersMap) throws CommonUtilsException {

	// Array de bytes que devolveremos:
	byte[ ] res = null;
	HttpGet method = new HttpGet(uriString);
	CloseableHttpClient client = null;
	InputStream in = null;
	CloseableHttpResponse response = null;

	// Creamos un manejador de la conexión.
	String protocol = method.getURI().getScheme();
	String host = method.getURI().getHost();
	int port = method.getURI().getPort();
	if (port < 0) {
	    if (HTTP_SCHEME.equalsIgnoreCase(protocol)) {
		port = NumberConstants.INT_80;
	    } else if (HTTPS_SCHEME.equalsIgnoreCase(protocol)) {
		port = NumberConstants.INT_443;
	    }
	}

	// Forzamos a establecer ciertos "Headers".
	forceSetHttpHeadersInHttpClientMethod(method, false, headersMap);

	HttpHost target = new HttpHost(host, port, protocol);

	// Creamos el gestor de credenciales.
	CredentialsProvider credsProvider = new BasicCredentialsProvider();
	// Obtenemos la configuración del proxy.
	HttpHost proxy = UtilsProxy.setUpProxyConfigurationInHttpClient(credsProvider, method, uriString);
	// Construimos las credenciales y la factoría SSL si son necesarios.
	client = buildCredentialsAndSSLSocketFactoryIfIsNecessary(credsProvider, user, password, host, port, protocol);

	// Establecemos el timeout de conexión.
	// Establecemos el timeout de lectura de datos.
	// Establecemos el proxy si es necesario.
	RequestConfig requestConfig = RequestConfig.custom().setSocketTimeout(readTimeout).setConnectTimeout(connectionTimeout).setRedirectsEnabled(true).setProxy(proxy).build();

	method.setConfig(requestConfig);

	try {

	    try {

		if (client != null) {
		    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_009, new Object[ ] { uriString }));
		    // Se ejecuta la conexión con el método creado.
		    response = client.execute(target, method);

		    // Si todo ha ido bien...
		    if (response == null) {

			throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_006));

		    } else {

			// Si todo ha ido bien...
			if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

			    LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_010));

			    HttpEntity entity = response.getEntity();
			    if (entity != null) {

				// Cogemos el stream del 'body' de respuesta.
				in = entity.getContent();

				LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_000));

				// Obtenemos el tamaño de los datos para crear
				// el array.
				int length = (int) entity.getContentLength();

				LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_011));

				// Si el tamaño de los datos es -1 es porque se
				// trata de
				// una
				// descarga de un DirectoryList que no tiene
				// 'ContentLength'
				// por lo que hay que omitir este dato y
				// realizar la
				// descarga sin este.
				if (length == -1) {

				    // Creamos un BufferedInputStream para
				    // realizar la
				    // lectura de los datos.
				    BufferedInputStream bis = new BufferedInputStream(in);
				    // Creamos un buffer intermedio.
				    byte[ ] buffer = new byte[NumberConstants.INT_1024];
				    // Creamos un ByteArrayOutputStream para ir
				    // almacenando
				    // los datos.
				    ByteArrayOutputStream baos = new ByteArrayOutputStream();
				    // Creamos un contador de bytes para limitar
				    // la
				    // descarga.
				    int contadorBytes = 0;
				    try {
					// Leemos todos los datos mientras no
					// superen el
					// límite
					// establecido.
					int readed = bis.read(buffer);
					contadorBytes = readed;

					while (readed > 0 && contadorBytes <= UtilsConnection.getMaxSizeConnection()) {
					    baos.write(buffer, 0, readed);
					    readed = bis.read(buffer);
					    contadorBytes += readed;
					}
				    } finally {
					// Cerramos recursos
					UtilsResourcesCommons.safeCloseOutputStream(baos);
					UtilsResourcesCommons.safeCloseInputStream(bis);
				    }
				    // Si hemos excedido el tamaño máximo
				    // permitido en
				    // las
				    // descargas lanzamos excepción.
				    if (contadorBytes > UtilsConnection.getMaxSizeConnection()) {
					throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_001, new Object[ ] { UtilsConnection.getMaxSizeConnection() }));
				    }

				    res = baos.toByteArray();

				} else {
				    if (length > UtilsConnection.getMaxSizeConnection()) {
					throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_002, new Object[ ] { length, UtilsConnection.getMaxSizeConnection() }));
				    }

				    // Creamos el array resultante.
				    res = new byte[length];

				    // Leemos los datos y los almacenamos en el
				    // array de
				    // bytes
				    // de respuesta.
				    int bytesLeidos = in.read(res, 0, length);
				    while (bytesLeidos < length) {
					bytesLeidos = in.read(res, bytesLeidos, length - bytesLeidos) + bytesLeidos;
				    }

				    // Si la cantidad de bytes leidos es
				    // distinta a la
				    // de
				    // los
				    // datos del stream... excepción.
				    if (bytesLeidos != length) {
					throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_003));
				    }

				    LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_004));
				}
			    }
			}
			// En cambio, si no se ha ejecutado correctamente la
			// conexión o
			// ha
			// habido algún problema
			else {
			    throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_005, new Object[ ] { response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase() }));
			}

		    }

		}

	    } finally {

		// En cualquier caso cerramos el recurso.
		UtilsResourcesCommons.safeCloseInputStream(in);

		if (response != null) {
		    response.close();
		}

		if (client != null) {
		    client.close();
		}

	    }

	    if (res == null) {
		throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_007, new Object[ ] { uriString }));
	    }

	} catch (UnsupportedOperationException | IOException e) {
	    throw new CommonUtilsException(e.getMessage(), e);
	}

	return res;

    }

    /**
     * Method that allows download the data from a URI using the <code>HttpClient</code> library.
     * @param path Parameter that represents the connection path (URI) to the resource.
     * @param connectionTimeout Parameter that represents the timeout for the connection.
     * @param readTimeout Parameter that represents the timeout for the data reading.
     * @return a byte array that represents the content of the resource obtained from the URI.
     * @throws CommonUtilsException In case of some error getting the resource.
     */
    public static byte[ ] getDataFromURI(String path, int connectionTimeout, int readTimeout) throws CommonUtilsException {
	byte[ ] res = null;

	HttpGet method = new HttpGet(path);
	CloseableHttpClient client = null;
	CloseableHttpResponse response = null;

	// Creamos un manejador de la conexión.
	String host = method.getURI().getHost();
	int port = method.getURI().getPort();
	String protocolo = method.getURI().getScheme();

	// Forzamos a establecer ciertos "Headers".
	forceSetHttpHeadersInHttpClientMethod(method, false);
	HttpHost target = new HttpHost(host, port, protocolo);
	RequestConfig requestConfig = null;
	CredentialsProvider credsProvider = new BasicCredentialsProvider();
	// Se establece la configuración del proxy si es necesario.
	HttpHost proxy = UtilsProxy.setUpProxyConfigurationInHttpClient(credsProvider, method, path);

	// Creamos el cliente encargado de ejecutar la conexión.
	// Especificamos el numeros de reintentos (false == Que no se relance de
	// forma automática para evitar inconsistencia de datos).
	// Desactivamos los reintentos ya que realmente no nos interesa.
	client = createClient(protocolo, credsProvider, connectionTimeout, readTimeout, host, port);
	requestConfig = RequestConfig.custom().setSocketTimeout(readTimeout).setConnectTimeout(connectionTimeout).setRedirectsEnabled(true).setProxy(proxy).build();
	method.setConfig(requestConfig);
	try {
	    if (client != null) {
		// Se ejecuta la conexión con el método creado.

		response = client.execute(target, method);

		// si todo ha ido bien...
		if (response != null && response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

		    res = getDatesFromResponse(response);
		}

		// En cambio, si no se ha ejecutado correctamente la conexión o
		// ha
		// habido algún problema
		else {
		    if (response != null) {
			// En cambio, si no se ha ejecutado correctamente la
			// conexión o
			// ha
			// habido algún problema
			throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UH_LOG_005, new Object[ ] { response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase() }));
		    } else {
			throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_006));
		    }
		}

	    }
	} catch (Exception e) {
	    throw new CommonUtilsException(e.getMessage(), e);
	}

	return res;

    }

    /**
     * Method that gets dates from response.
     * @param response CloseableHttpResponse
     * @param valmet ValidationMethod
     * @return byte[] res
     * @throws UnsupportedOperationException unsupported operation exception
     * @throws IOException io excpetion
     * @throws CommonUtilsException 
     */
    private static byte[ ] getDatesFromResponse(CloseableHttpResponse response) throws CommonUtilsException {
	byte[ ] res = null;
	InputStream is = null;
	// LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_010));
	HttpEntity entity = response.getEntity();
	try {
	    if (entity != null) {
		// Cogemos el stream del 'body' de respuesta.
		is = entity.getContent();
		// LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_000));
		// Obtenemos el tamaño de los datos para crear el array.
		int length = (int) entity.getContentLength();
		LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_011));

		// Si el tamaño de los datos es -1 es porque se trata de una
		// descarga de un DirectoryList que no tiene 'ContentLength'
		// por lo que hay que omitir este dato y realizar la
		// descarga
		// sin este.
		if (length == -1) {
		    // Creamos un BufferedInputStream para realizar la
		    // lectura
		    // de los datos.
		    BufferedInputStream bis = new BufferedInputStream(is);
		    // Creamos un buffer intermedio.
		    byte[ ] buffer = new byte[NumberConstants.INT_1024];
		    // Creamos un ByteArrayOutputStream para ir almacenando
		    // los
		    // datos.
		    ByteArrayOutputStream baos = new ByteArrayOutputStream();

		    try {
			// Leemos todos los datos
			int readed = bis.read(buffer);
			while (readed > 0) {
			    baos.write(buffer, 0, readed);
			    readed = bis.read(buffer);
			}
		    } finally {
			// Cerramos recursos
			UtilsResourcesCommons.safeCloseOutputStream(baos);
			UtilsResourcesCommons.safeCloseInputStream(bis);
		    }
		    res = baos.toByteArray();
		} else {

		    // Creamos el array resultante.
		    res = new byte[length];

		    // Leemos los datos y los almacenamos en el array de
		    // bytes
		    // de respuesta.
		    int bytesLeidos = is.read(res, 0, length);
		    while (bytesLeidos < length) {
			bytesLeidos = is.read(res, bytesLeidos, length - bytesLeidos) + bytesLeidos;
		    }
		    // Si la cantidad de bytes leidos es distinta a la de
		    // los
		    // datos del stream... excepción.
		    if (bytesLeidos != length) {
			throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UH_LOG_003));
		    }

		}

	    }

	} catch (UnsupportedOperationException | IOException e) {
	    throw new CommonUtilsException(e.getMessage(), e);
	}
	return res;
    }

    /**
     * Auxiliar method that sets some HTTP Headers
     * ({@link HTTPConstants#HEADER_USER_AGENT} and
     * {@link HTTPConstants#HEADER_ACCEPT_ENCODING}).
     *
     * @param method
     *            HTTP Request in which sets the headers.
     * @param isForOcspRequest
     *            flag that indicates if it is for a ocsp request
     *            (<code>true</code>) or not (<code>false</code>).
     */
    private static void forceSetHttpHeadersInHttpClientMethod(HttpRequestBase method, boolean isForOcspRequest) {

	// Si es para una petición OCSP...
	if (isForOcspRequest) {
	    // Se indica "Jakarta Commons-HttpClient"
	    method.setHeader(HEADER_USER_AGENT, HTTP_HEADER_USER_AGENT_JAKARTA);
	} else {
	    // Si no, se indica "Apache-HttpClient"
	    method.setHeader(HEADER_USER_AGENT, HTTP_HEADER_USER_AGENT_HTTPCLIENT);
	}
	// El Accept-Encoding lo mandamos vacío.
	method.setHeader(HEADER_ACCEPT_ENCODING, UtilsStringChar.EMPTY_STRING);

    }

    /**
     * Method that creates the client.
     * @param protocolo String
     * @param credsProvider CredentialsProvider
     * @param valmet ValidationMethod
     * @param host String
     * @param port Port
     * @return CloseableHttpClient client
     */
    private static CloseableHttpClient createClient(String protocolo, CredentialsProvider credsProvider, int connectionTimeout, int readTimeout, String host, int port) {
	CloseableHttpClient client = null;

	Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider> create().register(AuthSchemes.NTLM, new JCIFSNTLMSchemeFactory()).register(AuthSchemes.BASIC, new BasicSchemeFactory()).build();

	client = HttpClients.custom().setDefaultAuthSchemeRegistry(authSchemeRegistry).setRetryHandler(new StandardHttpRequestRetryHandler(0, false)).setDefaultCredentialsProvider(credsProvider).build();

	return client;
    }
}
