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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.utils.connection.ss.IntegraSSLSocketFactory.java.</p>
 * <b>Description:</b><p>Class that represents a custom SSL Sockect Factory for HTTP Client.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 18/04/2022.
 */

package es.gob.afirma.tsl.utils.connection.ssh;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpHost;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.protocol.HttpContext;
import es.gob.afirma.tsl.logger.Logger;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.utils.StaticTslConfig;
import es.gob.afirma.tsl.utils.UtilsStringChar;



/**
 * <p>Class that represents a custom SSL Sockect Factory for HTTP Client.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version  1.2, 18/04/2022.
 */
public class IntegraSSLSocketFactory implements LayeredConnectionSocketFactory {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(IntegraSSLSocketFactory.class);

	/**
	 * Attribute that represents the SSL Context.
	 */
	private SSLContext sslContext;

	/**
	 * Constructor method for the class IntegraSSLSocketFactory.java.
	 * @param sslContextParam SSL context.
	 */
	public IntegraSSLSocketFactory(SSLContext sslContextParam) {
		sslContext = sslContextParam;
	}

	/**
	 * {@inheritDoc}
	 * @see org.apache.http.conn.socket.ConnectionSocketFactory#createSocket(org.apache.http.protocol.HttpContext)
	 */
	@Override
	public Socket createSocket(HttpContext context) throws IOException {
		SSLConnectionSocketFactory sslFactory = createSSLConnectionSocketFactory();
		return sslFactory.createSocket(context);
	}

	/**
	 * {@inheritDoc}
	 * @see org.apache.http.conn.socket.ConnectionSocketFactory#connectSocket(int, java.net.Socket, org.apache.http.HttpHost, java.net.InetSocketAddress, java.net.InetSocketAddress, org.apache.http.protocol.HttpContext)
	 */
	@Override
	public Socket connectSocket(int connectTimeout, Socket sock, HttpHost host, InetSocketAddress remoteAddress, InetSocketAddress localAddress, HttpContext context) throws IOException {
		SSLConnectionSocketFactory sslFactory = createSSLConnectionSocketFactory();
		return sslFactory.connectSocket(connectTimeout, sock, host, remoteAddress, localAddress, context);
	}

	/**
	 * {@inheritDoc}
	 * @see org.apache.http.conn.socket.LayeredConnectionSocketFactory#createLayeredSocket(java.net.Socket, java.lang.String, int, org.apache.http.protocol.HttpContext)
	 */
	@Override
	public Socket createLayeredSocket(Socket socket, String target, int port, HttpContext context) throws IOException, UnknownHostException {
		SSLConnectionSocketFactory sslFactory = createSSLConnectionSocketFactory();
		return sslFactory.createLayeredSocket(socket, target, port, context);
	}

	/**
	 * Method that creates a socket factory for SSL connections and this factory supported only cipher suite allowed.
	 * @return	Socket Factory for SSL connections
	 */
	private SSLConnectionSocketFactory createSSLConnectionSocketFactory() {

		String[ ] actualCipherSuites = sslContext.getSupportedSSLParameters().getCipherSuites();
		String[ ] supportedCipherSuites = removeCipherSuitesRestricted(actualCipherSuites);

		// Pasamos el resultado a un array.
		String[ ] supportedProtocols = null;
		// Recuperamos los protocolos de los que se puede hacer uso...
		String[ ] actualProtocols = sslContext.getSupportedSSLParameters().getProtocols();
		// Obtenemos los protocolos restringidos.
		Set<String> restrictedProtocols = getRestrictedProtocols();
		// Si la lista de restringidos no es vacía...
		if (restrictedProtocols != null && !restrictedProtocols.isEmpty()) {
			// Creamos una lista para almacenar los que consideremos válidos.
			List<String> supportedProtocolsList = new ArrayList<String>();
			if (actualProtocols != null && actualProtocols.length > 1) {
				// Los recorremos y vamos añadiendo aquellos que no estén
				// restringidos.
				for (String protocol: actualProtocols) {
					if (!restrictedProtocols.contains(protocol)) {
						supportedProtocolsList.add(protocol);
					}
				}
			}
			if (!supportedProtocolsList.isEmpty()) {
				supportedProtocols = new String[supportedProtocolsList.size()];
				supportedProtocols = supportedProtocolsList.toArray(supportedProtocols);
			}
		}

		return new SSLConnectionSocketFactory(sslContext, supportedProtocols, supportedCipherSuites, new NoopHostnameVerifier());

	}

	/**
	 * Calculate a new array in which are added all the input cipher suites except which
	 * are restricted.
	 * @param cipherSuites Cipher suites array to analyze.
	 * @return array in which are added all the input cipher suites except which
	 * are restricted.
	 */
	private String[ ] removeCipherSuitesRestricted(String[ ] cipherSuites) {

		String[ ] result = null;

		List<String> enabledCiphers = new ArrayList<String>();
		if (cipherSuites != null && cipherSuites.length > 0) {
			String[ ] restrictedCipherSuites = getRestrictedCipherSuites();
			if (restrictedCipherSuites != null) {
				for (String cipher: cipherSuites) {
					boolean exclude = false;
					for (int i = 0; i < restrictedCipherSuites.length && !exclude; i++) {
						exclude = cipher.indexOf(restrictedCipherSuites[i]) >= 0;
					}
					if (!exclude) {
						enabledCiphers.add(cipher);
					}
				}
				result = new String[enabledCiphers.size()];
				enabledCiphers.toArray(result);
			} else {
				result = cipherSuites;
			}
		} else {
			result = cipherSuites;
		}

		return result;

	}

	/**
	 * Gets the String array with the particles of the algorithm names of cipher suites
	 * that are restricted.
	 * @return String array with the particles of the algorithm names of cipher suites
	 * that are restricted.
	 */
	private static String[ ] getRestrictedCipherSuites() {

		String[ ] result = null;

		String value = StaticTslConfig.getProperty(StaticTslConfig.SSL_RESTRICTED_CIPHER_SUITES);
		if (UtilsStringChar.isNullOrEmptyTrim(value)) {
			LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UTILS_SSL_SOCKET_000));
		} else {
			result = value.split(UtilsStringChar.SYMBOL_COMMA_STRING);
		}

		return result;
	}

	/**
	 * Gets the String set with the tokens of the protocols that are restricted.
	 * @return String set with the tokens of the protocols that are restricted.
	 */
	private static Set<String> getRestrictedProtocols() {

		Set<String> result = null;

		String value = StaticTslConfig.getProperty(StaticTslConfig.SSL_RESTRICTED_PROTOCOLS);
		String[ ] resultArray = null;
		if (UtilsStringChar.isNullOrEmptyTrim(value)) {
			LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UTILS_SSL_SOCKET_001));
		} else {
			resultArray = value.split(UtilsStringChar.SYMBOL_COMMA_STRING);
		}
		if (resultArray != null && resultArray.length > 0) {
			result = new HashSet<String>();
			for (String protocol: resultArray) {
				result.add(protocol);
			}
		}

		return result;

	}

}
