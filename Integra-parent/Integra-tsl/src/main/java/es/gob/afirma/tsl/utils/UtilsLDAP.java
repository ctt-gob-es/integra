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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsLDAP.java.</p>
 * <b>Description:</b><p>Utilities class relating to connections and LDAP protocol.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 18/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 18/04/2022.
 */
package es.gob.afirma.tsl.utils;

import iaik.x509.X509CRL;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger; 
import es.gob.afirma.tsl.logger.IntegraLogger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;


import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
/** 
 * <p>Utilities class relating to connections and LDAP protocol.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 18/04/2022.
 */
public final class UtilsLDAP {
    /**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsLDAP.class);

	/**
	 * Constant attribute that represents the representation string of the LDAP scheme.
	 */
	private static final String LDAP_SCHEME = "LDAP";

	/**
	 * Constant attribute that represents an instance of {@link UtilsLDAP} to build the inner class {@link LDAPSocket}.
	 */
	private static final UtilsLDAP INSTANCE_TO_BUILD_LDAP_SOCKET = new UtilsLDAP();

	/**
	 * Constructor method for the class UtilsLDAP.java.
	 */
	private UtilsLDAP() {
		super();
	}

	/**
	 * Method that obtains the CRL from the LDAP.
	 * @param urlServer Parameter that represents the URL of the LDAP server (with the port, in another case the port is 389).
	 * @param user Parameter that represents the user for the authentication.
	 * @param password Parameter that represents the password for the authentication.
	 * @param pathLDAP Parameter that represents the path to follow in the LDAP server.
	 * @param searchFilter Parameter that represents the filter to use in the LDAP server.
	 * @param attributes Parameter that represents the list of attributes for including in the search.
	 * @param connectionTimeout Parameter that represents the number of milliseconds for the connection timeout.
	 * @param readTimeout Parameter that represents the number of milliseconds for the reading timeout.
	 * @param directLDAP Parameter that indicates whether the connection by LDAP is direct (true) or segmented (false).
	 * @return a {@link X509CRL} object that represents the CRL.
	 * @throws CommonUtilsException In case of some error working with the LDAP connection o getting the CRL from this.
	 */
	public static X509CRL getCRLfromLDAP(String urlServer, String user, String password, String pathLDAP, String searchFilter, String[ ] attributes, int connectionTimeout, int readTimeout, boolean directLDAP) throws CommonUtilsException {

		X509CRL result = null;

		// ////////////////////////////////////////////////////////////
		// Conexion contra el ldap para obtener la CRL
		// ////////////////////////////////////////////////////////////
		// El proceso es:
		// conexion url base ldap
		// búsqueda de la crl
		// obtencion del atributo que contiene la CRL
		// ////////////////////////////////////////////////////////////

		byte[ ] crlByteArray = getCRLDataWithLDAPNovell(urlServer, user, password, pathLDAP, searchFilter, attributes, connectionTimeout, readTimeout, directLDAP);

		// Si se han obtenido datos...
		if (crlByteArray != null) {

			result = UtilsCRL.buildX509CRLfromByteArray(crlByteArray);

		}

		return result;

	}

	/**
	 * Method that obtains the data from a LDAP server using the Novell library for the LDAP connection.
	 * @param urlServer Parameter that represents the URL of the LDAP server (with the port, in another case the port is 389).
	 * @param user Parameter that represents the user for the authentication.
	 * @param password Parameter that represents the password for the authentication.
	 * @param pathLDAP Parameter that represents the path to follow in the LDAP server.
	 * @param searchFilter Parameter that represents the filter to use in the LDAP server.
	 * @param attributes Parameter that represents the list of attributes for including in the search.
	 * @param connectionTimeout Parameter that represents the number of milliseconds for the connection timeout.
	 * @param readTimeout Parameter that represents the number of milliseconds for the reading timeout.
	 * @param directLDAP Parameter that indicates whether the connection by LDAP is direct (<code>true</code>) or segmented (<code>false</code>).
	 * @return the data from a LDAP server using the Novell library for the LDAP connection.
	 * @throws CommonUtilsException In case of some error while is trying to obtain the data from the LDAP.
	 */
	private static byte[ ] getCRLDataWithLDAPNovell(String urlServer, String user, String password, String pathLDAP, String searchFilter, String[ ] attributes, int connectionTimeout, int readTimeout, boolean directLDAP) throws CommonUtilsException {

		int defaultPort = LDAPConnection.DEFAULT_PORT;
		int ldapVersion = LDAPConnection.LDAP_V3;
		int searchScope = -1;

		if (directLDAP) {
			searchScope = LDAPConnection.SCOPE_BASE;
		} else {
			searchScope = LDAPConnection.SCOPE_SUB;
		}

		// Inicializamos el resultado final.
		byte[ ] crlByteArray = null;

		// TODO Falta establecer configuración del proxy.

		// Creamos la conexión
		LDAPSocket ldapSkt = INSTANCE_TO_BUILD_LDAP_SOCKET.new LDAPSocket(connectionTimeout);
		LDAPConnection lc = new LDAPConnection(ldapSkt);

		LDAPSearchConstraints sCons = new LDAPSearchConstraints();
		sCons.setTimeLimit(readTimeout);

		// Ralizamos la conexión.
		makeConnectionWithLDAP(lc, urlServer, defaultPort);
		

		// Si resulta necesario autenticarse...
		if (!UtilsStringChar.isNullOrEmptyTrim(user) && !UtilsStringChar.isNullOrEmptyTrim(password)) {

			try {
				lc.bind(ldapVersion, user, password.getBytes(StandardCharsets.UTF_8), sCons);
			} catch (LDAPException e) {
				throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_LDAP_001, new Object[ ] { urlServer, defaultPort, user }), e);
			}

		}

		try {

			// Lanzamos el proceso de búsqueda.
			LDAPSearchResults ldapResults = lc.search(pathLDAP, searchScope, searchFilter, attributes, false, sCons);

			// Si se ha encontrado algún atributo que cumpla el filtro...
			if (ldapResults.hasMore()) {

				// Tratamos de obtener el único resultado
				LDAPEntry ldapEntry = ldapResults.next();

				// Obtenemos el atributo de la CRL (binario).
				LDAPAttribute ldapAttribute = ldapEntry.getAttribute("certificateRevocationList;binary");

				// Si es nulo, es que está en hexadecimal y hay que
				// transformarlo...
				if (ldapAttribute == null) {

					ldapAttribute = ldapEntry.getAttribute("certificateRevocationList");

					// Si aún así es nulo, es que no se encuentra el atributo de
					// la
					// CRL.
					if (ldapAttribute == null) {

						throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_LDAP_002));

					} else {

						LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UTILS_LDAP_003));
						crlByteArray = (byte[ ]) ldapAttribute.getByteValue();

						// Se eliminan los 5 primeros caracteres
						String aux = new String(crlByteArray);
						aux = aux.substring(NumberConstants.INT_5, aux.length());

						// Es necesario convertir la CRL de HEX a BIN.
						crlByteArray = Hex.decodeHex(aux);

					}

				} else {

					LOGGER.debug(Language.getResIntegraTsl(ILogTslConstant.UTILS_LDAP_003));
					crlByteArray = ldapAttribute.getByteValue();

				}

			} else {

				LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.UTILS_LDAP_004));

			}

		} catch (LDAPException e) {
			throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_LDAP_005), e);
		} catch (DecoderException e) {
			throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UTILS_LDAP_005), e);
		}

		return crlByteArray;

	}

	/**
	 * Auxiliar method that realizes the connection with the LDAP.
	 * @param ldapConnection Parameter that represents the ldap connection manager.
	 * @param urlServer {@link String} that represents the URL to the LDAP Server.
	 * @param defaultPort Default port to use in the LDAP connection if it is not specified in the URL server.
	 * @throws CommonUtilsException In case of some error connecting with the LDAP.
	 */
	private static void makeConnectionWithLDAP(LDAPConnection ldapConnection, String urlServer, int defaultPort) throws CommonUtilsException {

		try {
			ldapConnection.connect(urlServer, defaultPort);
		} catch (LDAPException e) {
		    // Relanzamos la excepción.
			throw new CommonUtilsException(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_LDAP_000, new Object[ ] { urlServer, defaultPort }), e);
		}

	}

	/**
	 * This method determines whether a given URI scheme is LDAP.
	 * @param uriString String representation of the URI to analyze.
	 * @return <i>true</i> if the scheme of the URI is LDAP, otherwise <i>false</i>.
	 */
	public static boolean isUriOfSchemeLDAP(String uriString) {

		boolean result = false;

		if (!UtilsStringChar.isNullOrEmptyTrim(uriString)) {

			try {

				URI uri = new URI(uriString);
				result = isUriOfSchemeLDAP(uri);

			} catch (URISyntaxException e) {
				result = false;
			}

		}

		return result;

	}

	/**
	 * This method determines whether a given URI scheme is LDAP.
	 * @param uri Representation of the URI to analyze.
	 * @return <i>true</i> if the scheme of the URI is LDAP, otherwise <i>false</i>.
	 */
	public static boolean isUriOfSchemeLDAP(URI uri) {

		boolean result = false;

		if (uri != null) {

			String scheme = uri.getScheme();
			if (!UtilsStringChar.isNullOrEmptyTrim(scheme) && scheme.equalsIgnoreCase(LDAP_SCHEME)) {
				result = true;
			}

		}

		return result;

	}

	/**
	 * Gets the first component value from a URI LDAP.
	 * @param uriLdapString URI LDAP.
	 * @return the first component value from a URI LDAP, or <code>null</code>
	 * if was not possible to extract.
	 */
	public static String extractFirstComponentFromURIldap(String uriLdapString) {

		String result = null;

		if (!UtilsStringChar.isNullOrEmptyTrim(uriLdapString) && isUriOfSchemeLDAP(uriLdapString)) {

			String tmp = null;

			// Quitamos al información de los parámetros de la URL.
			int questionMarkPosition = uriLdapString.indexOf(UtilsStringChar.SYMBOL_QUESTION_MARK);
			if (questionMarkPosition > 0) {
				tmp = uriLdapString.substring(0, questionMarkPosition);
			} else {
				tmp = uriLdapString;
			}

			// Nos quedamos con la ruta dentro del LDAP.
			tmp = tmp.substring(tmp.lastIndexOf(UtilsStringChar.SYMBOL_SLASH) + 1);

			// Nos quedamos con los caracteres posteriores al '=' y anteriores
			// a la posición de la ',';
			int equalPosition = tmp.indexOf(UtilsStringChar.SYMBOL_EQUAL);
			if (equalPosition > 0 && tmp.length() > equalPosition + 1) {

				tmp = tmp.substring(equalPosition + 1);
				int commaPosition = tmp.indexOf(UtilsStringChar.SYMBOL_COMMA);
				if (commaPosition > 0) {
					result = tmp.substring(0, commaPosition);
				} else {
					result = tmp;
				}

			}

		}

		return result;

	}

	/**
	 * <p>Class that implements a socket that is to be used in an LDAPConnection.</p>
	 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
	 * @version 1.0, 08/11/2018.
	 */
	private class LDAPSocket implements LDAPSocketFactory {

		/**
		 * Attribute that represents the SocketTimeOut value in milliseconds.
		 */
		private int timeOut = 0;

		/**
		 * Constructor method for the class LDAPSocket.java.
		 * @param connectionTimeout Parameter that represents the timeout value in milliseconds.
		 */
		LDAPSocket(int connectionTimeout) {
			this.timeOut = connectionTimeout;
		}

		/**
		 * {@inheritDoc}
		 * @see com.novell.ldap.LDAPSocketFactory#createSocket(java.lang.String, int)
		 */
		public Socket createSocket(String host, int port) throws IOException {
			SocketAddress sockaddr = new InetSocketAddress(host, port);
			Socket skt = new Socket();
			skt.connect(sockaddr, timeOut);
			return skt;
		}

	}
}
