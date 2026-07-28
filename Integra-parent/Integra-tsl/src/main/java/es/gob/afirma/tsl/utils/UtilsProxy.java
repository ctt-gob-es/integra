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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsProxy.java.</p>
 * <b>Description:</b><p>Utility class responsible for loading the properties from data base
 * to obtain the data necessary to establish a connection via PROXY. Besides this load will be done in the initialization
 * of the platform, and this class is responsible for setting the data in the virtual machine.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 18/04/2022.
 */
package es.gob.afirma.tsl.utils;

import java.net.Authenticator;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.StringTokenizer;

import org.apache.http.HttpHost;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.HttpRequestBase;
import es.gob.afirma.tsl.logger.Logger;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.constants.IOperationModeIdConstants;
import es.gob.afirma.tsl.i18n.ILogTslConstant;

/** 
 * <p>Utility class responsible for loading the properties from data base
 * to obtain the data necessary to establish a connection via PROXY. Besides this load will be done in the initialization
 * of the platform, and this class is responsible for setting the data in the virtual machine.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 18/04/2022.
 */
public final class UtilsProxy {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(UtilsProxy.class);

    /**
     * Constant attribute that represents the system property key 'proxySet'.
     */
    private static final String SYSPROP_PROXYSET = "proxySet";

    /**
     * Constant attribute that represents the system property key 'http.proxyHost'.
     */
    private static final String SYSPROP_HTTP_PROXYHOST = "http.proxyHost";

    /**
     * Constant attribute that represents the system property key 'http.proxyPort'.
     */
    private static final String SYSPROP_HTTP_PROXYPORT = "http.proxyPort";

    /**
     * Constant attribute that represents the system property key 'http.proxyUser'.
     */
    private static final String SYSPROP_HTTP_PROXYUSER = "http.proxyUser";

    /**
     * Constant attribute that represents the system property key 'http.proxyPassword'.
     */
    private static final String SYSPROP_HTTP_PROXYPASSWORD = "http.proxyPassword";

    /**
     * Constant attribute that represents the system property key 'http.auth.ntlm.username'.
     */
    private static final String SYSPROP_HTTP_AUTH_NTLM_USERNAME = "http.auth.ntlm.username";

    /**
     * Constant attribute that represents the system property key 'http.auth.ntlm.password'.
     */
    private static final String SYSPROP_HTTP_AUTH_NTLM_PASSWORD = "http.auth.ntlm.password";

    /**
     * Constant attribute that represents the system property key 'http.auth.ntlm.domain'.
     */
    private static final String SYSPROP_HTTP_AUTH_NTLM_DOMAIN = "http.auth.ntlm.domain";

    /**
     * Constant attribute that represents the system property key 'http.auth.ntlm.workstation'.
     */
    private static final String SYSPROP_HTTP_AUTH_NTLM_WORKSTATION = "http.auth.ntlm.workstation";

    /**
     * Constant attribute that represents the system property key 'http.auth.ntlm.host'.
     */
    private static final String SYSPROP_HTTP_AUTH_NTLM_HOST = "http.auth.ntlm.host";

    /**
     * Constant attribute that represents the system property key 'http.nonProxyHosts'.
     */
    private static final String SYSPROP_HTTP_NONPROXYHOSTS = "http.nonProxyHosts";

    /**
     * Constant attribute that represents the system property key 'https.proxyHost'.
     */
    private static final String SYSPROP_HTTPS_PROXYHOST = "https.proxyHost";

    /**
     * Constant attribute that represents the system property key 'https.proxyPort'.
     */
    private static final String SYSPROP_HTTPS_PROXYPORT = "https.proxyPort";

    /**
     * Constant attribute that represents the system property key 'https.proxyUser'.
     */
    private static final String SYSPROP_HTTPS_PROXYUSER = "https.proxyUser";

    /**
     * Constant attribute that represents the system property key 'https.proxyPassword'.
     */
    private static final String SYSPROP_HTTPS_PROXYPASSWORD = "https.proxyPassword";

    /**
     * Constant attribute that represents the system property key 'https.auth.ntlm.username'.
     */
    private static final String SYSPROP_HTTPS_AUTH_NTLM_USERNAME = "https.auth.ntlm.username";

    /**
     * Constant attribute that represents the system property key 'https.auth.ntlm.password'.
     */
    private static final String SYSPROP_HTTPS_AUTH_NTLM_PASSWORD = "https.auth.ntlm.password";

    /**
     * Constant attribute that represents the system property key 'https.auth.ntlm.domain'.
     */
    private static final String SYSPROP_HTTPS_AUTH_NTLM_DOMAIN = "https.auth.ntlm.domain";

    /**
     * Constant attribute that represents the system property key 'https.auth.ntlm.workstation'.
     */
    private static final String SYSPROP_HTTPS_AUTH_NTLM_WORKSTATION = "https.auth.ntlm.workstation";

    /**
     * Constant attribute that represents the system property key 'https.auth.ntlm.host'.
     */
    private static final String SYSPROP_HTTPS_AUTH_NTLM_HOST = "https.auth.ntlm.host";

    /**
     * Constant attribute that represents the system property key 'https.nonProxyHosts'.
     */
    private static final String SYSPROP_HTTPS_NONPROXYHOSTS = "https.nonProxyHosts";

    /**
     * Attribute that indicates whether the configuration data loading for the PROXY has been initialized correctly (<code>true</code>) or not (<code>false</code>).
     */
    private static boolean proxyConfigurationInitialized = false;

    /**
     * Attribute that represents the operational mode for the proxy: {@link IOperationModeIdConstants}.
     */
    private static int proxyOperational = -1;

    /**
     * Attribute that represents the value for host to use in the proxy.
     */
    private static String proxyHost = null;

    /**
     * Attribute that represents the value for port to use in the proxy.
     */
    private static int proxyPort = -1;

    /**
     * Attribute that represents the value for authentication user to use in the proxy.
     */
    private static String proxyUserName = null;

    /**
     * Attribute that represents the value for authentication password to use in the proxy.
     */
    private static String proxyUserPass = null;

    /**
     * Attribute that represents the value for the NTLM domain to use in the proxy.
     */
    private static String proxyDomain = null;

    /**
     * Attribute that represents the value for the NTLM WorkStation to use in the proxy.
     */
    private static String proxyWorkstation = null;

    /**
     * Attribute that represents the value for host to use in the secure proxy.
     */
    private static String proxySecureHost = null;

    /**
     * Attribute that represents the operational mode for the secure proxy: {@link IOperationModeIdConstants}.
     */
    private static int proxySecureOperational = -1;

    /**
     * Attribute that represents the value for port to use in the secure proxy.
     */
    private static int proxySecurePort = -1;

    /**
     * Attribute that represents the value for authentication user to use in the secure proxy.
     */
    private static String proxySecureUserName = null;

    /**
     * Attribute that represents the value for authentication password to use in the secure proxy.
     */
    private static String proxySecureUserPass = null;

    /**
     * Attribute that represents the value for the NTLM domain to use in the secure proxy.
     */
    private static String proxySecureDomain = null;

    /**
     * Attribute that represents the value for the NTLM WorkStation to use in the proxy.
     */
    private static String proxySecureWorkstation = null;

    /**
     * Attribute that represents a list of addressees that must be avoid to use with proxy.
     */
    private static String dontUseProxyAddresses = null;

    /**
     * Attribute that represents the value for the property <code>proxy.checkLocalAddress</code> in
     * the database.
     */
    private static boolean checkLocalAddres = false;

    /**
     * Constructor method for the class UtilsProxy.java.
     */
    private UtilsProxy() {
	super();
    }

    /**
     * Method that loads the configuration where the properties which configure the PROXY to use are defined.
     * Also sets this configuration in java static properties.
     */
    public static synchronized void loadProxyConfiguration() {

	// Inicialmente consideramos que el proxy no ha sido inicializado.
	proxyConfigurationInitialized = false;

	// // Establecemos la configuración Java por defecto para el proxy.
	setUpProxyConfigurationInJava();

    }

    /**
     * Checks and set the host and port for the proxy.
     */
    private static void checkAndSetHostAndPortValuesForProxy() {

	switch (proxyOperational) {
	    case IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE:
	    case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
	    case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
		if (UtilsStringChar.isNullOrEmpty(proxyHost) || proxyPort <= 0) {
		    LOGGER.error(Language.getFormatResIntegraTsl(ILogTslConstant.UPR_LOG000, new Object[ ] { proxyHost, proxyPort }));
		    proxyOperational = IOperationModeIdConstants.ID_NONE_INTVALUE;
		    checkAndSetHostAndPortValuesForProxy();
		}
		break;

	    default:
		proxyHost = null;
		proxyPort = -1;
		proxyUserName = null;
		proxyUserPass = null;
		proxyDomain = null;
		proxyWorkstation = null;
		break;
	}

    }

    /**
     * Checks and set the host and port for the secure proxy.
     */
    private static void checkAndSetHostAndPortValuesForSecureProxy() {

	switch (proxySecureOperational) {
	    case IOperationModeIdConstants.ID_NONE_INTVALUE:
		proxySecureHost = null;
		proxySecurePort = -1;
		proxySecureUserName = null;
		proxySecureUserPass = null;
		proxySecureDomain = null;
		proxySecureWorkstation = null;
		break;
	    case IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE:
	    case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
	    case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
		if (UtilsStringChar.isNullOrEmpty(proxySecureHost) || proxySecurePort <= 0) {
		    LOGGER.error(Language.getFormatResIntegraTsl(ILogTslConstant.UPR_LOG001, new Object[ ] { proxySecureHost, proxySecurePort }));
		    proxySecureOperational = IOperationModeIdConstants.ID_NONE_INTVALUE;
		    checkAndSetHostAndPortValuesForSecureProxy();
		}
		break;
	    default:
		break;
	}

    }

    /**
     * Checks and set the user and password for the proxy.
     */
    private static void checkAndSetUserAndPasswordForProxy() {

	switch (proxyOperational) {
	    case IOperationModeIdConstants.ID_NONE_INTVALUE:
		break;
	    case IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE:
		proxyUserName = null;
		proxyUserPass = null;
		proxyDomain = null;
		proxyWorkstation = null;
		break;
	    case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
	    case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
		if (UtilsStringChar.isNullOrEmpty(proxyUserName) || UtilsStringChar.isNullOrEmpty(proxyUserPass)) {
		    LOGGER.error(Language.getFormatResIntegraTsl(ILogTslConstant.UPR_LOG002, new Object[ ] { proxyUserName, proxyUserPass }));
		    proxyOperational = IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE;
		    checkAndSetUserAndPasswordForProxy();
		}
		break;
	    default:
		break;
	}

    }

    /**
     * Checks and set the user and password for the secure proxy.
     */
    private static void checkAndSetUserAndPasswordForSecureProxy() {

	switch (proxySecureOperational) {
	    case IOperationModeIdConstants.ID_NONE_INTVALUE:
		break;
	    case IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE:
		proxySecureUserName = null;
		proxySecureUserPass = null;
		proxySecureDomain = null;
		proxySecureWorkstation = null;
		break;
	    case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
	    case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
		if (UtilsStringChar.isNullOrEmpty(proxySecureUserName) || UtilsStringChar.isNullOrEmpty(proxySecureUserPass)) {
		    LOGGER.error(Language.getFormatResIntegraTsl(ILogTslConstant.UPR_LOG003, new Object[ ] { proxySecureUserName, proxySecureUserPass }));
		    proxySecureOperational = IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE;
		    checkAndSetUserAndPasswordForSecureProxy();
		}
		break;
	    default:
		break;
	}

    }

    /**
     * Checks and set the domain and workstation (NTLM) for the proxy.
     */
    private static void checkAndSetDomainAndWorkStationForProxy() {

	switch (proxyOperational) {
	    case IOperationModeIdConstants.ID_NONE_INTVALUE:
	    case IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE:
		break;
	    case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
		proxyDomain = null;
		proxyWorkstation = null;
		break;
	    case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
		if (UtilsStringChar.isNullOrEmpty(proxyDomain) || UtilsStringChar.isNullOrEmpty(proxyWorkstation)) {
		    LOGGER.error(Language.getFormatResIntegraTsl(ILogTslConstant.UPR_LOG004, new Object[ ] { proxyDomain, proxyWorkstation }));
		    proxyOperational = IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE;
		    checkAndSetDomainAndWorkStationForProxy();
		}
		break;
	    default:
		break;
	}

    }

    /**
     * Checks and set the domain and workstation (NTLM) for the secure proxy.
     */
    private static void checkAndSetDomainAndWorkStationForSecureProxy() {

	switch (proxySecureOperational) {
	    case IOperationModeIdConstants.ID_NONE_INTVALUE:
	    case IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE:
		break;
	    case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
		proxySecureDomain = null;
		proxySecureWorkstation = null;
		break;
	    case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
		if (UtilsStringChar.isNullOrEmpty(proxySecureDomain) || UtilsStringChar.isNullOrEmpty(proxySecureWorkstation)) {
		    LOGGER.error(Language.getFormatResIntegraTsl(ILogTslConstant.UPR_LOG005, new Object[ ] { proxySecureDomain, proxySecureWorkstation }));
		    proxySecureOperational = IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE;
		    checkAndSetDomainAndWorkStationForProxy();
		}
		break;
	    default:
		break;
	}

    }

    /**
     * Method that sets the default properties in the java virtual machine for the proxy.
     */
    public static synchronized void setUpProxyConfigurationInJava() {

	boolean disableProxy = false;

	// Si la configuración del proxy ha sido inicializada...
	if (proxyConfigurationInitialized) {

	    // Si el proxy está configurado ...
	    if (proxyOperational != IOperationModeIdConstants.ID_NONE_INTVALUE) {

		System.setProperty(SYSPROP_PROXYSET, Boolean.TRUE.toString());
		// setUpProxyConfigurationInJavaNotSecuredProxy();

	    }

	    // Si el proxy seguro está configurado está configurado...
	    if (proxySecureOperational != IOperationModeIdConstants.ID_NONE_INTVALUE) {

		System.setProperty(SYSPROP_PROXYSET, Boolean.TRUE.toString());
		// setUpProxyConfigurationInJavaSecuredProxy();

	    }

	    // Si ninguno está configurado, lo deshabilitamos.
	    disableProxy = proxyOperational == IOperationModeIdConstants.ID_NONE_INTVALUE && proxySecureOperational == IOperationModeIdConstants.ID_NONE_INTVALUE;

	}
	// Si no, lo deshabilitamos.
	else {

	    disableProxy = true;

	}

	// Si hay que deshabilitar el proxy, limpiamos las propiedades del
	// sistema.
	if (disableProxy) {
	    System.setProperty(SYSPROP_PROXYSET, Boolean.FALSE.toString());
	    Authenticator.setDefault(null);
	    System.setProperty(SYSPROP_HTTP_PROXYHOST, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_PROXYPORT, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_PROXYUSER, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_PROXYPASSWORD, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_AUTH_NTLM_USERNAME, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_AUTH_NTLM_PASSWORD, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_AUTH_NTLM_DOMAIN, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_AUTH_NTLM_WORKSTATION, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_AUTH_NTLM_HOST, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTP_NONPROXYHOSTS, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_PROXYHOST, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_PROXYPORT, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_PROXYUSER, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_PROXYPASSWORD, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_USERNAME, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_PASSWORD, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_DOMAIN, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_WORKSTATION, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_HOST, UtilsStringChar.EMPTY_STRING);
	    System.setProperty(SYSPROP_HTTPS_NONPROXYHOSTS, UtilsStringChar.EMPTY_STRING);
	}

    }

    /**
     * Method that sets the default properties in the java virtual machine for the non secured proxy.
     */

    /**
     * Method that sets the default properties in the java virtual machine for the secured proxy.
     */
    // private static void setUpProxyConfigurationInJavaSecuredProxy() {
    //
    // // Establecemos el host y puerto.
    // System.setProperty(SYSPROP_HTTPS_PROXYHOST, proxySecureHost);
    // System.setProperty(SYSPROP_HTTPS_PROXYPORT,
    // String.valueOf(proxySecurePort));
    //
    // switch (proxyOperational) {
    // case IOperationModeIdConstants.ID_NONE_AUTHENTICATION_INTVALUE:
    // System.setProperty(SYSPROP_HTTPS_PROXYUSER,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_PROXYPASSWORD,
    // UtilsStringChar.EMPTY_STRING);
    // Authenticator.setDefault(null);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_USERNAME,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_PASSWORD,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_DOMAIN,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_WORKSTATION,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_HOST,
    // UtilsStringChar.EMPTY_STRING);
    // break;
    //
    // case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
    // System.setProperty(SYSPROP_HTTPS_PROXYUSER, proxySecureUserName);
    // System.setProperty(SYSPROP_HTTPS_PROXYPASSWORD, proxySecureUserPass);
    // Authenticator.setDefault(new CredentialsManager(proxySecureUserName,
    // proxySecureUserPass));
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_USERNAME,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_PASSWORD,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_DOMAIN,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_WORKSTATION,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_HOST,
    // UtilsStringChar.EMPTY_STRING);
    // break;
    //
    // case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
    // System.setProperty(SYSPROP_HTTPS_PROXYUSER,
    // UtilsStringChar.EMPTY_STRING);
    // System.setProperty(SYSPROP_HTTPS_PROXYPASSWORD,
    // UtilsStringChar.EMPTY_STRING);
    // Authenticator.setDefault(new CredentialsManager(proxySecureUserName,
    // proxySecureUserPass));
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_USERNAME,
    // proxySecureUserName);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_PASSWORD,
    // proxySecureUserPass);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_DOMAIN, proxySecureDomain);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_WORKSTATION,
    // proxySecureWorkstation);
    // System.setProperty(SYSPROP_HTTPS_AUTH_NTLM_HOST, proxySecureHost);
    // break;
    //
    // default:
    // break;
    // }
    //
    // // Si hay una lista de direcciones a las que no se les debe
    // // aplicar el proxy...
    // if (UtilsStringChar.isNullOrEmptyTrim(dontUseProxyAddresses)) {
    //
    // System.setProperty(SYSPROP_HTTPS_NONPROXYHOSTS,
    // UtilsStringChar.EMPTY_STRING);
    //
    // } else {
    //
    // System.setProperty(SYSPROP_HTTPS_NONPROXYHOSTS, dontUseProxyAddresses);
    //
    // }
    //
    // }

    /**
     * Method that returns the proxy configuration needed in a {@link HttpHost} object.
     * @param credentials Parameter that represents the HTTP client credentials that are modified if needed.
     * @param method Parameter that represents the protocol.
     * @param path Parameter that represents the path.
     * @return a HttpHost with proxy configuration or <code>null</code> if not needed.
     */
    // public static HttpHost
    // setUpProxyConfigurationInHttpClient(CredentialsProvider credentials,
    // HttpRequestBase method, String path) {
    //
    // HttpHost result = null;
    //
    // // Si la configuración del proxy está inicializada y la URL no está en
    // // la
    // // lista de no usar con proxy, y no se considera ruta local...
    // if (proxyConfigurationInitialized && !isHostURLInNonProxyList(path) &&
    // !isLocalPath(path)) {
    //
    // String protocol = method.getURI().getScheme();
    //
    // // Si es HTTP...
    // if (UtilsHTTP.HTTP_SCHEME.equalsIgnoreCase(protocol)) {
    //
    // // Si hay configuración proxy establecida...
    // if (proxyOperational != IOperationModeIdConstants.ID_NONE_INTVALUE) {
    // result = setUpProxyConfigurationInHttpClientNonSecuredProxy(credentials,
    // path);
    // }
    //
    // }
    // // Si es HTTPS...
    // else {
    //
    // // Si hay configuración proxy establecida...
    // if (proxySecureOperational != IOperationModeIdConstants.ID_NONE_INTVALUE)
    // {
    // result = setUpProxyConfigurationInHttpClientSecuredProxy(credentials,
    // path);
    // }
    //
    // }
    //
    // }
    //
    // return result;
    //
    // }

    // /**
    // * Method that returns the proxy configuration needed in a {@link
    // HttpHost} object for HTTP connection.
    // * @param credentials Parameter that represents the HTTP client
    // credentials that are modified if needed.
    // * @param path Parameter that represents the path.
    // * @return a HttpHost with proxy configuration or <code>null</code> if not
    // needed.
    // */
    // private static HttpHost
    // setUpProxyConfigurationInHttpClientNonSecuredProxy(CredentialsProvider
    // credentials, String path) {
    //
    // HttpHost result = new HttpHost(proxyHost, proxyPort);
    //
    // switch (proxyOperational) {
    // case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
    // credentials.setCredentials(new AuthScope(proxyHost, proxyPort), new
    // UsernamePasswordCredentials(proxyUserName, proxyUserPass));
    // break;
    //
    // case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
    // credentials.setCredentials(new AuthScope(proxyHost, proxyPort, null), new
    // NTCredentials(proxyUserName, proxyUserPass, proxyWorkstation,
    // proxyDomain));
    // break;
    //
    // default:
    // break;
    // }
    //
    // return result;
    //
    // }

    // /**
    // * Method that returns the proxy configuration needed in a {@link
    // HttpHost} object for HTTPS connection.
    // * @param credentials Parameter that represents the HTTPS client
    // credentials that are modified if needed.
    // * @param path Parameter that represents the path.
    // * @return a HttpHost with proxy configuration or <code>null</code> if not
    // needed.
    // */
    // private static HttpHost
    // setUpProxyConfigurationInHttpClientSecuredProxy(CredentialsProvider
    // credentials, String path) {
    //
    // HttpHost result = new HttpHost(proxySecureHost, proxySecurePort);
    //
    // switch (proxySecureOperational) {
    // case IOperationModeIdConstants.ID_BASIC_AUTHENTICATION_INTVALUE:
    // credentials.setCredentials(new AuthScope(proxySecureHost,
    // proxySecurePort), new UsernamePasswordCredentials(proxySecureUserName,
    // proxySecureUserPass));
    // break;
    //
    // case IOperationModeIdConstants.ID_NTLM_AUTHENTICATION_INTVALUE:
    // credentials.setCredentials(new AuthScope(proxySecureHost,
    // proxySecurePort, null), new NTCredentials(proxySecureUserName,
    // proxySecureUserPass, proxySecureWorkstation, proxySecureDomain));
    // break;
    //
    // default:
    // break;
    // }
    //
    // return result;
    //
    // }

    /**
     * Method that checks whether a path represents a host from the local network (<code>true</code>) or not (<code>false</code>).
     * @param path Parameter that represents the path to check.
     * @return a boolean that indicates whether a path represents a host from the local network (<code>true</code>) or not (<code>false</code>).
     */
    public static boolean isLocalPath(String path) {

	boolean result = false;
	if (checkLocalAddres) {

	    try {

		URI uri = new URI(path);
		InetAddress ia = InetAddress.getByName(uri.getHost());

		result = ia.isAnyLocalAddress() || ia.isLinkLocalAddress() || ia.isLoopbackAddress();
		result = result || ia.isMCLinkLocal() || ia.isMCNodeLocal();
		result = result || ia.isMCOrgLocal() || ia.isMCSiteLocal();
		result = result || ia.isSiteLocalAddress();

	    } catch (URISyntaxException | UnknownHostException e) {
		LOGGER.debug(Language.getFormatResIntegraTsl(ILogTslConstant.UPR_LOG007, new Object[ ] { path }));
	    }

	}

	return result;

    }

    /**
     * Method that checks if proxy configuration is initialized.
     * @return a boolean that indicates if proxy configuration is initialized (<code>true</code>)
     * or not (<code>false</code>).
     */
    public static boolean isProxyConfigurationInitialized() {
	return proxyConfigurationInitialized;
    }

    /**
     * Method that checks whether the specified URL is in the list of non proxy hosts.
     * @param urlString Parameter that represents the URL to check in a string.
     * @return a boolean that indicates whether the specified host is in the list of non proxy hosts.
     */
    public static boolean isHostURLInNonProxyList(String urlString) {

	try {

	    URL url = new URL(urlString);
	    String host = url.getHost();

	    if (UtilsStringChar.isNullOrEmptyTrim(dontUseProxyAddresses) || host == null) {
		return false;
	    }

	    StringTokenizer tokenizer = new StringTokenizer(dontUseProxyAddresses, "|");

	    while (tokenizer.hasMoreTokens()) {
		String pattern = tokenizer.nextToken();
		if (match(pattern, host, false)) {
		    return true;
		}
	    }

	} catch (MalformedURLException e) {

	    LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UPR_LOG008, new Object[ ] { urlString }));

	}

	return false;
    }

    /**
     * Method that matches a string against a pattern.
     * @param pattern Parameter that represents the (non-null) pattern to match against.
     * @param str Parameter that represents the (non-null) string that must be matched against the pattern.
     * @param isCaseSensitive Parameter that indicates if the match considers the sesitive case (true) or not (false).
     * @return a boolean that indicates whether the string matches against the pattern (true) or not (false).
     */
    private static boolean match(String pattern, String str, boolean isCaseSensitive) {

	char[ ] patArr = pattern.toCharArray();
	char[ ] strArr = str.toCharArray();
	int patIdxStart = 0;
	int patIdxEnd = patArr.length - 1;
	int strIdxStart = 0;
	int strIdxEnd = strArr.length - 1;
	char ch;
	boolean containsStar = false;

	for (int i = 0; i < patArr.length; i++) {
	    if (patArr[i] == UtilsStringChar.SYMBOL_ASTERISK) {
		containsStar = true;
		break;
	    }
	}
	if (!containsStar) {

	    // No '*'s, so we make a shortcut
	    if (patIdxEnd != strIdxEnd) {
		return false; // Pattern and string do not have the same size
	    }
	    for (int i = 0; i <= patIdxEnd; i++) {
		ch = patArr[i];
		if (isCaseSensitive && ch != strArr[i]) {
		    return false; // Character mismatch
		}
		if (!isCaseSensitive && Character.toUpperCase(ch) != Character.toUpperCase(strArr[i])) {
		    return false; // Character mismatch
		}
	    }
	    return true; // String matches against pattern
	}
	if (patIdxEnd == 0) {
	    return true; // Pattern contains only '*', which matches anything
	}

	// Process characters before first star
	ch = patArr[patIdxStart];
	while (ch != UtilsStringChar.SYMBOL_ASTERISK && strIdxStart <= strIdxEnd) {
	    if (isCaseSensitive && ch != strArr[strIdxStart]) {
		return false; // Character mismatch
	    }
	    if (!isCaseSensitive && Character.toUpperCase(ch) != Character.toUpperCase(strArr[strIdxStart])) {
		return false; // Character mismatch
	    }
	    patIdxStart++;
	    strIdxStart++;
	    ch = patArr[patIdxStart];
	}
	if (strIdxStart > strIdxEnd) {

	    // All characters in the string are used. Check if only '*'s are
	    // left in the pattern. If so, we succeeded. Otherwise failure.
	    for (int i = patIdxStart; i <= patIdxEnd; i++) {
		if (patArr[i] != UtilsStringChar.SYMBOL_ASTERISK) {
		    return false;
		}
	    }
	    return true;
	}

	// Process characters after last star
	ch = patArr[patIdxEnd];
	while (ch != UtilsStringChar.SYMBOL_ASTERISK && strIdxStart <= strIdxEnd) {
	    if (isCaseSensitive && ch != strArr[strIdxEnd]) {
		return false; // Character mismatch
	    }
	    if (!isCaseSensitive && Character.toUpperCase(ch) != Character.toUpperCase(strArr[strIdxEnd])) {
		return false; // Character mismatch
	    }
	    patIdxEnd--;
	    strIdxEnd--;
	    ch = patArr[patIdxEnd];
	}
	if (strIdxStart > strIdxEnd) {

	    // All characters in the string are used. Check if only '*'s are
	    // left in the pattern. If so, we succeeded. Otherwise failure.
	    for (int i = patIdxStart; i <= patIdxEnd; i++) {
		if (patArr[i] != UtilsStringChar.SYMBOL_ASTERISK) {
		    return false;
		}
	    }
	    return true;
	}

	// process pattern between stars. padIdxStart and patIdxEnd point
	// always to a '*'.
	while (patIdxStart != patIdxEnd && strIdxStart <= strIdxEnd) {
	    int patIdxTmp = -1;

	    for (int i = patIdxStart + 1; i <= patIdxEnd; i++) {
		if (patArr[i] == UtilsStringChar.SYMBOL_ASTERISK) {
		    patIdxTmp = i;
		    break;
		}
	    }
	    if (patIdxTmp == patIdxStart + 1) {

		// Two stars next to each other, skip the first one.
		patIdxStart++;
		continue;
	    }

	    // Find the pattern between padIdxStart & padIdxTmp in str between
	    // strIdxStart & strIdxEnd
	    int patLength = patIdxTmp - patIdxStart - 1;
	    int strLength = strIdxEnd - strIdxStart + 1;
	    int foundIdx = -1;

	    strLoop : for (int i = 0; i <= strLength - patLength; i++) {
		for (int j = 0; j < patLength; j++) {
		    ch = patArr[patIdxStart + j + 1];
		    if (isCaseSensitive && ch != strArr[strIdxStart + i + j]) {
			continue strLoop;
		    }
		    if (!isCaseSensitive && Character.toUpperCase(ch) != Character.toUpperCase(strArr[strIdxStart + i + j])) {
			continue strLoop;
		    }
		}
		foundIdx = strIdxStart + i;
		break;
	    }
	    if (foundIdx == -1) {
		return false;
	    }
	    patIdxStart = patIdxTmp;
	    strIdxStart = foundIdx + patLength;
	}

	// All characters in the string are used. Check if only '*'s are left
	// in the pattern. If so, we succeeded. Otherwise failure.
	for (int i = patIdxStart; i <= patIdxEnd; i++) {
	    if (patArr[i] != UtilsStringChar.SYMBOL_ASTERISK) {
		return false;
	    }
	}
	return true;
    }

    /**
     * Method that returns the proxy configuration needed in a {@link HttpHost} object.
     * @param credentials Parameter that represents the HTTP client credentials that are modified if needed.
     * @param method Parameter that represents the protocol.
     * @param path Parameter that represents the path.
     * @return a HttpHost with proxy configuration or <code>null</code> if not needed.
     */
    public static HttpHost setUpProxyConfigurationInHttpClient(CredentialsProvider credentials, HttpRequestBase method, String path) {

	HttpHost result = null;

	// Si la configuración del proxy está inicializada y la URL no está en
	// la
	// lista de no usar con proxy, y no se considera ruta local...
	if (proxyConfigurationInitialized && !isHostURLInNonProxyList(path) && !isLocalPath(path)) {

	    String protocol = method.getURI().getScheme();

	    // Si es HTTP...
	    if (UtilsHTTP.HTTP_SCHEME.equalsIgnoreCase(protocol)) {

		// Si hay configuración proxy establecida...
		if (proxyOperational != IOperationModeIdConstants.ID_NONE_INTVALUE) {
		    // result =
		    // setUpProxyConfigurationInHttpClientNonSecuredProxy(credentials,
		    // path);
		}

	    }
	    // Si es HTTPS...
	    else {

		// Si hay configuración proxy establecida...
		if (proxySecureOperational != IOperationModeIdConstants.ID_NONE_INTVALUE) {
		    // result =
		    // setUpProxyConfigurationInHttpClientSecuredProxy(credentials,
		    // path);
		}

	    }

	}

	return result;

    }

}
