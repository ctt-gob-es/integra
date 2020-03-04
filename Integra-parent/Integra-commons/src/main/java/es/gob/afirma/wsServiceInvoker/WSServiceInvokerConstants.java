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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants related to the invocation of @Firma and eVisor services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 04/03/2020.
 */
package es.gob.afirma.wsServiceInvoker;

/**
 * <p>Interface that defines all the constants related to the invocation of @Firma services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 04/03/2020.
 */
public interface WSServiceInvokerConstants {

    /**
     * Constant attribute that identifies the common prefix of the keys defined on the properties file where to configure the invoke of @Firma and eVisor
     * web services for commons properties.
     */
    String COM_PROPERTIE_HEADER = "com";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the end point where the web services are deployed.
     */
    String WS_ENDPOINT_PROPERTY = "endPoint";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the path of the web services.
     */
    String WS_SRV_PATH_PROPERTY = "servicePath";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the path to the trusted keystore for secure connections.
     */
    String WS_TRUSTED_STORE_PROP = "trustedstorePath";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the password of the trusted keystore for secure connections.
     */
    String WS_TRUSTED_STOREPASS_PROP = "trustedstorepassword";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the connection and request timeout for the web service, in milliseconds.
     */
    String WS_CALL_TIMEOUT_PROP = "callTimeout";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the authorization method used to secure the SOAP requests to invoke the web service.
     */
    String WS_AUTHORIZATION_METHOD_PROP = "authorizationMethod";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the authorization method used to secure the SOAP requests to invoke the web service.
     */
    String TSA__USER_WS_AUTHORIZATION_METHOD_PROP = "UserNameToken";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the authorization method used to secure the SOAP requests to invoke the web service.
     */
    String TSA_CERTIFICATE_WS_AUTHORIZATION_METHOD_PROP = "X509CertificateToken";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the authorization method used to secure the SOAP requests to invoke the web service.
     */
    String TSA_SAML_AUTHORIZATION_METHOD_PROP = "SAMLToken";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the user name or the alias of the certificate defined for the authorization method used to secure the SOAP requests to invoke the web service.
     */
    String WS_AUTHORIZ_METHOD_USER_PROP = "user";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the user name or the alias of the certificate defined for the authorization method used to secure the SOAP requests to invoke the web service.
     */
    String TSA_WS_AUTHORIZ_METHOD_USER_PROP = "userName";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the user password or the password of the private key of the certificate defined for the authorization method used to secure the SOAP requests
     *  to invoke the web service.
     */
    String WS_AUTHORIZATION_METHOD_PASS_PROP = "password";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the user password defined for the authorization method used to secure the SOAP requests
     *  to invoke the web service.
     */
    String TSA_WS_AUTHORIZATION_METHOD_PASS_PROP = "userPassword";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the password of the private key of the certificate defined for the authorization method used to secure the SOAP requests
     *  to invoke the web service.
     */
    String TSA_WS_AUTHORIZATION_METHOD_KEYSTOREPASSWORD_PROP = "keystorePassword";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the password of the private key of the certificate defined for the authorization method used to secure the SOAP requests
     *  to invoke the web service.
     */
    String TSA_AUTHORIZATION_METHOD_PRIVATEKEYPASSWORD_PROP = "privateKeyPassword";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the user password type or the password type of the private key of the certificate defined for the authorization method used to secure the SOAP requests
     *  to invoke the web service.
     */
    String WS_AUTHORIZATION_METHOD_PASS_TYPE_PROP = "passwordType";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the path of the keystore with the certificates used to sign the requests.
     */
    String WS_AUTHORIZATION_METHOD_USERKEYSTORE_PROP = "userKeystore";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the path of the keystore with the certificates used to sign the requests.
     */
    String TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PROP = "keystorePath";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the SAML method used to sign the requests.
     */
    String TSA_SAML_AUTHORIZATION_METHOD_METHOD_PROP = "method";    
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the name of certificate to use.
     */
    String TSA_WS_AUTHORIZATION_METHOD_CERTNAME_PROP = "privateKeyAlias";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the password of the keystore with the certificates used to sign the requests.
     */
    String WS_AUTHORIZATION_METHOD_USERKEYSTORE_PASS_PROP = "userKeystorePassword";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the password of the keystore with the certificates used to sign the requests.
     */
    String TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_PASS_PROP = "keystorePassword";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the type of the keystore with the certificates used to sign the requests.
     */
    String WS_AUTHORIZATION_METHOD_USERKEYSTORE_TYPE_PROP = "userKeystoreType";
    
    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of TS@ web services with
     *  the type of the keystore with the certificates used to sign the requests.
     */
    String TSA_WS_AUTHORIZATION_METHOD_USERKEYSTORE_TYPE_PROP = "keystoreType";

    /**
     *  Constant attribute that identifies the application context to the classes used to execute the request of the web services.
     */
    String APPLICATION_NAME = "applicationName";

    /**
     *  Constant attribute that identifies the service to call for the classes used to execute the request of the web services for @Firma.
     */
    String AFIRMA_SERVICE = "afirmaService";
    
    /**
     *  Constant attribute that identifies the service to call for the classes used to execute the request of the web services for TSA@.
     */
    String TSA_SERVICE = "tsaService";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the secure mode for the communication with the web services.
     */
    String SECURE_MODE_PROPERTY = "secureMode";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the indication for validating the responses.
     */
    String RESPONSE_VALIDATE_PROPERTY = "validate";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     *  the alias of the certificate used to sign the responses.
     */
    String RESPONSE_ALIAS_CERT_PROPERTY = "certificateAlias";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with the
     * prefix used in the response of the web services.
     */
    String PREFIX_RESPONSE_PROPERTY = "response";

    /**
     * Constant attribute that identifies the SAML key defined on the properties file where to configure the invoke of web services with the
     * prefix used in the response of the web services.
     */
    String PREFIX_RESPONSE_SAML_PROPERTY = "SAML";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with the
     * indication to use the certificates validation responses cache.
     */
    String WS_CERTIFICATES_CACHE_USE_PROP = "com.certificatesCache.use";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     * the entries number of the certificates validation responses cache.
     */
    String WS_CERTIFICATES_CACHE_ENTRIES_PROP = "com.certificatesCache.entries";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the invoke of @Firma and eVisor web services with
     * the life time of the certificates validation responses cache, in seconds.
     */
    String WS_CERTIFICATES_CACHE_LIFETIME_PROP = "com.certificatesCache.lifeTime";
}
