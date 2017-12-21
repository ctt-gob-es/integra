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
 * <b>File:</b><p>es.gob.afirma.ocsp.IOCSPConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants related to the communication with an OCSP server to validate certificates.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/05/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 14/05/2015.
 */
package es.gob.afirma.ocsp;

/**
 * <p>Interface that defines all the constants related to the communication with an OCSP server to validate certificates.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 14/05/2015.
 */
public interface IOCSPConstants {

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the timeout for the communication with the OCSP responder, in milliseconds.
     */
    String KEY_OCSP_TIMEOUT = "OCSP_TIMEOUT";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the path to the trusted keystore for secure connections.
     */
    String KEY_OCSP_TRUSTEDSTORE_PATH = "OCSP_TRUSTEDSTORE_PATH";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the password of the trusted keystore for secure connections.
     */
    String KEY_OCSP_TRUSTEDSTORE_PASSWORD = "OCSP_TRUSTEDSTORE_PASSWORD";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the indicator to use the client authentication for HTTPS communication, or not.
     */
    String KEY_OCSP_HTTPS_USE_AUTH_CLIENT = "OCSP_HTTPS_USE_AUTH_CLIENT";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the path of the keystore which contains the certificate used to the client authentication for the HTTPS communication.
     */
    String KEY_OCSP_HTTPS_KEYSTORE_PATH = "OCSP_HTTPS_KEYSTORE_PATH";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the type of the keystore which contains the certificate used to the client authentication for the HTTPS communication.
     */
    String KEY_OCSP_HTTPS_KEYSTORE_TYPE = "OCSP_HTTPS_KEYSTORE_TYPE";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the password of the keystore which contains the certificate used to the client authentication for the HTTPS communication.
     */
    String KEY_OCSP_HTTPS_KEYSTORE_PASSWORD = "OCSP_HTTPS_KEYSTORE_PASSWORD";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the indicator to use <code>GET</code> for the communication with OCSP responder, or <code>POST</code>.
     */
    String KEY_OCSP_USE_GET = "OCSP_USE_GET";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the URL of the OCSP responder.
     */
    String KEY_OCSP_URL = "OCSP_URL";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the path of the keystore with the issuers of the certificates to validate against an OCSP server.
     */
    String KEY_OCSP_ISSUER_KEYSTORE_PATH = "OCSP_ISSUER_KEYSTORE_PATH";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the type of the keystore with the
     * OCSP server.
     */
    String KEY_OCSP_ISSUER_KEYSTORE_TYPE = "OCSP_ISSUER_KEYSTORE_TYPE";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the password of the keystore with the issuers of the certificates to validate against an OCSP server.
     */
    String KEY_OCSP_ISSUER_KEYSTORE_PASSWORD = "OCSP_ISSUER_KEYSTORE_PASSWORD";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the path of the certificate used for the OCSP responder to sign the OCSP responses.
     */
    String KEY_OCSP_RESPONSE_CERTIFICATE_PATH = "OCSP_RESPONSE_CERTIFICATE_PATH";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the indicator to sign the OCSP request (true) or not (false).
     */
    String KEY_OCSP_SIGN_REQUEST = "OCSP_SIGN_REQUEST";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the path of the keystore which contains the certificate used to sign the OCSP request.
     */
    String KEY_OCSP_REQUEST_KEYSTORE_PATH = "OCSP_REQUEST_KEYSTORE_PATH";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the type of the keystore which contains the certificate used to sign the OCSP request.
     */
    String KEY_OCSP_REQUEST_KEYSTORE_TYPE = "OCSP_REQUEST_KEYSTORE_TYPE";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the password of the keystore which contains the certificate used to sign the OCSP request.
     */
    String KEY_OCSP_REQUEST_KEYSTORE_PASSWORD = "OCSP_REQUEST_KEYSTORE_PASSWORD";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the alias of the private key used to sign the OCSP request.
     */
    String KEY_OCSP_REQUEST_PRIVATE_KEY_ALIAS = "OCSP_REQUEST_PRIVATE_KEY_ALIAS";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the password of the private key used to sign the OCSP request.
     */
    String KEY_OCSP_REQUEST_PRIVATE_KEY_PASSWORD = "OCSP_REQUEST_PRIVATE_KEY_PASSWORD";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the properties related to the communication with an
     * OCSP server with the identifier of the client application for the OCSP responder.
     */
    String KEY_OCSP_APP_ID = "OCSP_APP_ID";

}
