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
 * <b>File:</b><p>es.gob.afirma.integraFacade.SignatureFormatConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants related to the properties file used by the facade for the invocation of Integr@ services 
 * and @Firma web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2014.
 */
package es.gob.afirma.integraFacade;

/**
 * <p>Interface that defines all the constants related to the properties file used by the facade for the invocation of Integr@ services and @Firma 
 * web services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/11/2014.
 */
public interface IntegraFacadeConstants {

    // /**
    // * Constant attribute that identifies the name of the properties file
    // where to configure the properties related to the services facade.
    // */
    // String INTEGRA_FACADE_PROPERTIES = "integraFacade.properties";

    /**
     *  Constant attribute that identifies the key defined on the properties file where to configure the services facade with the certificate
     *  validation level.
     */
    String KEY_CERTIFICATE_VALIDATION_LEVEL = "CERTIFICATE_VALIDATION_LEVEL";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the services facade with the identifier of the
     * client application used for the communication with TS@.
     */
    String KEY_TSA_APP_ID = "TSA_APP_ID";
    
    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the services facade with the identifier of the
     * client application used for the communication with @firma.
     */
    String KEY_AFIRMA_APP_ID = "AFIRMA_APP_ID";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the services facade with the communication type used
     * to obtain the timestamp from TS@.
     */
    String KEY_TSA_COMMUNICATION_TYPE = "TSA_COMMUNICATION_TYPE";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the services facade with the type of the timestamp
     * to request to TS@.
     */
    String KEY_TSA_TIMESTAMP_TYPE = "TSA_TIMESTAMP_TYPE";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the services facade with the signature type.
     */
    String KEY_FACADE_SIGNATURE_TYPE = "FACADE_SIGNATURE_TYPE";

    /**
     * Constant attribute that identifies the key defined on the properties file where to configure the services facade with the signature algorithm.
     */
    String KEY_FACADE_SIGNATURE_ALGORITHM = "FACADE_SIGNATURE_ALGORITHM";
    
    /**
     * Constant attribute that identifies the keystore location reading from the properties file where to configure the services facade.
     */
    String KEY_WS_KEYSTORE = "WS_KEYSTORE";
    
    /**
     * Constant attribute that identifies the keystore password reading from the properties file where to configure the services facade.
     */
    String KEY_WS_KEYSTORE_PASS = "WS_KEYSTORE_PASS";
    
    /**
     * Constant attribute that identifies the keystore type reading from the properties file where to configure the services facade.
     */
    String KEY_WS_KEYSTORE_TYPE = "WS_KEYSTORE_TYPE";
    
    /**
     * Constant attribute that indicates if not suppported formats are upgraded in afirma.
     */
    String KEY_UPPER_FORMAT_UPGRADE_AFIRMA = "UPPER_FORMAT_UPGRADE_AFIRMA";
    
    /**
     * Constant attribute that indicates if get certificates and keys from HSM in WS.
     */
    String KEY_USE_HSM = "USE_HSM";
      

}
