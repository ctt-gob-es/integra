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
 * <b>File:</b><p>es.gob.afirma.signature.SignerConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants related to the properties file used by interface {@link es.gob.afirma.signature.Signer}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * <b>Date:</b><p>30/07/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 30/07/2015.
 */
package es.gob.afirma.signature;

/** 
 * <p>Interface that defines all the constants related to the properties file used by interface {@link es.gob.afirma.signature.Signer}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 30/07/2015.
 */
public interface SignerConstants {

    /**
     *  Constant attribute that identifies the key with the certificate validation level.
     */
    String KEY_CERTIFICATE_VALIDATION_LEVEL = "CERTIFICATE_VALIDATION_LEVEL";

    /**
     * Constant attribute that identifies the key with the identifier of the client application used for the communication with TS@.
     */
    String KEY_TSA_APP_ID = "TSA_APP_ID";

    /**
     * Constant attribute that identifies the key with the communication type used to obtain the timestamp from TS@.
     */
    String KEY_TSA_COMMUNICATION_TYPE = "TSA_COMMUNICATION_TYPE";

    /**
     * Constant attribute that identifies the key with the type of the timestamp to request to TS@.
     */
    String KEY_TSA_TIMESTAMP_TYPE = "TSA_TIMESTAMP_TYPE";

}
