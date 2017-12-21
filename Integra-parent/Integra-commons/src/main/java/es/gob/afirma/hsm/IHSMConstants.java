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
 * <b>File:</b><p>es.gob.afirma.hsm.IHSMConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants related to the managing of HSMs.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/12/2014.
 */
package es.gob.afirma.hsm;

/** 
 * <p>Interface that defines all the constants related to the managing of HSMs.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/12/2014.
 */
public interface IHSMConstants {

    /**
     * Constant attribute that identifies the name of the properties file where to configure the access to the HSMs.
     */
    String HSM_PROPERTIES = "hsm.properties";

    /**
     *  Constant attribute that identifies the key defined on {@link #HSM_PROPERTIES} properties file with the path to the PKCS11 configuration file where
     *  to set the absolute path to the HSM native library.
     */
    String KEY_HSM_CONFIG_PATH = "HSM_CONFIG_PATH";

    /**
     *  Constant attribute that identifies the key defined on {@link #HSM_PROPERTIES} properties file with the password for accessing to the HSM.
     */
    String KEY_HSM_PASSWORD = "HSM_PASSWORD";

}
