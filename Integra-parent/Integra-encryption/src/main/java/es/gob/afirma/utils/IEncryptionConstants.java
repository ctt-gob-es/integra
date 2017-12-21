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
 * <b>File:</b><p>es.gob.afirma.utils.IEncryptionConstants.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>23/02/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 23/02/2016.
 */
package es.gob.afirma.utils;

/** 
 * <p>Class .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 23/02/2016.
 */
public interface IEncryptionConstants {

    /**
     * Attribute that represents the AES algorithm name. 
     */
    String AES_ALGORITHM = "AES";
    /**
     * Attribute that represents the DES algorithm name. 
     */
    String DES_ALGORITHM = "DES";

    /**
     * Attribute that represents the 3DES algorithm name. 
     */
    String DESEDE_ALGORITHM = "DESede";

    /**
     * Attribute that represents the Blowfish algorithm name. 
     */
    String BLOWFISH_ALGORITHM = "Blowfish";

    /**
     * Attribute that represents the Camellia algorithm name. 
     */
    String CAMELLIA_ALGORITHM = "Camellia";
    
    /**
     * Attribute that represents the RSA algorithm name. 
     */
    String RSA_ALGORITHM = "RSA";

    /**
     * Attribute that represents the Padding algorithm for the AES cipher. 
     */
    String AES_PADDING_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Attribute that represents the Padding algorithm for the DES cipher. 
     */
    String DES_PADDING_ALGORITHM = "DES/CBC/PKCS5Padding";

    /**
     * Attribute that represents the Padding algorithm for the 3DES cipher. 
     */
    String DESEDE_PADDING_ALGORITHM = "DESede/CBC/PKCS5Padding";
    /**
     * Attribute that represents the Padding algorithm for the Blowfish cipher. 
     */
    String BLOWFISH_PADDING_ALGORITHM = "Blowfish/CBC/PKCS5Padding";

    /**
     * Attribute that represents the Padding algorithm for the Camellia cipher. 
     */
    String CAMELLIA_PADDING_ALGORITHM = "Camellia/CBC/PKCS5Padding";

    /**
     * Attribute that represents the Padding algorithm for the RSA-OAEP cipher.
     */
    String RSA_OAEP_PADDING_ALGORITHM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";

    /**
     * Attribute that represents the Padding algorithm for the RSA-PKCS1 cipher.
     */
    String RSA_PKCS1_PADDING_ALGORITHM = "RSA/ECB/PKCS1Padding";
    
    /**
     * Attribute that represents the provider IAIK.
     */
    String PROVIDER_BC ="BC";

}
