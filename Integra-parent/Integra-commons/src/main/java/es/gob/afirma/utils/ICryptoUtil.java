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
 * <b>File:</b><p>es.gob.afirma.utils.ICryptoUtil.java.</p>
 * <b>Description:</b><p>Interface that defines constants related to encryption and hash algorithms.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 03/02/2016.
 */
package es.gob.afirma.utils;

/**
 * <p>Interface that defines constants related to encryption and hash algorithms.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 03/02/2016.
 */
public interface ICryptoUtil {

    /**
     * Constant attribute that represents the name of hash algorithm for SHA1.
     */
    String HASH_ALGORITHM_SHA = "SHA";

    /**
     * Constant attribute that represents the name of hash algorithm for SHA1.
     */
    String HASH_ALGORITHM_SHA1 = "SHA-1";

    /**
     * Constant attribute that represents the name of hash algorithm for SHA256.
     */
    String HASH_ALGORITHM_SHA256 = "SHA-256";

    /**
     * Constant attribute that represents the name of hash algorithm for SHA384.
     */
    String HASH_ALGORITHM_SHA384 = "SHA-384";

    /**
     * Constant attribute that represents the name of hash algorithm for SHA512.
     */
    String HASH_ALGORITHM_SHA512 = "SHA-512";

    /**
     * Constant attribute that represents the name of hash algorithm for RIPEMD-160.
     */
    String HASH_ALGORITHM_RIPEMD160 = "RIPEMD-160";

    /**
     * Constant attribute that represents RSA encryption algorithm.
     */
    String ENCRYPTION_ALGORITHM_RSA = "RSA";
}
