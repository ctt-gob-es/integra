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
 * <b>File:</b><p>es.gob.afirma.encryption.AlgorithmEnum.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/02/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 26/02/2016.
 */
package es.gob.afirma.encryption;

import es.gob.afirma.utils.IEncryptionConstants;


/** 
 * <p>Class that represents the differents types of ciphers algorithm.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 26/02/2016.
 */
public enum AlgorithmCipherEnum {
    
    /**
     * Attribute that represents the identifiers of the different ciphers.
     */
    AES(IEncryptionConstants.AES_ALGORITHM, IEncryptionConstants.AES_PADDING_ALGORITHM), DES(IEncryptionConstants.DES_ALGORITHM, IEncryptionConstants.DES_PADDING_ALGORITHM), TRIPLE_DES(IEncryptionConstants.DESEDE_ALGORITHM, IEncryptionConstants.DESEDE_PADDING_ALGORITHM), BLOWSFISH(IEncryptionConstants.BLOWFISH_ALGORITHM, IEncryptionConstants.BLOWFISH_PADDING_ALGORITHM), CAMELLIA(IEncryptionConstants.CAMELLIA_ALGORITHM, IEncryptionConstants.CAMELLIA_PADDING_ALGORITHM),RSA_OAEP(IEncryptionConstants.RSA_ALGORITHM, IEncryptionConstants.RSA_OAEP_PADDING_ALGORITHM),RSA_PKCS1(IEncryptionConstants.RSA_ALGORITHM, IEncryptionConstants.RSA_PKCS1_PADDING_ALGORITHM);
    
    /**
     * Attribute that represents the name of cipher algorithm.
     */
    private String algorithm;
    
    /**
     *  Attribute that represents the Padding algorithm.
     */
    private String paddingAlgorithm;
    
    /**
     * 
     * Constructor method for the class AlgorithmEnum.java.
     * @param algorithmParam  Parameter that represents the name of cipher algorithm.
     * @param paddingAlgorithmParam  Parameter that represents the Padding algorithm.
     */
    private AlgorithmCipherEnum(String algorithmParam, String paddingAlgorithmParam){
	this.algorithm = algorithmParam;
	this.paddingAlgorithm = paddingAlgorithmParam;
    }
    
    /**
     * Gets the value of the attribute {@link #algorithm}.
     * @return the value of the attribute {@link #algorithm}.
     */
    public String getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Gets the value of the attribute {@link #paddingAlgorithm}.
     * @return the value of the attribute {@link #paddingAlgorithm}.
     */
    public String getPaddingAlgorithm() {
        return paddingAlgorithm;
    }
    
   
}
