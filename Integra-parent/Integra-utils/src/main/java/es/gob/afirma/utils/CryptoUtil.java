// Copyright (C) 2017 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.signature.CryptoUtil.java.</p>
 * <b>Description:</b><p> Utility class contains encryption and hash functions for digital signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>29/06/2011.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.utils;

import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import es.gob.afirma.signature.SigningException;

/**
 * <p>Utility class contains encryption and hash functions for digital signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public final class CryptoUtil implements ICryptoUtil {

    /**
     * Constructor method for the class CryptoUtil.java.
     */
    private CryptoUtil() {
    }

    /**
     * Method that obtains the hash computation from a array bytes.
     * @param algorithm Parameter that represents the algorithm used in the hash computation.
     * @param data Parameter that represents the source data.
     * @return the hash value.
     * @throws SigningException If a MessageDigestSpi implementation for the specified algorithm is not available
     * from the specified Provider object.
     */
    public static byte[ ] digest(String algorithm, byte[ ] data) throws SigningException {
	return CryptoUtilPdfBc.digest(algorithm, data);
    }

    /**
     * Method that translates a {@link AlgorithmIdentifier} object to a digest algorithm string.
     * @param algorithmIdentifier Parameter that represents the OID of the digest algorithm.
     * @return the digest algorithm name.
     */
    public static String translateAlgorithmIdentifier(AlgorithmIdentifier algorithmIdentifier) {
	return CryptoUtilXML.translateAlgorithmIdentifier(algorithmIdentifier);
    }

    /**
     * Method that obtains the OID of a hash algorithm from the name.
     * @param hashAlgorithm Parameter that represents the name of the hash algorithm.
     * @return the OID value.
     */
    public static AlgorithmIdentifier getAlgorithmIdentifierByName(String hashAlgorithm) {
	return CryptoUtilPdfBc.getAlgorithmIdentifierByName(hashAlgorithm);
    }

    /**
     * Method that translates a {@link AlgorithmIdentifier} object to a digest algorithm string.
     * @param digestAlg Parameter that represents the digest method algorithm URI.
     * @return the digest algorithm name.
     */
    public static String translateXmlDigestAlgorithm(String digestAlg) {
	return CryptoUtilXML.translateXmlDigestAlgorithm(digestAlg);
    }

    /**
     * Method that gets the name of a digest algorithm by name or alias.
     * @param pseudoName Parameter that represents the name or alias of the digest algorithm.
     * @return the name of the digest algorithm.
     */
    public static String getDigestAlgorithmName(String pseudoName) {
	return CryptoUtilPdfBc.getDigestAlgorithmName(pseudoName);
    }

    /**
     * Method that obtains the MessageImprint from the digest method algorithm URI.
     * @param hashAlgXML Parameter that represents the digest method algorithm URI.
     * @param data Parameter that represents the hashed message.
     * @return the generated MessageImprint.
     */
    public static MessageImprint generateMessageImprintFromXMLAlgorithm(String hashAlgXML, byte[ ] data) {
	return CryptoUtilXML.generateMessageImprintFromXMLAlgorithm(hashAlgXML, data);
    }
}
