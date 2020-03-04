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
 * @version 1.3,04/03/2020.
 */
package es.gob.afirma.utils;

import org.apache.xml.crypto.dsig.DigestMethod;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * <p>Utility class contains encryption and hash functions for digital signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 04/03/2020.
 */
public final class CryptoUtilXML {

    /**
     * Constructor method for the class CryptoUtil.java.
     */
    private CryptoUtilXML() {
    }

    /**
     * Method that translates a {@link AlgorithmIdentifier} object to a digest algorithm string.
     * @param algorithmIdentifier Parameter that represents the OID of the digest algorithm.
     * @return the digest algorithm name.
     */
    public static String translateAlgorithmIdentifier(AlgorithmIdentifier algorithmIdentifier) {
	if (algorithmIdentifier == null) {
	    return null;
	}
	ASN1ObjectIdentifier algId = algorithmIdentifier.getAlgorithm();
	if (OIWObjectIdentifiers.idSHA1.equals(algId)) {
	    return ICryptoUtil.HASH_ALGORITHM_SHA1;
	} else if (NISTObjectIdentifiers.id_sha256.equals(algId)) {
	    return ICryptoUtil.HASH_ALGORITHM_SHA256;
	} else if (NISTObjectIdentifiers.id_sha384.equals(algId)) {
	    return ICryptoUtil.HASH_ALGORITHM_SHA384;
	} else if (NISTObjectIdentifiers.id_sha512.equals(algId)) {
	    return ICryptoUtil.HASH_ALGORITHM_SHA512;
	} else if (X509ObjectIdentifiers.ripemd160.equals(algId)) {
	    return ICryptoUtil.HASH_ALGORITHM_RIPEMD160;
	} else {
	    return null;
	}
    }

    /**
     * Method that translates a {@link AlgorithmIdentifier} object to a digest algorithm string.
     * @param digestAlg Parameter that represents the digest method algorithm URI.
     * @return the digest algorithm name.
     */
    public static String translateXmlDigestAlgorithm(String digestAlg) {
	if (digestAlg == null) {
	    return null;
	}
	if (DigestMethod.SHA1.equals(digestAlg)) {
	    return ICryptoUtil.HASH_ALGORITHM_SHA1;
	} else if (DigestMethod.SHA256.equals(digestAlg)) {
	    return ICryptoUtil.HASH_ALGORITHM_SHA256;
	} else if ("http://www.w3.org/2001/04/xmldsig-more#sha384".equals(digestAlg)) {
	    return ICryptoUtil.HASH_ALGORITHM_SHA384;
	} else if (DigestMethod.SHA512.equals(digestAlg)) {
	    return ICryptoUtil.HASH_ALGORITHM_SHA512;
	} else {
	    return null;
	}
    }

    /**
     * Method that obtains the MessageImprint from the digest method algorithm URI.
     * @param hashAlgXML Parameter that represents the digest method algorithm URI.
     * @param data Parameter that represents the hashed message.
     * @return the generated MessageImprint.
     */
    public static MessageImprint generateMessageImprintFromXMLAlgorithm(String hashAlgXML, byte[ ] data) {
	AlgorithmIdentifier algoritmID = null;
	if (hashAlgXML.equalsIgnoreCase(DigestMethod.SHA1)) {
	    algoritmID = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
	} else if (hashAlgXML.equalsIgnoreCase(DigestMethod.SHA256)) {
	    algoritmID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
	} else if (hashAlgXML.equalsIgnoreCase(DigestMethod.SHA512)) {
	    algoritmID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
	} else if (hashAlgXML.equalsIgnoreCase(DigestMethod.RIPEMD160)) {
	    algoritmID = new AlgorithmIdentifier(X509ObjectIdentifiers.ripemd160);
	} else {
	    return null;
	}

	return new MessageImprint(algoritmID, data);
    }

    /**
     * Method that translates a {@link java.net.URI} object to a algorithm string.
     * @param alg Parameter that represents the method algorithm.
     * @return the algorithm name.
     */
    public static String translateDigestAlgorithmToXMLURI(String alg) {
	if (alg == null) {
	    return null;
	}
	if ("SHA1".equals(alg)) {
	    return DigestMethod.SHA1;
	} else if ("SHA256".equals(alg)) {
	    return DigestMethod.SHA256;
	} else if ("SHA512".equals(alg)) {
	    return DigestMethod.SHA512;
	} else {
	    return null;
	}
    }
}
