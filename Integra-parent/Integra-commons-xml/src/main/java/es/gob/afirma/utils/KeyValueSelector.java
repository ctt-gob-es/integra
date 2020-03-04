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
 * <b>File:</b><p>es.gob.afirma.utils.KeyValueSelector.java.</p>
 * <b>Description:</b><p>Class that extends KeySelector to retrieve the public key out of the KeyValue element and returns it. NOTE: If the key algorithm
 * doesn't match the signature algorithm, then the public key will be ignored.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>17/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 04/03/2020.
 */
package es.gob.afirma.utils;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.xml.crypto.AlgorithmMethod;
import org.apache.xml.crypto.KeySelector;
import org.apache.xml.crypto.KeySelectorException;
import org.apache.xml.crypto.KeySelectorResult;
import org.apache.xml.crypto.XMLCryptoContext;
import org.apache.xml.crypto.XMLStructure;
import org.apache.xml.crypto.dsig.SignatureMethod;
import org.apache.xml.crypto.dsig.keyinfo.KeyInfo;
import org.apache.xml.crypto.dsig.keyinfo.X509Data;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import org.apache.xml.security.signature.XMLSignature;

/**
 * <p>Class that extends KeySelector to retrieve the public key out of the KeyValue element and returns it. NOTE: If the key algorithm doesn't match
 * the signature algorithm, then the public key will be ignored.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 04/03/2020.
 */
public class KeyValueSelector extends KeySelector {

    /**
     * {@inheritDoc}
     * @see org.apache.xml.crypto.KeySelector#select(org.apache.xml.crypto.dsig.keyinfo.KeyInfo, org.apache.xml.crypto.KeySelector.Purpose, org.apache.xml.crypto.AlgorithmMethod, org.apache.xml.crypto.XMLCryptoContext)
     */
    @SuppressWarnings("unchecked")
    @Override
    public final KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
	if (keyInfo == null) {
	    throw new KeySelectorException(Language.getResIntegra(ILogConstantKeys.KVS_LOG001));
	}
	SignatureMethod sm = (SignatureMethod) method;
	List<XMLStructure> list = keyInfo.getContent();

	for (int i = 0; i < list.size(); i++) {
	    XMLStructure xmlStructure = list.get(i);
	    if (xmlStructure instanceof X509Data) {
		List<X509Certificate> x509datalist = ((X509Data) xmlStructure).getContent();
		for (int y = x509datalist.size() - 1; y >= 0; y--) {
		    PublicKey pk = null;

		    X509Certificate certificate = x509datalist.get(y);
		    if (certificate.getKeyUsage() != null && certificate.getKeyUsage()[0]) {
			// certificado firmante
			pk = certificate.getPublicKey();
			if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
			    return new SimpleKeySelectorResult(pk);
			}
		    }
		}
	    }
	}
	throw new KeySelectorException(Language.getResIntegra(ILogConstantKeys.KVS_LOG002));
    }

    /**
     * Method that indicates if the algorithm used for the creation of the public key matches with the required signature algorithm (true) or not (false).
     * @param algURI Parameter that represents the required signature algorithm.
     * @param algName Parameter that represents the algorithm used for the creation of the public key.
     * @return a boolean that indicates if the algorithm used for the creation of the public key matches with the required signature
     * algorithm (true) or not (false).
     */
    private static boolean algEquals(String algURI, String algName) {
	boolean result = false;

	if (algName.equalsIgnoreCase("RSA") && (algURI.equalsIgnoreCase(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1) || algURI.equalsIgnoreCase(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256) || algURI.equalsIgnoreCase(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512))) {
	    result = true;
	}
	return result;
    }

    /**
     * <p>Private class containing the public key selected with {@link KeyValueSelector#select(KeyInfo, Purpose, AlgorithmMethod, XMLCryptoContext)}.</p>
     * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
     * @version 1.0, 04/07/2013.
     */
    private static class SimpleKeySelectorResult implements KeySelectorResult {

	/**
	 * Attribute that represents the public key to validate the signature.
	 */
	private PublicKey pk;

	/**
	 * Constructor method for the class SimpleKeySelectorResult.java.
	 * @param pkParam Parameter that represents the public key to validate the signature.
	 */
	SimpleKeySelectorResult(PublicKey pkParam) {
	    this.pk = pkParam;
	}

	/**
	 * {@inheritDoc}
	 * @see org.apache.xml.crypto.KeySelectorResult#getKey()
	 */
	@Override
	public Key getKey() {
	    return pk;
	}

    }

}
