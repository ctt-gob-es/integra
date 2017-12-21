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
 * <b>File:</b><p>es.gob.afirma.encryption.Cipher.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/02/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 26/02/2016.
 */
package es.gob.afirma.encryption;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.gob.afirma.exception.CipherException;
import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.utils.IEncryptionConstants;

/** 
 * <p>Class to decode and encode text using different symmetric or asymmetric algorithms.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 26/02/2016.
 */
public class CipherIntegra implements Serializable {

    /**
     * Attribute that represents class serial version. 
     */
    private static final long serialVersionUID = 1901845015676235860L;

    /**
     * Attribute that represents the key for encode/decode data.
     */
    private Key key;

    /**
     * Attribute that represents the name of cipher algorithm.
     */
    private String algorithm;

    /**
     * Attribute that represents the Padding algorithm.
     */
    private String paddingAlgorithm;

    /**
     * 
     * Constructor method for the class Cipher.java.
     * @param algorithmCipherParam Parameter that represents the selected cipher algorithm.
     * @param keyParam Parameter that represents the used key to encrypt/decrypt a message.
     * @throws CipherException 
     */
    public CipherIntegra(AlgorithmCipherEnum algorithmCipherParam, Key keyParam) throws CipherException {
	if (algorithmCipherParam != null && keyParam != null) {
	    algorithm = algorithmCipherParam.getAlgorithm();
	    paddingAlgorithm = algorithmCipherParam.getPaddingAlgorithm();
	    key = keyParam;
	} else {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG008));
	}
    }

    /**
     * Method for symmetric encryption of data.
     *    
      * @param message Text to be encoded.
     * @return The encoded text.
     * @throws CipherException If the method fails.
     */
    public final String encrypt(String message) throws CipherException {
	String res = null;
	if (message == null || message.isEmpty()) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG006));
	}
	Cipher cipher = null;
	try {
	    if (algorithm.equals(IEncryptionConstants.CAMELLIA_ALGORITHM)) {
		Security.addProvider(new BouncyCastleProvider());
		cipher = Cipher.getInstance(paddingAlgorithm, IEncryptionConstants.PROVIDER_BC);
	    } else {
		cipher = Cipher.getInstance(paddingAlgorithm);
	    }
	    if (!algorithm.equals(IEncryptionConstants.RSA_ALGORITHM)) {
		byte[ ] ivByte = new byte[cipher.getBlockSize()];
		IvParameterSpec ivParamsSpec = new IvParameterSpec(ivByte);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivParamsSpec);
	    } else {
		cipher.init(Cipher.ENCRYPT_MODE, key);
	    }
	    byte[ ] encrypted = cipher.doFinal(message.getBytes("UTF8"));
	    res = new String(Base64.encodeBase64(encrypted));

	} catch (InvalidKeyException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG009), e);
	} catch (IllegalBlockSizeException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG004), e);
	} catch (BadPaddingException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG004), e);
	} catch (NoSuchAlgorithmException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG004), e);
	} catch (NoSuchPaddingException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG004), e);
	} catch (InvalidAlgorithmParameterException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG004), e);
	} catch (NoSuchProviderException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG004), e);
	} catch (UnsupportedEncodingException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG004), e);
	}

	return res;

    }


    /**
     * Method for symmetric decryption.
     * @param message Text to be decoded.
     * @return Text The encoded text.
     * @throws CipherException If the method fails.
     */
    public final String decrypt(String message) throws CipherException {
	String res = "";
	if (message == null || message.isEmpty()) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG007));
	}
	Cipher cipher = null;
	try {
	    if (algorithm.equals(IEncryptionConstants.CAMELLIA_ALGORITHM)) {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		cipher = Cipher.getInstance(paddingAlgorithm, IEncryptionConstants.PROVIDER_BC);
	    } else {
		cipher = Cipher.getInstance(paddingAlgorithm);
	    }
	    if (!algorithm.equals(IEncryptionConstants.RSA_ALGORITHM)) {
		byte[ ] ivByte = new byte[cipher.getBlockSize()];
		IvParameterSpec ivParamsSpec = new IvParameterSpec(ivByte);

		cipher.init(Cipher.DECRYPT_MODE, key, ivParamsSpec);
	    } else {
		cipher.init(Cipher.DECRYPT_MODE, key);
	    }
	    byte[ ] resBytes = cipher.doFinal(Base64.decodeBase64(message));
	    res = new String(resBytes);
	} catch (InvalidKeyException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG010), e);

	} catch (IllegalBlockSizeException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG005), e);

	} catch (BadPaddingException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG005), e);

	} catch (NoSuchAlgorithmException e) {
	    throw new CipherException(Language.getFormatResIntegra(ILogConstantKeys.IE_LOG003, new Object[ ] { algorithm }), e);
	} catch (NoSuchPaddingException e) {
	    throw new CipherException(Language.getFormatResIntegra(ILogConstantKeys.IE_LOG003, new Object[ ] { algorithm }), e);
	} catch (InvalidAlgorithmParameterException e) {
	    throw new CipherException(Language.getResIntegra(ILogConstantKeys.IE_LOG005), e);
	} catch (NoSuchProviderException e) {
	    throw new CipherException(Language.getFormatResIntegra(ILogConstantKeys.IE_LOG003, new Object[ ] { algorithm }), e);
	}
	return res;

    }

}
