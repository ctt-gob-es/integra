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
 * <b>File:</b><p>es.gob.afirma.tsl.ITslValidation.java.</p>
 * <b>Description:</b><p>Class to decode and encode password using AES algorithm.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 19/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.CipherException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;



/**
 * <p>Class to decode and encode password using AES algorithm.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.1, 15/06/2021.
 */
public final class UtilsAESCipher {

	/**
	 * Attribute that represents the key for decode the passwords.
	 */
	private static Key key;

	/**
	 * Attribute that represents an instance of the class.
	 */
	private static UtilsAESCipher instance = null;

	/**
	 * Constructor method for the class UtilsAESCipher.java.
	 */
	private UtilsAESCipher() {
		key = new SecretKeySpec(StaticTslConfig.getProperty(StaticTslConfig.AES_PASSWORD).getBytes(), StaticTslConfig.getProperty(StaticTslConfig.AES_ALGORITHM));
	}

	/**
	 * Method that obtains an instance of the class.
	 * @return an instance of the class.
	 */
	public static synchronized UtilsAESCipher getInstance() {
		if (instance == null) {
			instance = new UtilsAESCipher();
		}
		return instance;
	}

	/**
	 * Method that forces to reload the instance of the class.
	 * @return the reloaded instance of the class.
	 */
	public static synchronized UtilsAESCipher forceReloadInstance() {
		instance = new UtilsAESCipher();
		return instance;
	}

	/**
	 * Method that checks a new key.
	 * @param newAES The new key.
	 * @return <code>true</code> if the key is valid, otherwise <code>false</code>.
	 */
	public static boolean testCipher(String newAES) {
		boolean result = true;
		try {
			byte[ ] aesKeyBytes = newAES.getBytes();
			SecretKeySpec newKey = new SecretKeySpec(aesKeyBytes, StaticTslConfig.getProperty(StaticTslConfig.AES_ALGORITHM));
			Cipher cipher = Cipher.getInstance(StaticTslConfig.getProperty(StaticTslConfig.AES_NO_PADDING_ALG));
			cipher.init(Cipher.ENCRYPT_MODE, newKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			result = false;
		}
		return result;
	}

	/**
	 * Method that encrypts a message.
	 * @param msg The message to encrypt.
	 * @return the message encrypted.
	 * @throws CipherException If the method fails.
	 */
	public byte[ ] encryptMessage(String msg) throws CipherException {
		try {
			Cipher cipher = Cipher.getInstance(StaticTslConfig.getProperty(StaticTslConfig.AES_NO_PADDING_ALG));
			IvParameterSpec ivspec = new IvParameterSpec(key.getEncoded());
			cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
			return Base64.encodeBase64(cipher.doFinal(msg.getBytes()));
		} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			throw new CipherException(Language.getResIntegraTsl(ILogTslConstant.CIPHER_LOG003), e);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException e) {
			throw new CipherException(Language.getResIntegraTsl(ILogTslConstant.CIPHER_LOG001), e);
		}
	}

	/**
	 * Method that decrypts a message.
	 * @param msg The message to decrypt in base 64.
	 * @return the message decrypted.
	 * @throws CipherException If the method fails.
	 */
	public byte[ ] decryptMessage(String msg) throws CipherException {
		try {
			Cipher cipher = Cipher.getInstance(StaticTslConfig.getProperty(StaticTslConfig.AES_NO_PADDING_ALG));
			IvParameterSpec ivspec = new IvParameterSpec(key.getEncoded());
			cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
			return cipher.doFinal(Base64.decodeBase64(msg));
		} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			throw new CipherException(Language.getResIntegraTsl(ILogTslConstant.CIPHER_LOG002), e);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException e) {
			throw new CipherException(Language.getResIntegraTsl(ILogTslConstant.CIPHER_LOG001), e);
		}
	}

}
