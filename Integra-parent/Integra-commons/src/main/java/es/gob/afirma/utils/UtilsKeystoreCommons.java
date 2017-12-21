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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsKeystore.java.</p>
 * <b>Description:</b><p>Class that manages operations related with the management of keystores.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 14/01/2014.
 */
package es.gob.afirma.utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * <p>Class that manages operations related with the management of keystores.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 14/01/2014.
 */
public final class UtilsKeystoreCommons implements IUtilsKeystore {

    /**
     * Constructor method for the class UtilsKeystore.java.
     */
    private UtilsKeystoreCommons() {
    }

    /**
     * Method that loads a keystore.
     * @param path Parameter that represents the path where is located the keystore.
     * @param password Parameter that represents the password of the keystore.
     * @param type Parameter that represents the keystore type.
     * @return an object that represents the loaded keystore.
     * @throws KeyStoreException If no Provider supports a KeyStoreSpi implementation for the specified type.
     * @throws NoSuchAlgorithmException If the algorithm used to check the integrity of the keystore cannot be found.
     * @throws CertificateException If any of the certificates in the keystore could not be loaded.
     * @throws IOException If the file does not exist, is a directory rather than a regular file, or for some other reason cannot be opened for reading, or
     * if there is an I/O or format problem with the keystore data, if a password is required but not given, or if the given password was incorrect.
     */
    public static KeyStore loadKeystore(String path, String password, String type) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
	InputStream bais = null;
	KeyStore ks = null;
	try {
	    ks = KeyStore.getInstance(type);
	    bais = new FileInputStream(path);
	    ks.load(bais, password.toCharArray());
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(bais);
	}
	return ks;
    }

    /**
     * Method that obtains a certificate stored inside of a keystore.
     * @param keystore Parameter that represents the keystore.
     * @param keystoreDecodedPass Parameter that represents the keystore password.
     * @param alias Parameter that represents the alias of the certificate to obtain.
     * @param keystoreType Parameter that represents the keystore type.
     * @return the found certificate.
     * @throws KeyStoreException If no Provider supports a KeyStoreSpi implementation for the specified type, or if the keystore has not been
     * initialized (loaded).
     * @throws NoSuchAlgorithmException If the algorithm used to check the integrity of the keystore cannot be found.
     * @throws CertificateException If any of the certificates in the keystore could not be loaded.
     * @throws IOException If there is an I/O or format problem with the keystore data, if a password is required but not given, or if the given password
     * was incorrect.
     */
    public static byte[ ] getCertificateEntry(byte[ ] keystore, String keystoreDecodedPass, String alias, String keystoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
	ByteArrayInputStream bais = null;
	byte[ ] certBytes = null;
	try {
	    KeyStore ks = KeyStore.getInstance(keystoreType);
	    bais = new ByteArrayInputStream(keystore);
	    ks.load(bais, keystoreDecodedPass.toCharArray());
	    Certificate cert = ks.getCertificate(alias);
	    certBytes = cert.getEncoded();
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(bais);
	}
	return certBytes;
    }

    /**
     * Method that obtains a list with all the certificates stored inside of a keystore.
     * @param keystore Parameter that represents the keystore.
     * @param keystoreDecodedPass Parameter that represents the keystore password.
     * @param keystoreType Parameter that represents the keystore type.
     * @return a list with all the found certificates.
     * @throws KeyStoreException If no Provider supports a KeyStoreSpi implementation for the specified type, or if the keystore has not been
     * initialized (loaded).
     * @throws NoSuchAlgorithmException If the algorithm used to check the integrity of the keystore cannot be found.
     * @throws CertificateException If any of the certificates in the keystore could not be loaded.
     * @throws IOException If there is an I/O or format problem with the keystore data, if a password is required but not given, or if the given password
     * was incorrect.
     */
    public static List<X509Certificate> getListCertificates(byte[ ] keystore, String keystoreDecodedPass, String keystoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
	ByteArrayInputStream bais = null;
	List<X509Certificate> listCertificates = new ArrayList<X509Certificate>();
	try {
	    KeyStore ks = KeyStore.getInstance(keystoreType);
	    bais = new ByteArrayInputStream(keystore);
	    ks.load(bais, keystoreDecodedPass.toCharArray());
	    Enumeration<String> aliases = ks.aliases();
	    while (aliases.hasMoreElements()) {
		String alias = aliases.nextElement();
		if (ks.isCertificateEntry(alias)) {
		    listCertificates.add((X509Certificate) ks.getCertificate(alias));
		}
	    }
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(bais);
	}
	return listCertificates;
    }

    /**
     * Method that obtains a private key stored inside of a keystore.
     * @param keystore Parameter that represents the keystore.
     * @param keystoreDecodedPass Parameter that represents the keystore password.
     * @param alias Parameter that represents the alias of the certificate to obtain.
     * @param keystoreType Parameter that represents the keystore type.
     * @param privateKeyDecodedPass Parameter that represents the private key password.
     * @return the found private key.
     * @throws KeyStoreException If if no Provider supports a KeyStoreSpi implementation for the specified type, or if the keystore has not been
     * initialized (loaded).
     * @throws NoSuchAlgorithmException If the algorithm used to check the integrity of the keystore cannot be found, or if the algorithm for recovering
     * the key cannot be found.
     * @throws CertificateException If any of the certificates in the keystore could not be loaded.
     * @throws IOException If there is an I/O or format problem with the keystore data, if a password is required but not given, or if the given
     * password was incorrect.
     * @throws UnrecoverableKeyException If the key cannot be recovered (e.g., the given password is wrong).
     */
    public static PrivateKey getPrivateKeyEntry(byte[ ] keystore, String keystoreDecodedPass, String alias, String keystoreType, String privateKeyDecodedPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
	ByteArrayInputStream bais = null;
	PrivateKey pk = null;
	try {
	    KeyStore ks = KeyStore.getInstance(keystoreType);
	    bais = new ByteArrayInputStream(keystore);
	    ks.load(bais, keystoreDecodedPass.toCharArray());
	    pk = (PrivateKey) ks.getKey(alias, privateKeyDecodedPass.toCharArray());
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(bais);
	}
	return pk;
    }
}
