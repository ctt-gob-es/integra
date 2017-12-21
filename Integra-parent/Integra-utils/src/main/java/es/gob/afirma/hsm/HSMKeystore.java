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
 * <b>File:</b><p>es.gob.afirma.hsm.HSMKeystore.java.</p>
 * <b>Description:</b><p>Class that manages all the operations related with HSM keystores.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/12/2014.
 */
package es.gob.afirma.hsm;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.utils.GenericUtilsCommons;

/**
 * <p>Class that manages all the operations related with HSM keystores.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/12/2014.
 */
public final class HSMKeystore {

    /**
     * Constructor method for the class HSMKeystore.java.
     */
    private HSMKeystore() {
    }

    /**
     * Method that obtains a private key from a HSM by the alias.
     * @param alias Parameter that represents the alias of the private key.
     * @return an object that represents the private key.
     * @throws HSMException If the private key cannot be retrieved.
     */
    public static PrivateKey getPrivateKey(String alias) throws HSMException {
	// Comprobamos que se ha indicado el alias
	if (!GenericUtilsCommons.assertStringValue(alias)) {
	    throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.HSMK_LOG001));
	}

	// Obtenemos el keystore que representa al HSM.
	KeyStore hsmKeystore = HSMKeystorePKCS11Provider.getKeyStore();

	try {
	    // Obtenemos la clave asociada al alias.
	    Key result = hsmKeystore.getKey(alias, null);

	    if (result != null) {
		return (PrivateKey) result;
	    }
	    return null;
	} catch (Exception e) {
	    throw new HSMException(Language.getFormatResIntegra(ILogConstantKeys.HSMK_LOG002, new Object[ ] { alias }), e);
	}
    }

    /**
     * Method that obtains a certificate from a HSM by the alias.
     * @param alias Parameter that represents the alias of the certificate.
     * @return an object that represents the certificate.
     * @throws HSMException If the certificate cannot be retrieved.
     */
    public static X509Certificate getCertificate(String alias) throws HSMException {
	// Comprobamos que se ha indicado el alias
	if (!GenericUtilsCommons.assertStringValue(alias)) {
	    throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.HSMK_LOG001));
	}

	// Obtenemos el keystore que representa al HSM.
	KeyStore hsmKeystore = HSMKeystorePKCS11Provider.getKeyStore();

	try {
	    // Obtenemos el certificado asociado al alias.
	    Certificate result = hsmKeystore.getCertificate(alias);

	    if (result != null) {
		return (X509Certificate) result;
	    }
	    return null;
	} catch (Exception e) {
	    throw new HSMException(Language.getFormatResIntegra(ILogConstantKeys.HSMK_LOG003, new Object[ ] { alias }), e);
	}
    }

    /**
     * Method that obtains a private key entry from a HSM by the alias.
     * @param alias Parameter that represents the alias of the private key entry.
     * @return an object that represents the private key entry.
     * @throws HSMException If the private key entry cannot be retrieved.
     */
    public static PrivateKeyEntry getPrivateKeyEntry(String alias) throws HSMException {
	// Comprobamos que se ha indicado el alias
	if (!GenericUtilsCommons.assertStringValue(alias)) {
	    throw new IllegalArgumentException(Language.getResIntegra(ILogConstantKeys.HSMK_LOG001));
	}

	// Obtenemos el keystore que representa al HSM.
	KeyStore hsmKeystore = HSMKeystorePKCS11Provider.getKeyStore();

	try {
	    // Obtenemos la clave asociada al alias.
	    Entry result = hsmKeystore.getEntry(alias, null);

	    if (result != null) {
		return (PrivateKeyEntry) result;
	    }
	    return null;
	} catch (Exception e) {
	    throw new HSMException(Language.getFormatResIntegra(ILogConstantKeys.HSMK_LOG004, new Object[ ] { alias }), e);
	}
    }
}
