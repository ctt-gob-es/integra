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
 * <b>File:</b><p>es.gob.afirma.hsm.HSMKeystorePKCS11Provider.java.</p>
 * <b>Description:</b><p>Class to manage the connection to the HSM and create the Keystore representation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/12/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.hsm;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.util.Properties;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.properties.HSMProperties;
import es.gob.afirma.utils.GenericUtilsCommons;
import sun.security.pkcs11.SunPKCS11;

/**
 * <p>Class to manage the connection to the HSM and create the Keystore representation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
@SuppressWarnings("restriction")
public final class HSMKeystorePKCS11Provider {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(HSMKeystorePKCS11Provider.class);

    /**
     * Constant attribute that represents the token 'PKCS11'.
     */
    private static final String TOKEN_PKCS11 = "PKCS11";

    /**
     * Attribute that represents the PKCS11 provider instance to access to the HSM.
     */
    private static Provider pkcs11Provider = null;

    /**
     * Attribute that represents the HSM how a KeyStore.
     */
    private static KeyStore hsmKeystore = null;

    /**
     * Private Constructor method for the class HSMKeystorePKCS11Provider.java.
     */
    private HSMKeystorePKCS11Provider() {
	super();
    }

    /**
     * Method that loads the properties and configure the access to the HSM.
     * @throws HSMException In case of some error loading the properties or the HSM configuration.
     */
    public static void reloadHSMConfiguration() throws HSMException {

	LOGGER.info(Language.getResIntegra(ILogConstantKeys.HKPP_LOG001));

	try {
	    // Accedemos al archivo de propiedades relacionadas con los HSM
	    Properties hsmProperties = HSMProperties.getHSMProperties();

	    if (hsmProperties.isEmpty()) {
		throw new HSMException(Language.getFormatResIntegra(ILogConstantKeys.HKPP_LOG002, new Object[ ] { IHSMConstants.HSM_PROPERTIES }));
	    }

	    // Cargamos la propiedad con la ruta absoluta al fichero de
	    // configuración PKCS11 donde se establece la ruta absoluta a la
	    // librería nativa del HSM entre otras configuraciones adicionales
	    String absPathConfigFile = hsmProperties.getProperty(IHSMConstants.KEY_HSM_CONFIG_PATH);
	    if (!GenericUtilsCommons.assertStringValue(absPathConfigFile)) {
		throw new HSMException(Language.getFormatResIntegra(ILogConstantKeys.HKPP_LOG003, new Object[ ] { IHSMConstants.HSM_PROPERTIES }));
	    }

	    // Cargamos la propiedad con la contraseña de acceso al HSM
	    String password = hsmProperties.getProperty(IHSMConstants.KEY_HSM_PASSWORD);
	    if (password == null) {
		password = "";
	    }

	    try {
		// Comprobamos si ya existe un proveedor PKCS11
		pkcs11Provider = Security.getProvider(TOKEN_PKCS11);

		// Si no existe, asociamos el proveedor de Sun como PKCS11 y lo
		// añadimos a la lista de proveedores en la última posición
		if (pkcs11Provider == null) {
		    pkcs11Provider = new SunPKCS11(absPathConfigFile);
		    Security.addProvider(pkcs11Provider);
		}
		// Obtenemos el almacén de claves
		hsmKeystore = KeyStore.getInstance(TOKEN_PKCS11);
	    } catch (KeyStoreException e) {
		throw new HSMException(Language.getResIntegra(ILogConstantKeys.HKPP_LOG004), e);
	    }

	    // Hacemos la carga del KeyStore
	    try {
		hsmKeystore.load(null, password.toCharArray());
	    } catch (Exception e) {
		throw new HSMException(Language.getResIntegra(ILogConstantKeys.HKPP_LOG005), e);
	    }
	} finally {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.HKPP_LOG006));
	}
    }

    /**
     * Private method to check if the provider and keystore are already initialized,
     * if not, start it.
     * @throws HSMException In case of some error loading the properties or the HSM configuration.
     */
    private static void checkIfIsInitialized() throws HSMException {
	if (pkcs11Provider == null || hsmKeystore == null) {
	    reloadHSMConfiguration();
	}
    }

    /**
     * Method that returns the keystore representation of the HSM.
     * @return Keystore representation of the HSM.
     * @throws HSMException In case of some error loading the properties or the HSM configuration.
     */
    public static KeyStore getKeyStore() throws HSMException {
	checkIfIsInitialized();
	return hsmKeystore;
    }

}
