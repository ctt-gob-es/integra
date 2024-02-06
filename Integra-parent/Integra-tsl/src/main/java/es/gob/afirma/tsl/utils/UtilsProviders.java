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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsProviders.java.</p>
 * <b>Description:</b><p>Utilities class for manage the cryptographic providers.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 16/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.3, 19/09/2022.
 */
package es.gob.afirma.tsl.utils;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.gob.afirma.tsl.logger.Logger;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.i18n.ILogTslConstant;

/** 
 * <p>Utilities class for manage the cryptographic providers.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 19/09/2022.
 */
public final class UtilsProviders {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(UtilsProviders.class);

    /**
     * Constant attribute that represents the token name-id for the seed algorithm SHA1-PRNG.
     */
    public static final String SEED_ALGORITHM_SHA1PRNG = "SHA1PRNG";

    /**
     * Constant attribute that represents a token for a no provider specified.
     */
    private static final String TOKEN_NO_PROVIDER_SPECIFIED = "NoProviderSpecified";
    /**
     * Constant attribute that represents the BC Provider.
     */
    public static final Provider BC_PROVIDER = new BouncyCastleProvider();

    /**
     * Constant attribute that represents the string to identify the name of the Bouncy Castle Provider.
     */
    public static final String BC_PROVIDER_TOKEN_NAME = BC_PROVIDER.getName();

    /**
     * Constructor method for the class UtilsProviders.java.
     */
    private UtilsProviders() {
	super();
    }

    /**
     * Method that initializes the providers.
     */
    public static void initializeProviders() {
	// Eliminamos (por si ya existiera) y añadimos el proveedor BouncyCastle
	// en la posición 1.
	Security.removeProvider(BC_PROVIDER_TOKEN_NAME);
	Security.insertProviderAt(BC_PROVIDER, 1);

	// Se eliminan los elementos relativos a PKCS12 que entran en
	// conflicto con los de SunJCE.
	BC_PROVIDER.remove("KeyGenerator.PKCS#12-MAC");
	BC_PROVIDER.remove("KeyGenerator.PKCS#12-IV");
	BC_PROVIDER.remove("KeyGenerator.PKCS#12");
	BC_PROVIDER.remove("KeyStore.PKCS12");
	BC_PROVIDER.remove("Alg.Alias.KeyStore.PKCS#12");
	BC_PROVIDER.remove("SecretKeyFactory.PKCS#12");

    }

    /**
     * Gets the secure random used for the input seed algorithm in the input provider.
     * If the input provider is <code>null</code>, then left the decision to the JDK.
     * @param algNameSecRandom Algorithm name of the seed generator to set.
     * @param prov Provider to use for the seed algorithm.
     * @return Returns the {@link SecureRandom} implementation for the input
     * seed algorithm by the input provider. If not is found, then return <code>null</code>.
     */
    public static SecureRandom getSecureRandomForSeedAlgorithmProvider(String algNameSecRandom, Provider prov) {

	if (prov == null) {
	    return getSecureRandomForSeedAlgorithmProviderName(algNameSecRandom, null);
	} else {
	    return getSecureRandomForSeedAlgorithmProviderName(algNameSecRandom, prov.getName());
	}

    }

    /**
     * Attribute that represents a map to use like a cache for the seed algorithm generator builded.
     */
    private static Map<String, SecureRandom> secureRandomCachedMap = new HashMap<String, SecureRandom>();

    /**
     * Gets the secure random used for the input seed algorithm in the input provider.
     * If the input provider is <code>null</code>, then left the decision to the JDK.
     * @param algNameSecRandom Algorithm name of the sedd generator to set.
     * @param provName Provider name to use for the seed generator.
     * @return Returns the {@link SecureRandom} implementation for the input
     * seed algorithm by the input provider. If not is found, then return <code>null</code>.
     */
    public static SecureRandom getSecureRandomForSeedAlgorithmProviderName(String algNameSecRandom, String provName) {

	SecureRandom result = null;

	String composedName = null;
	if (UtilsStringChar.isNullOrEmptyTrim(provName)) {
	    composedName = TOKEN_NO_PROVIDER_SPECIFIED + UtilsStringChar.SYMBOL_HYPHEN_STRING + algNameSecRandom;
	} else {
	    composedName = provName + UtilsStringChar.SYMBOL_HYPHEN_STRING + algNameSecRandom;
	}

	result = secureRandomCachedMap.get(composedName);
	if (result == null) {

	    if (UtilsStringChar.isNullOrEmptyTrim(provName)) {
		try {
		    result = SecureRandom.getInstance(algNameSecRandom);
		    secureRandomCachedMap.put(composedName, result);
		    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.UP_LOG003, new Object[ ] { algNameSecRandom, result.getProvider().getName() }));
		} catch (NoSuchAlgorithmException e) {
		    LOGGER.error(Language.getFormatResIntegraTsl(ILogTslConstant.UP_LOG000, new Object[ ] { algNameSecRandom }));
		}
	    } else {
		try {
		    result = SecureRandom.getInstance(algNameSecRandom, provName);
		    secureRandomCachedMap.put(composedName, result);
		    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.UP_LOG003, new Object[ ] { algNameSecRandom, result.getProvider().getName() }));
		} catch (NoSuchAlgorithmException e) {
		    LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UP_LOG001, new Object[ ] { algNameSecRandom, provName }));
		} catch (NoSuchProviderException e) {
		    LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UP_LOG002, new Object[ ] { provName, algNameSecRandom }));
		} finally {
		    result = getSecureRandomForSeedAlgorithmProviderName(algNameSecRandom, null);
		}
	    }

	}

	if (result != null) {
	    LOGGER.debug(Language.getFormatResIntegraTsl(ILogTslConstant.UP_LOG004, new Object[ ] { algNameSecRandom, result.getProvider().getName() }));
	}

	return result;

    }

    /**
     * Reset the seed algorithm generator cache.
     */
    public static void resetAllSecureRandomCache() {
	secureRandomCachedMap.clear();
    }

}
