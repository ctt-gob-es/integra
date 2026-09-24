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
// https://eupl.eu/1.1/es/

/**
 * <b>File:</b><p>es.gob.afirma.signature.CryptoUtilCommons.java.</p>
 * <b>Description:</b><p> Utility class contains encryption and hash functions for digital signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>29/06/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 29/06/2011.
 */
package es.gob.afirma.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;

import es.gob.afirma.logger.Logger;

/**
 * <p>Utility class contains encryption and hash functions for digital signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 29/06/2011.
 */
public final class CryptoUtilCommons implements ICryptoUtil {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(CryptoUtilCommons.class);

    /**
     * Constructor method for the class CryptoUtilCommons.java.
     */
    private CryptoUtilCommons() {
    }

    public static Provider getP11Provider(final byte[] p11NSSConfigFileContents) throws NoSuchMethodException,
		    SecurityException,
		    IllegalAccessException,
		    IllegalArgumentException,
		    InvocationTargetException,
		    InstantiationException,
		    ClassNotFoundException,
		    IOException {
    	return isJava9orNewer() ?
    			getP11ProviderJava9(p11NSSConfigFileContents) :
    				getP11ProviderJava8(p11NSSConfigFileContents);
    }

    /**
     * Indica si el JRE actual es Java 9 o superior.
     * @return <code>true</code> si el JRE actual es Java 9 o superior,
     *         <code>false</code> si es Java 8 o inferior.
     */
	private static boolean isJava9orNewer() {
		final String ver = System.getProperty("java.version");  //$NON-NLS-1$
		if (ver == null || ver.isEmpty()) {
			LOGGER.warn("No se ha podido determinar la version de Java"); //$NON-NLS-1$
			return false;
		}
		try {
			// Valoramos si la version tiene el patron antiguo (1.X)
			if (ver.startsWith("1.")) { //$NON-NLS-1$
				return Integer.parseInt(ver.substring(2, 3)) > 8;
			}

			// En el nuevo esquema de versionado de Java se sigue el patron [1-9][0-9]*((\.0)*\.[1-9][0-9]*)*,
			// en el que tenemos $MAJOR.$MINOR.$SECURITY (http://openjdk.java.net/jeps/223)
			String majorVer = ver;
			if (majorVer.indexOf(".") > -1) { //$NON-NLS-1$
				majorVer = majorVer.substring(0, majorVer.indexOf(".")); //$NON-NLS-1$
			}

			if (isOnlyNumber(majorVer)) {
				return Integer.parseInt(majorVer) > 8;
			}
		}
		catch(final Exception e) {
			LOGGER.warn("No se ha podido determinar la version de Java (" + ver + "):" + e); //$NON-NLS-1$ //$NON-NLS-2$
		}
		return false;
	}

	/**
	 * Comprueba si el texto es un n&uacute;mero.
	 * @param value Texto a comprobar.
	 * @return <code>true</code> si el texto es un n&uacute;mero, <code>false</code>
	 *         en caso contrario.
	 */
	public static boolean isOnlyNumber(final String value) {
		if (value == null || value.isEmpty()) {
			return false;
		}
	    return value.matches("^[0-9]+$"); //$NON-NLS-1$
	}

    private static Provider getP11ProviderJava9(final byte[] p11NSSConfigFileContents) throws IOException,
		    NoSuchMethodException,
		    SecurityException,
		    IllegalAccessException,
		    IllegalArgumentException,
		    InvocationTargetException {
    	final Provider p = Security.getProvider("SunPKCS11"); //$NON-NLS-1$
    	final File f = File.createTempFile("pkcs11_", ".cfg");  //$NON-NLS-1$//$NON-NLS-2$
    	try (
    			final OutputStream fos = new FileOutputStream(f);
    			) {
    		fos.write(p11NSSConfigFileContents);
    	}
    	final Method configureMethod = Provider.class.getMethod("configure", String.class); //$NON-NLS-1$
    	final Provider configuredProvider = (Provider) configureMethod.invoke(p, f.getAbsolutePath());
    	f.deleteOnExit();
    	Security.addProvider(configuredProvider);
    	return configuredProvider;
    }

    private static Provider getP11ProviderJava8(final byte[] p11NSSConfigFileContents) throws InstantiationException,
		    IllegalAccessException,
		    IllegalArgumentException,
		    InvocationTargetException,
		    NoSuchMethodException,
		    SecurityException,
		    ClassNotFoundException {
    	final Provider p = (Provider) Class.forName("sun.security.pkcs11.SunPKCS11") //$NON-NLS-1$
    			.getConstructor(InputStream.class)
    			.newInstance(new ByteArrayInputStream(p11NSSConfigFileContents));
    	Security.addProvider(p);
    	return p;
    }
}
