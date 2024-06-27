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
 * <b>File:</b><p>es.gob.afirma.signature.SignatureConstants.java.</p>
 * <b>Description:</b><p>Class that defines constants related to processes with signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/06/2011.</p>
 * @author Gobierno de España.
 * @version 1.3, 06/03/2020.
 */
package es.gob.afirma.signature;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.DigestMethod;

import es.gob.afirma.utils.CryptoUtilCommons;

/**
 * <p>Class that defines constants related to processes with signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 06/03/2020.
 */
public final class SignatureConstants {

    /**
     * Constructor method for the class SignatureConstants.java.
     */
    private SignatureConstants() {
    }

    /**
     * Constant attribute that identifies the UTF-8 encoding.
     */
    public static final String UTF8_ENCODING = "UTF-8";

    /**
     * Constant attribute that represents CAdES signature format.
     */
    public static final String SIGN_FORMAT_CADES = "CAdES";

    /**
     * Constant attribute that identifies the XAdES detached signature.
     */
    public static final String SIGN_FORMAT_XADES_DETACHED = "XAdES Detached";

    /**
     * Constant attribute that identifies the XAdES externally detached signature.
     */
    public static final String SIGN_FORMAT_XADES_EXTERNALLY_DETACHED = "XAdES Externally Detached";

    /**
     * Constant attribute that identifies the XAdES enveloped signature.
     */
    public static final String SIGN_FORMAT_XADES_ENVELOPED = "XAdES Enveloped";

    /**
     * Constant attribute that identifies the XAdES enveloping signature.
     */
    public static final String SIGN_FORMAT_XADES_ENVELOPING = "XAdES Enveloping";

    /**
     * Constant attribute that represents PAdES signature format.
     */
    public static final String SIGN_FORMAT_PADES = "PAdES";

    /**
     * Constant attribute that represents PAdES signature format.
     */
    public static final String SIGN_FORMAT_PADES_BASIC = "PAdES-Basic";

    /**
     * Constant attribute that represents XAdES signature format.
     */
    public static final String SIGN_FORMAT_XADES = "XAdES";

    /**
     * Constant attribute that represents ASiC-S CAdES Baseline signature format.
     */
    public static final String SIGN_FORMAT_ASICS_CADES_BASELINE = "ASiC-S CAdES Baseline";

    /**
     * Constant attribute that represents ASiC-S XAdES Baseline signature format.
     */
    public static final String SIGN_FORMAT_ASICS_XADES_BASELINE = "ASiC-S XAdES Baseline";

    /**
     * Constant attribute that represents explicit signature mode.
     */
    public static final String SIGN_MODE_EXPLICIT = "explicit mode";

    /**
     * Constant attribute that represents explicit hash signature mode.
     */
    public static final String SIGN_MODE_EXPLICIT_HASH = "explicit hash mode";

    /**
     * Constant attribute that represents implicit signature mode.
     */
    public static final String SIGN_MODE_IMPLICIT = "implicit mode";
    
    /**
     * Constant attribute that represents SHA1 algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA1 = "SHA1";

    /**
     * Constant attribute that represents SHA256 algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA256 = "SHA256";

    /**
     * Constant attribute that represents SHA384 algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA384 = "SHA384";
    
    /**
     * Constant attribute that represents SHA512 algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA512 = "SHA512";

    /**
     * Constant attribute that represents default signature mode.
     */
    public static final String DEFAULT_SIGN_MODE = SIGN_MODE_EXPLICIT;

    /**
     * Constant attribute that represents supported XAdES counter signature formats.
     */
    public static final Set<String> SUPPORTED_COUNTER_XADES_SIGN_FORMAT = new HashSet<String>() {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = -3526322449162410326L;
	{
	    add(SIGN_FORMAT_XADES_DETACHED);
	    add(SIGN_FORMAT_XADES_EXTERNALLY_DETACHED);
	}
    };

    /**
     * Constant attribute that represents supported XAdES signature formats.
     */
    public static final Set<String> SUPPORTED_XADES_SIGN_FORMAT = new HashSet<String>() {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = -3526322449162410326L;

	{
	    add(SIGN_FORMAT_XADES_ENVELOPED);
	    add(SIGN_FORMAT_XADES_ENVELOPING);
	    add(SIGN_FORMAT_XADES_DETACHED);
	    add(SIGN_FORMAT_XADES_EXTERNALLY_DETACHED);
	}
    };

    /**
     * Constant attribute that represents SHA1withRSA algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA1WITHRSA = "SHA1withRSA";

    /**
     * Constant attribute that represents SHA256withRSA algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA256WITHRSA = "SHA256withRSA";

    /**
     * Constant attribute that represents SHA384withRSA algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA384WITHRSA = "SHA384withRSA";

    /**
     * Constant attribute that represents SHA512withRSA algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA512WITHRSA = "SHA512withRSA";
    
    /**
     * Constant attribute that represents SHA1withECDSA algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA1WITHECDSA = "SHA1withECDSA";

    /**
     * Constant attribute that represents SHA256withECDSA algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA256WITHECDSA = "SHA256withECDSA";

    /**
     * Constant attribute that represents SHA384withECDSA algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA384WITHECDSA = "SHA384withECDSA";
    
    /**
     * Constant attribute that represents SHA512withECDSA algorithm.
     */
    public static final String SIGN_ALGORITHM_SHA512WITHECDSA = "SHA512withECDSA";

    /**
     * Constant attribute that represents the URI of allowed signature algorithms to use with XADES signatures.
     */
    public static final Map<String, String> SIGN_ALGORITHM_URI = new HashMap<String, String>() {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = -3091842386857850550L;

	{
	    put(SIGN_ALGORITHM_SHA1, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
	    put(SIGN_ALGORITHM_SHA256, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
	    put(SIGN_ALGORITHM_SHA384, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
	    put(SIGN_ALGORITHM_SHA512, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
	    put(SIGN_ALGORITHM_SHA1WITHRSA, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
	    put(SIGN_ALGORITHM_SHA256WITHRSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
	    put(SIGN_ALGORITHM_SHA384WITHRSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
	    put(SIGN_ALGORITHM_SHA512WITHRSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
	    put(SIGN_ALGORITHM_SHA1WITHECDSA, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");
	    put(SIGN_ALGORITHM_SHA256WITHECDSA, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
	    put(SIGN_ALGORITHM_SHA384WITHECDSA, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384");
	    put(SIGN_ALGORITHM_SHA512WITHECDSA, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
	}
    };

    /**
     * Constant attribute that represents the allowed digest algorithms to use with CADES signatures.
     */
    public static final Map<String, String> DIGEST_ALGORITHMS_SUPPORT_CADES = new HashMap<String, String>() {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = 74770910568121154L;

	{
	    put(SIGN_ALGORITHM_SHA1, CryptoUtilCommons.HASH_ALGORITHM_SHA1);
	    put(SIGN_ALGORITHM_SHA256, CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    put(SIGN_ALGORITHM_SHA384, CryptoUtilCommons.HASH_ALGORITHM_SHA384);
	    put(SIGN_ALGORITHM_SHA512, CryptoUtilCommons.HASH_ALGORITHM_SHA512);
	    put(CryptoUtilCommons.HASH_ALGORITHM_SHA1, CryptoUtilCommons.HASH_ALGORITHM_SHA1);
	    put(CryptoUtilCommons.HASH_ALGORITHM_SHA256, CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    put(CryptoUtilCommons.HASH_ALGORITHM_SHA384, CryptoUtilCommons.HASH_ALGORITHM_SHA384);
	    put(CryptoUtilCommons.HASH_ALGORITHM_SHA512, CryptoUtilCommons.HASH_ALGORITHM_SHA512);
	    put(SIGN_ALGORITHM_SHA1WITHRSA, CryptoUtilCommons.HASH_ALGORITHM_SHA1);
	    put(SIGN_ALGORITHM_SHA256WITHRSA, CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    put(SIGN_ALGORITHM_SHA384WITHRSA, CryptoUtilCommons.HASH_ALGORITHM_SHA384);
	    put(SIGN_ALGORITHM_SHA512WITHRSA, CryptoUtilCommons.HASH_ALGORITHM_SHA512);
	    put(SIGN_ALGORITHM_SHA1WITHECDSA, CryptoUtilCommons.HASH_ALGORITHM_SHA1);
	    put(SIGN_ALGORITHM_SHA256WITHECDSA, CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    put(SIGN_ALGORITHM_SHA384WITHECDSA, CryptoUtilCommons.HASH_ALGORITHM_SHA384);
	    put(SIGN_ALGORITHM_SHA512WITHECDSA, CryptoUtilCommons.HASH_ALGORITHM_SHA512);
	}
    };

    /**
     * Constant attribute that represents the URI of allowed hash algorithms to use with XADES signatures.
     */
    public static final Map<String, String> DIGEST_METHOD_ALGORITHMS_XADES = new HashMap<String, String>() {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = -3091842386857850550L;

	{
	    put(SIGN_ALGORITHM_SHA1, DigestMethod.SHA1);
	    put(SIGN_ALGORITHM_SHA256, DigestMethod.SHA256);
	    put(SIGN_ALGORITHM_SHA384, "http://www.w3.org/2001/04/xmldsig-more#sha384");
	    put(SIGN_ALGORITHM_SHA512, DigestMethod.SHA512);
	    put(SIGN_ALGORITHM_SHA1WITHRSA, DigestMethod.SHA1);
	    put(SIGN_ALGORITHM_SHA256WITHRSA, DigestMethod.SHA256);
	    put(SIGN_ALGORITHM_SHA384WITHRSA, "http://www.w3.org/2001/04/xmldsig-more#sha384");
	    put(SIGN_ALGORITHM_SHA512WITHRSA, DigestMethod.SHA512);
	    put(SIGN_ALGORITHM_SHA1WITHECDSA, DigestMethod.SHA1);
	    put(SIGN_ALGORITHM_SHA256WITHECDSA, DigestMethod.SHA256);
	    put(SIGN_ALGORITHM_SHA384WITHECDSA, "http://www.w3.org/2001/04/xmldsig-more#sha384");
	    put(SIGN_ALGORITHM_SHA512WITHECDSA, DigestMethod.SHA512);
	}
    };

    /**
     * Constant attribute that represents the allowed signature algorithms to use with CADES, PAdES and XAdES signatures.
     */
    public static final Map<String, String> SIGN_ALGORITHMS_SUPPORT_CADES = new HashMap<String, String>() {

	/**
	 * Class serial version.
	 */
	private static final long serialVersionUID = -3091842386857850550L;

	{
	    put(SIGN_ALGORITHM_SHA1, CryptoUtilCommons.HASH_ALGORITHM_SHA1);
	    put(SIGN_ALGORITHM_SHA256, CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    put(SIGN_ALGORITHM_SHA384, CryptoUtilCommons.HASH_ALGORITHM_SHA384);
	    put(SIGN_ALGORITHM_SHA512, CryptoUtilCommons.HASH_ALGORITHM_SHA512);
	    put(SIGN_ALGORITHM_SHA1WITHRSA, CryptoUtilCommons.HASH_ALGORITHM_SHA1);
	    put(SIGN_ALGORITHM_SHA256WITHRSA, CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    put(SIGN_ALGORITHM_SHA384WITHRSA, CryptoUtilCommons.HASH_ALGORITHM_SHA384);
	    put(SIGN_ALGORITHM_SHA512WITHRSA, CryptoUtilCommons.HASH_ALGORITHM_SHA512);
	    put(SIGN_ALGORITHM_SHA1WITHECDSA, CryptoUtilCommons.HASH_ALGORITHM_SHA1);
	    put(SIGN_ALGORITHM_SHA256WITHECDSA, CryptoUtilCommons.HASH_ALGORITHM_SHA256);
	    put(SIGN_ALGORITHM_SHA384WITHECDSA, CryptoUtilCommons.HASH_ALGORITHM_SHA384);
	    put(SIGN_ALGORITHM_SHA512WITHECDSA, CryptoUtilCommons.HASH_ALGORITHM_SHA512);
	}
    };

    /**
     * Constant attribute that represents property name used in Manifest references list (external references in a detached signature).
     */
    public static final String MF_REFERENCES_PROPERTYNAME = "Manifest-References";

    /**
     * Constant attribute that identifies a Certified PDF signature.
     */
    public static final String PDF_CERTIFIED = "CERTIFIED_NO_CHANGES_ALLOWED";

    /**
     * Constant attribute that identifies an Approval PDF signature.
     */
    public static final String PDF_APPROVAL = "NOT_CERTIFIED";

    /**
     * Constant attribute that represents CAdES Baseline signature format.
     */
    public static final String SIGN_FORMAT_CADES_BASELINE = "CAdES Baseline";

    /**
     * Constant attribute that represents XAdES Baseline signature format.
     */
    public static final String SIGN_FORMAT_XADES_BASELINE = "XAdES Baseline";

    /**
     * Constant attribute that represents PAdES Baseline signature format.
     */
    public static final String SIGN_FORMAT_PADES_BASELINE = "PAdES Baseline";

    /**
     * Constant attribute that represents the property description of data object format.
     */
    public static final String XADES_DATA_FORMAT_DESCRIPTION_PROP_DEFAULT = "Data signed by Integr@";
    /**
     * Constant attribute that represents the property mimetype of data object format.
     */
    public static final String XADES_DATA_FORMAT_MIME_PROP_DEFAULT = "application/xml";
    
	/**
	 * Compone el nombre del algoritmo de firma que utiliza un algoritmo de huella concreto y emplea un determinado tipo
	 * de clave de cifrado. El algoritmo de huella se extrae del algoritmo proporcionado, que puede ser de huella, de firma
	 * o una referencia al algoritmo (OID o URL).
	 * @param algorithm Algoritmo de huella digital o firma.
	 * @param keyType Tipo de clave de firma.
	 * @return Nombre del algoritmo de firma. */
	public static String composeSignatureAlgorithmName(final String algorithm, final String keyType) {
		if (algorithm == null) {
			throw new IllegalArgumentException(
					"El nombre del algoritmo no puede ser nulo"); //$NON-NLS-1$
		}
		if (keyType == null) {
			throw new IllegalArgumentException(
					"El tipo de clave de certificado no puede ser nulo"); //$NON-NLS-1$
		}

		// Limpiamos el nombre del algorithm de huella
		final String digestAlgorithm = getDigestAlgorithmName(algorithm).replace("-", ""); //$NON-NLS-1$ //$NON-NLS-2$

		// Agregamos el algoritmo de cifrado correspondiente al tipo de clave del certificado
		String suffix;
		if (keyType.equals("RSA")) { //$NON-NLS-1$
			suffix = "withRSA"; //$NON-NLS-1$
		} else if (keyType.equals("DSA")) { //$NON-NLS-1$
			suffix = "withDSA"; //$NON-NLS-1$
		} else if (keyType.startsWith("EC")) { //$NON-NLS-1$
			suffix = "withECDSA"; //$NON-NLS-1$
		} else {
			throw new IllegalArgumentException("Tipo de clave de firma no soportado: " + keyType); //$NON-NLS-1$
		}
		return digestAlgorithm + suffix;
	}
    
	/** Obtiene el nombre de un algoritmo de huella digital a partir de una de
	 * las variantes de este.
	 * @param pseudoName Nombre o variante del nombre del algoritmo de huella digital.
	 * @return Nombre del algoritmo de huella digital. */
	public static String getDigestAlgorithmName(final String pseudoName) {
		if (pseudoName == null) {
			throw new IllegalArgumentException(
				"El nombre del algoritmo de huella digital no puede ser nulo" //$NON-NLS-1$
			);
		}
		final String upperPseudoName = pseudoName.toUpperCase(Locale.US);
		if (upperPseudoName.equals("SHA")  //$NON-NLS-1$
				|| upperPseudoName.equals("http://www.w3.org/2000/09/xmldsig#sha1".toUpperCase(Locale.US)) //$NON-NLS-1$
				|| upperPseudoName.equals("1.3.14.3.2.26") //$NON-NLS-1$
				|| upperPseudoName.startsWith("SHA1") //$NON-NLS-1$
				|| upperPseudoName.startsWith("SHA-1")) //$NON-NLS-1$
		{
			return "SHA1"; //$NON-NLS-1$
		}

		if (upperPseudoName.equals("http://www.w3.org/2001/04/xmlenc#sha256".toUpperCase(Locale.US))  //$NON-NLS-1$
				|| upperPseudoName.equals("2.16.840.1.101.3.4.2.1") //$NON-NLS-1$
				|| upperPseudoName.startsWith("SHA256") //$NON-NLS-1$
				|| upperPseudoName.startsWith("SHA-256")) { //$NON-NLS-1$
			return "SHA-256"; //$NON-NLS-1$
		}

		if (upperPseudoName.startsWith("SHA384") //$NON-NLS-1$
				|| upperPseudoName.equals("2.16.840.1.101.3.4.2.2") //$NON-NLS-1$
				|| upperPseudoName.startsWith("SHA-384")) { //$NON-NLS-1$
			return "SHA-384"; //$NON-NLS-1$
		}

		if (upperPseudoName.equals("http://www.w3.org/2001/04/xmlenc#sha512".toUpperCase(Locale.US))  //$NON-NLS-1$
				|| upperPseudoName.equals("2.16.840.1.101.3.4.2.3") //$NON-NLS-1$
				|| upperPseudoName.startsWith("SHA512") //$NON-NLS-1$
				|| upperPseudoName.startsWith("SHA-512")) { //$NON-NLS-1$
			return "SHA-512"; //$NON-NLS-1$
		}

		if (upperPseudoName.equals("http://www.w3.org/2001/04/xmlenc#ripemd160".toUpperCase(Locale.US))  //$NON-NLS-1$
				|| upperPseudoName.startsWith("RIPEMD160") //$NON-NLS-1$
				|| upperPseudoName.startsWith("RIPEMD-160")) { //$NON-NLS-1$
			return "RIPEMD160"; //$NON-NLS-1$
		}

		// Comprobamos si el nombre del algoritmo tiene un formato conocido de algoritmo de firma
		// e intentamos obtener el nombre del algoritmo de huella del mismo

		// Nombre estandar de algoritmo de firma
		if (pseudoName.contains("with")) { //$NON-NLS-1$
			final String subname = pseudoName.substring(0, pseudoName.indexOf("with")); //$NON-NLS-1$
			return getDigestAlgorithmName(subname);
		}
		// Algoritmo de firma XML
		else if (pseudoName.startsWith("http://www.w3.org/2001/04/xmldsig-more#") //$NON-NLS-1$
				|| pseudoName.startsWith("http://www.w3.org/2000/09/xmldsig#") //$NON-NLS-1$
				|| pseudoName.startsWith("http://www.w3.org/2009/xmldsig11#")) { //$NON-NLS-1$
			final String subname = pseudoName.substring(pseudoName.lastIndexOf('-') + 1);
			return getDigestAlgorithmName(subname);
		}

		// No se ha podido extraer el nombre del algoritmo
		Logger.getLogger("es.gob.afirma").warning( //$NON-NLS-1$
			"Algoritmo de huella desconocido, no se normalizara su nombre: " + pseudoName //$NON-NLS-1$
		);

		return pseudoName;
	}
}
