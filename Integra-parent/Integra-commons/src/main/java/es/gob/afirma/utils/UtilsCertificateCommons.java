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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsCertificate.java.</p>
 * <b>Description:</b><p>Class that provides methods for managing certificates and private keys.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

/**
 * <p>Class that provides methods for managing certificates and private keys.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public final class UtilsCertificateCommons {

    /**
     * Constant that represents a comma separator.
     */
    private static final String COMMA_SEPARATOR = ",";

    /**
     * Constant that represents a equals character.
     */
    private static final String EQUALS_CHAR = "=";

    /**
     * Constructor method for the class UtilsCertificate.java.
     */
    private UtilsCertificateCommons() {
    }

    /**
     * Method that canonicalizes a X.500 Principal of a certificate.
     * @param x500PrincipalName Parameter that represents the value of the X.500 Principal of the certificate to canonicalize.
     * @return the canonicalized X.500 Principal.
     */
    public static String canonicalizeX500Principal(String x500PrincipalName) {
	if (x500PrincipalName.indexOf(EQUALS_CHAR) != -1) {
	    String[ ] campos = x500PrincipalName.split(COMMA_SEPARATOR);
	    Set<String> ordenados = new TreeSet<String>();
	    StringBuffer sb = new StringBuffer();
	    String[ ] pair;
	    int i = 0;
	    while (i < campos.length) {
		/*Puede darse el caso de que haya campos que incluyan comas, ejemplo:
		 *[OU=Class 3 Public Primary Certification Authority, O=VeriSign\\,  Inc., C=US]
		 */
		int currentIndex = i;
		// Lo primero es ver si estamos en el campo final y si el
		// siguiente campo no posee el símbolo igual, lo
		// concatenamos al actual
		while (i < campos.length - 1 && !campos[i + 1].contains(EQUALS_CHAR)) {
		    campos[currentIndex] += COMMA_SEPARATOR + campos[i + 1];
		    i++;
		}
		sb = new StringBuffer();
		pair = campos[currentIndex].trim().split(EQUALS_CHAR);
		sb.append(pair[0].toLowerCase());
		sb.append(EQUALS_CHAR);
		sb.append(pair[1]);
		ordenados.add(sb.toString());
		i++;
	    }
	    Iterator<String> it = ordenados.iterator();
	    sb = new StringBuffer();
	    while (it.hasNext()) {
		sb.append(it.next());
		sb.append(COMMA_SEPARATOR);
	    }
	    return sb.substring(0, sb.length() - 1);
	} else {
	    // No es un identificador de certificado, no se canonicaliza.
	    return x500PrincipalName;
	}
    }

    /**
     * Method that obtains a certificate from the bytes array.
     * @param certificateBytes Parameter that represents the certificate.
     * @return an object that represents the certificate.
     * @throws CertificateException If there is a parsing error.
     */
    public static X509Certificate generateCertificate(byte[ ] certificateBytes) throws CertificateException {
	InputStream is = null;
	try {
	    CertificateFactory certFactory;
	    try {
		certFactory = CertificateFactory.getInstance("X.509", "BC");
	    } catch (NoSuchProviderException e) {
		certFactory = CertificateFactory.getInstance("X.509");
	    }
	    is = new ByteArrayInputStream(certificateBytes);
	    return (X509Certificate) certFactory.generateCertificate(is);
	} finally {
	    UtilsResourcesCommons.safeCloseInputStream(is);
	}
    }

    /**
     * Method that indicates whether some other certificate is "equal to" this one (true) or not (false).
     * @param cert1 Parameter that represents the first certificate to compare.
     * @param cert2 Parameter that represents the second certificate to compare.
     * @return a boolean that indicates whether some other certificate is "equal to" this one (true) or not (false).
     */
    public static boolean equals(X509Certificate cert1, X509Certificate cert2) {
	boolean res = false;

	if (cert1 != null && cert2 != null) {
	    if (cert1.getPublicKey().equals(cert2.getPublicKey())) {
		String idEmisor1 = canonicalizeX500Principal(cert1.getIssuerDN().getName());
		String idEmisor2 = canonicalizeX500Principal(cert2.getIssuerDN().getName());
		if (idEmisor1 != null && idEmisor2 != null && idEmisor1.equalsIgnoreCase(idEmisor2)) {
		    if (cert1.getSerialNumber() != null && cert2.getSerialNumber() != null && cert1.getSerialNumber().compareTo(cert2.getSerialNumber()) == 0) {
			res = true;
		    } else {
			res = false;
		    }
		}
	    } else {
		res = false;
	    }
	}
	return res;
    }

}
