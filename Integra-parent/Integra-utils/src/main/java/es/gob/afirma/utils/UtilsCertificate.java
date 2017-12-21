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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * <p>Class that provides methods for managing certificates and private keys.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public final class UtilsCertificate {

    /**
     * Constructor method for the class UtilsCertificate.java.
     */
    private UtilsCertificate() {
    }

    /**
     * Method that canonicalizes a X.500 Principal of a certificate.
     * @param x500PrincipalName Parameter that represents the value of the X.500 Principal of the certificate to canonicalize.
     * @return the canonicalized X.500 Principal.
     */
    public static String canonicalizeX500Principal(String x500PrincipalName) {
	return UtilsCertificateCommons.canonicalizeX500Principal(x500PrincipalName);
    }

    /**
     * Method that obtains a certificate from the bytes array.
     * @param certificateBytes Parameter that represents the certificate.
     * @return an object that represents the certificate.
     * @throws CertificateException If there is a parsing error.
     */
    public static X509Certificate generateCertificate(byte[ ] certificateBytes) throws CertificateException {
	return UtilsCertificateCommons.generateCertificate(certificateBytes);
    }

    /**
     * Method that indicates whether some other certificate is "equal to" this one (true) or not (false).
     * @param cert1 Parameter that represents the first certificate to compare.
     * @param cert2 Parameter that represents the second certificate to compare.
     * @return a boolean that indicates whether some other certificate is "equal to" this one (true) or not (false).
     */
    public static boolean equals(X509Certificate cert1, X509Certificate cert2) {
	return UtilsCertificateCommons.equals(cert1, cert2);
    }

}
