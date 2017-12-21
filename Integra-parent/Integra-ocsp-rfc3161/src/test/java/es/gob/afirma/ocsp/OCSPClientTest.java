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
 * <b>File:</b><p>es.gob.afirma.ocsp.OCSPClientTest.java.</p>
 * <b>Description:</b><p>Class that allows to tests the certificates validation against an OCSP server.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * <b>Date:</b><p>08/05/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 08/05/2015.
 */
package es.gob.afirma.ocsp;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

/**
 * <p>Class that allows to tests the certificates validation against an OCSP server.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 08/05/2015.
 */
public class OCSPClientTest extends TestCase {

    /**
     * Tests for {@link OCSPClient#validateCertificate(java.security.cert.X509Certificate)}.
     */
    public void testOCSPClient() {

	/*
	 * Test 1: Argumento nulo
	 */
	try {
	    OCSPClient.validateCertificate(null);
	    assertTrue(false);
	} catch (Exception e) {
	    assertTrue(true);
	}

	/*
	 * Test 2: Argumento correcto
	 */
	try {
	    OCSPEnhancedResponse ocspResponse = OCSPClient.validateCertificate(getCertificate());
	    System.out.println("OCSP response status --> " + ocspResponse.getStatus());
	    System.out.println("Revocation date --> " + ocspResponse.getRevocationDate());
	    System.out.println("Error message --> " + ocspResponse.getErrorMsg());
	    System.out.println("Date when the cached response expires --> " + ocspResponse.getMaxAge());
	} catch (Exception e) {
	    assertTrue(false);
	}
    }

    protected static X509Certificate getCertificate() {
	X509Certificate certificate = null;
	try {
	    InputStream is = new FileInputStream(ClassLoader.getSystemResource("keyStoreJCEKS.jks").getFile());
	    KeyStore ks = KeyStore.getInstance("JCEKS");
	    char[ ] password = "12345".toCharArray();
	    ks.load(is, password);
	    certificate = (X509Certificate) ks.getCertificate("raul conde");
	} catch (NoSuchAlgorithmException e) {
	    e.printStackTrace();
	} catch (CertificateException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (KeyStoreException e) {
	    e.printStackTrace();
	}

	return certificate;
    }
}
