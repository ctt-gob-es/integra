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
 * <b>File:</b><p>es.gob.afirma.signature.SignerFactoryTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link SignersFactory}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.signature;

import es.gob.afirma.signature.cades.CadesSigner;
import es.gob.afirma.signature.pades.PadesSigner;
import es.gob.afirma.signature.xades.XadesSigner;

/**
 * <p>Class that defines tests for {@link SignersFactory}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public class SignerFactoryTest extends AbstractSignatureTest {

    /**
     * Tests for {@link SignersFactory#getSigner(String)}.
     * @throws Exception If the test fails.
     */
    public void testGetSigner() throws Exception {

	// test con valor nulo;
	try {
	    SignersFactory.getInstance().getSigner(null);
	    fail();
	} catch (SigningException e) {}
	// test con valor no válido (formato de firma no soportado)
	try {
	    assertNull(SignersFactory.getInstance().getSigner("CMS/PKCS#7"));
	    fail();
	} catch (SigningException e) {}

	// test con valores válidos (todos los tipos de firma)
	Signer signer = SignersFactory.getInstance().getSigner(SignatureConstants.SIGN_FORMAT_CADES);
	assertTrue(signer instanceof CadesSigner);

	signer = SignersFactory.getInstance().getSigner(SignatureConstants.SIGN_FORMAT_PADES);
	assertTrue(signer instanceof PadesSigner);

	signer = SignersFactory.getInstance().getSigner(SignatureConstants.SIGN_FORMAT_XADES_DETACHED);
	assertTrue(signer instanceof XadesSigner);

	signer = SignersFactory.getInstance().getSigner(SignatureConstants.SIGN_FORMAT_XADES_ENVELOPED);
	assertTrue(signer instanceof XadesSigner);

	signer = SignersFactory.getInstance().getSigner(SignatureConstants.SIGN_FORMAT_XADES_ENVELOPING);
	assertTrue(signer instanceof XadesSigner);

	signer = SignersFactory.getInstance().getSigner(SignatureConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED);
	assertTrue(signer instanceof XadesSigner);
    }

}
