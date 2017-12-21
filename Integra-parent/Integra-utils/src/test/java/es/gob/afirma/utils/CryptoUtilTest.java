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
 * <b>File:</b><p>es.gob.afirma.utils.CryptoUtilTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link CryptoUtil}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.utils;

import junit.framework.TestCase;

/**
 * <p>Class that defines tests for {@link CryptoUtil}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public final class CryptoUtilTest extends TestCase {

    /**
     * Tests for {@link CryptoUtil#digest(String, byte[])}.
     * @throws Exception If the test fails.
     */
    public void testDigest() throws Exception {
	byte[ ] data = "Test_prueba".getBytes();

	byte[ ] hash = CryptoUtil.digest(CryptoUtil.HASH_ALGORITHM_SHA1, data);
	String hashEncoded = new String(Base64Coder.encodeBase64(hash));
	assertEquals("71OLp4USkobZLnrT7Xvz2lELNAU=", hashEncoded);

	hash = CryptoUtil.digest(CryptoUtil.HASH_ALGORITHM_SHA256, data);
	hashEncoded = new String(Base64Coder.encodeBase64(hash));
	assertEquals("nuK6g3/q0exjbwildPBINNu7B/pd25XWcodW+kbSGc8=", hashEncoded);

	hash = CryptoUtil.digest(CryptoUtil.HASH_ALGORITHM_SHA384, data);
	hashEncoded = new String(Base64Coder.encodeBase64(hash));
	assertEquals("LqXgsJ9tQajoll8IKXQRJWpE/sJeiNjUSKJVYo6oESzKkhQNJuc4kjNyCHEcXcb/", hashEncoded);

	hash = CryptoUtil.digest(CryptoUtil.HASH_ALGORITHM_SHA512, data);
	hashEncoded = new String(Base64Coder.encodeBase64(hash));
	assertEquals("rvGVeH3jYDC5klpLr0kdwDVQ/2ENcuKNGByR0ooXYIu7HKqTdRBbBfHOC8sdV+8FAa1uery4Oc4L\nzFyuDVcbLw==", hashEncoded);

    }

}
