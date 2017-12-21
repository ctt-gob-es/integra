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
 * <b>File:</b><p>es.gob.afirma.utils.Base64CoderTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link Base64Coder}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.utils;

import junit.framework.TestCase;
import es.gob.afirma.transformers.TransformersException;

/**
 * <p>Class that defines tests for {@link Base64Coder}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public final class Base64CoderTest extends TestCase {

    /**
     * Constant attribute that represents a text for tests encoded on ASCII.
     */
    private final String ASCII_SAMPLE = "This an example..@Ññàèìòù%$!?¿Z[]^_`}~";

    /**
     * Constant attribute that represents a text for tests encoded on Base64.
     */
    private final String BASE64_ENCODED_SAMPLE = "VGhpcyBhbiBleGFtcGxlLi5Aw5HDscOgw6jDrMOyw7klJCE/wr9aW11eX2B9fg==";

    /**
     * Tests for {@link Base64Coder#decodeBase64(byte[])}, {@link Base64Coder#decodeBase64(String)} and {@link Base64Coder#decodeBase64(byte[], int, int)}.
     * @throws Exception If the test fails.
     */
    public void testDecodeBase64() throws Exception {

	// tests with invalid parameters.
	String nullData = null;
	try {
	    Base64Coder.decodeBase64(nullData);
	    fail("No se ha lanzado la excepción");
	} catch (TransformersException e) {}

	Base64Coder.decodeBase64("");
	Base64Coder.decodeBase64(new byte[0]);
	try {
	    Base64Coder.decodeBase64(null, 0, 0);
	    fail("No se ha lanzado la excepción");
	} catch (TransformersException e) {}
	// test with byte array
	byte[ ] result = Base64Coder.decodeBase64(BASE64_ENCODED_SAMPLE.getBytes());
	assertEquals(ASCII_SAMPLE, new String(result));
	// test with all parameters
	result = Base64Coder.decodeBase64(BASE64_ENCODED_SAMPLE.getBytes(), 0, BASE64_ENCODED_SAMPLE.getBytes().length);
	assertEquals(ASCII_SAMPLE, new String(result));

	// test with string
	assertEquals(ASCII_SAMPLE, Base64Coder.decodeBase64(BASE64_ENCODED_SAMPLE));
    }

    /**
     * Tests for {@link Base64Coder#encodeBase64(byte[])}, {@link Base64Coder#encodeBase64(String)} and {@link Base64Coder#encodeBase64(byte[], int, int)}.
     * @throws Exception If the test fails.
     */
    public void testEncodeBase64() throws Exception {
	// tests with invalid parameters.
	String nullData = null;
	try {
	    Base64Coder.encodeBase64(nullData);
	    fail("No se ha lanzado la excepción");
	} catch (TransformersException e) {}

	Base64Coder.encodeBase64("");
	Base64Coder.encodeBase64(new byte[0]);

	try {
	    Base64Coder.encodeBase64(null, 0, 0);
	    fail("No se ha lanzado la excepción");
	} catch (TransformersException e) {}

	// test with byte array
	byte[ ] result = Base64Coder.encodeBase64(ASCII_SAMPLE.getBytes());
	assertEquals(BASE64_ENCODED_SAMPLE, new String(result));

	// test with all parameters
	result = Base64Coder.encodeBase64(ASCII_SAMPLE.getBytes(), 0, ASCII_SAMPLE.getBytes().length);
	assertEquals(BASE64_ENCODED_SAMPLE, new String(result));

	// test with string
	assertEquals(BASE64_ENCODED_SAMPLE, Base64Coder.encodeBase64(ASCII_SAMPLE));
    }

    /**
     * Tests for {@link Base64Coder#isBase64Encoded(byte[])}.
     * @throws Exception If the test fails.
     */
    public void testIsBase64Encoded() throws Exception {
	assertTrue(Base64Coder.isBase64Encoded(BASE64_ENCODED_SAMPLE.getBytes()));
	assertFalse(Base64Coder.isBase64Encoded(ASCII_SAMPLE.getBytes()));
    }

}
