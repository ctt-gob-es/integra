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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsFileSystemTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link UtilsFileSystem}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.utils;

import junit.framework.TestCase;

/**
 * <p>Class that defines tests for {@link UtilsFileSystem}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public class UtilsFileSystemTest extends TestCase {

    /**
     * Tests for {@link UtilsFileSystem#readFileBase64Encoded(String, boolean)}.
     * @throws Exception If the test fails.
     */
    public void testReadFileBase64Encoded() throws Exception {
	// prueba con valor nulo.
	try {
	    assertNull(UtilsFileSystem.readFileBase64Encoded(null, false));
	} catch (IllegalArgumentException e) {}

	// prueba con valor no válido.
	assertNull(UtilsFileSystem.readFileBase64Encoded("/s", false));

	// prueba con valor válido.
	assertEquals(13252, UtilsFileSystem.readFileBase64Encoded("ficheroAfirmar.txt", true).length());
    }

    /**
     * Tests for {@link UtilsFileSystem#readFile(String, boolean)}.
     * @throws Exception If the test fails.
     */
    public void testReadFile() throws Exception {
	// prueba con valor nulo.
	try {
	    assertNull(UtilsFileSystem.readFile(null, false));
	} catch (IllegalArgumentException e) {}

	// //prueba con valor no válido.
	assertNull(UtilsFileSystem.readFile("/s", false));

	// prueba con valor válido.
	assertEquals(9810, UtilsFileSystem.readFile("ficheroAfirmar.txt", true).length);
    }

    /**
     * Tests for {@link UtilsFileSystem#writeFile(byte[], String)}.
     * @throws Exception If the test fails.
     */
    public void testWriteFile() throws Exception {

	// prueba con valores nulos
	try {
	    UtilsFileSystem.writeFile(null, null);
	    fail("No se ha lanzado la excepción esperada");
	} catch (IllegalArgumentException e) {}

	// prueba con valores no válidos
	try {
	    UtilsFileSystem.writeFile(new byte[0], "");
	    fail("No se ha lanzado la excepción esperada");
	} catch (IllegalArgumentException e) {}

    }
}
