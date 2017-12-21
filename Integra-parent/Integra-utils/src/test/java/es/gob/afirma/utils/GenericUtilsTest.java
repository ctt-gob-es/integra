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
 * <b>File:</b><p>es.gob.afirma.utils.GenericUtilsTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link GenericUtils}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.utils;

import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

/**
 * <p>Class that defines tests for {@link GenericUtils}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public class GenericUtilsTest extends TestCase {

    /**
     * Tests for {@link GenericUtils#getValueFromMapsTree(String, Map)}.
     * @throws Exception If the test fails.
     */
    public void testGetValueFromMapsTree() throws Exception {
	Map<String, Object> data = new HashMap<String, Object>();
	Map<String, Object> data1 = new HashMap<String, Object>();
	Map<String, Object> data2 = new HashMap<String, Object>();
	data2.put("conclusion", "Firma correcta");
	data1.put("descripcion", data2);
	data.put("respuesta", data1);
	data.put("respuesta2", "data");

	// valores nulos
	assertNull(GenericUtils.getValueFromMapsTree(null, null));

	// valores no válidos
	assertNull(GenericUtils.getValueFromMapsTree("", null));
	assertNull(GenericUtils.getValueFromMapsTree("novalido", new HashMap<String, Object>()));
	// rutas erróneas
	assertNull(GenericUtils.getValueFromMapsTree("respuesta2/descripcion/conclusion", data));

	// valores válidos
	assertEquals("Firma correcta", GenericUtils.getValueFromMapsTree("respuesta/descripcion/conclusion", data));
	assertEquals("data", GenericUtils.getValueFromMapsTree("respuesta2", data));
    }

}
