// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.encryption.CipherIntegraTest.java.</p>
 * <b>Description:</b><p> .</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>07/03/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 07/03/2016.
 */
package es.gob.afirma.encryption;

import static org.junit.Assert.assertTrue;
import static org.junit.matchers.JUnitMatchers.containsString;

import java.io.File;
import java.io.FileInputStream;
import java.io.Serializable;
import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import es.gob.afirma.exception.CipherException;
import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;

/** 
 * <p>Test class based on JUnit framework for {@link CipherIntegra}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 07/03/2016.
 */
public class CipherIntegraTest implements Serializable {

    /**
     * Attribute that represents the class serial version. 
     */
    private static final long serialVersionUID = -8508277512648660284L;

    /**
     * Attribute that represents the class that implements the operations to encrypt and descrypt messages.
     */
    private CipherIntegra cipherIntegra;

    /**
     * Attribute that represents the identifiers of the different ciphers.
     */
    private AlgorithmCipherEnum algorithmTest;

    /**
     * Attribute that represents the used key for encryption/decryption of messages.
     */
    private Key keyAes;

    /**
     * Attribute that represents the used key for encryption/decryption of messages.
     */
    private Key keyDes;

    /**
     * Constant Attribute that represents a key path.
     */
    private static final String KEY_PATH = "src/test/resources/keyAES/key.key";

    /**
     * Constant Attribute that represents the AES algorithm.
     */
    private static final String ALGORITHM_AES = "AES";

    /**
     * Constant Attribute that represents the DES algorithm.
     */
    private static final String ALGORITHM_DES = "DES";

    /**
     * Constant Attribute that represents the text to be encrypted in the tests.
     */
    private static final String TEXT = "Prueba de cifrado.";

    /**
     * Constant Attribute that represents the text.
     */
    private static final String CIPHER_TEXT = "+ptk2U6CeAeVkQgLQV10CimK/iIeNTvCPna0xtPSnlc=";

    /**
     * Attribute to specify expected exception types and messages.
     */
    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    /**
     * 
     * @throws java.lang.Exception If method fails.
     */
    @Before
    public final void setUp() throws Exception {
	// usamos algoritmo AES
	algorithmTest = AlgorithmCipherEnum.AES;
	// cargamos un clave para pruebas
	File fileKey = new File(KEY_PATH);
	FileInputStream fis = new FileInputStream(KEY_PATH);
	byte[ ] encodedKey = new byte[(int) fileKey.length()];
	fis.read(encodedKey);
	fis.close();
	keyAes = new SecretKeySpec(encodedKey, ALGORITHM_AES);
	keyDes = new SecretKeySpec(encodedKey, ALGORITHM_DES);

    }

    /**
     * 
     * @throws java.lang.Exception If method fails.
     */
    @After
    public void tearDown() throws Exception {
    }

    /**
     *  Test for {@link CipherIntegra#encrypt(String)}.
     * 
     * @throws CipherException If method fails
     */
    @Test
    public final void test1() throws CipherException {
	// Test para un funcionamiento normal
	cipherIntegra = new CipherIntegra(algorithmTest, keyAes);
	String cipherText = cipherIntegra.encrypt(TEXT);
	assertTrue(cipherText.equals(CIPHER_TEXT));
    }

    /**
     *  Test for {@link CipherIntegra#encrypt(String)}.
     * @throws Exception If test fails.
     */
    @Test
    public final void test2() throws Exception {
	// Test para un funcionamiento incorrecto, pasándole una key inválida.Se
	// constructor, pasándole algoritmo de cifrado no compatible con la
	// clave para cifrar.
	expectedEx.expect(CipherException.class);
	expectedEx.expectMessage(containsString(Language.getResIntegra(ILogConstantKeys.IE_LOG009)));
	cipherIntegra = new CipherIntegra(algorithmTest, keyDes);
	cipherIntegra.encrypt(TEXT);

    }

    /**
     *  Test for {@link CipherIntegra#CipherIntegra(AlgorithmCipherEnum, java.security.Key)}.
     * @throws Exception 
     * 
     * @throws Exception If test fails.
     */
    @Test
    public final void test3() throws Exception {
	// Test para un funcionamiento incorrecto, pasándole al constructor
	// algún parámetro nulo.
	expectedEx.expect(CipherException.class);
	expectedEx.expectMessage(Language.getResIntegra(ILogConstantKeys.IE_LOG008));
	cipherIntegra = new CipherIntegra(null, keyAes);

    }

    /**
     *  Test for {@link CipherIntegra#decrypt(String)}.
     * 
     * @throws Exception If test fails.
     */
    @Test
    public final void test4() throws Exception {
	// Test para un funcionamiento normal
	cipherIntegra = new CipherIntegra(algorithmTest, keyAes);
	String decryptedText = cipherIntegra.decrypt(CIPHER_TEXT);
	assertTrue(decryptedText.equals(TEXT));


    }

    /**
     *  Test for {@link CipherIntegra#decrypt(String)}.
     * @throws Exception  If test fails.
     */
    @Test
    public final void test5() throws Exception {
	// Test para un funcionamiento incorrecto, pasándole una key inválida.Se
	// constructor, pasándole algoritmo de cifrado no compatible con la
	// clave para descifrar.
	expectedEx.expect(CipherException.class);
	expectedEx.expectMessage(containsString(Language.getResIntegra(ILogConstantKeys.IE_LOG010)));
	cipherIntegra = new CipherIntegra(algorithmTest, keyDes);
	cipherIntegra.decrypt(TEXT);
    }

}
