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
 * <b>File:</b><p>es.gob.afirma.signature.SignatureFormatDetectorTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link SignatureFormatDetector}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.signature;

import junit.framework.TestCase;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that defines tests for {@link SignatureFormatDetector}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public class SignatureFormatDetectorTest extends TestCase {

    /**
     * Method that tests all the allowed ASN.1 signature formats.
     */
    public final void testASN1Signatures() {

	/*
	 * Test 1: Obtener el formato de una firma CAdES-BES
	 */
	byte[ ] cadesBES = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-BES.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesBES).equals(SignatureFormatDetector.FORMAT_CADES_BES) && !SignatureFormatDetector.getSignatureFormat(cadesBES).equals(SignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Obtener el formato de una firma CAdES-EPES
	 */
	byte[ ] cadesEPES = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-EPES.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesEPES).equals(SignatureFormatDetector.FORMAT_CADES_EPES) && !SignatureFormatDetector.getSignatureFormat(cadesBES).equals(SignatureFormatDetector.FORMAT_CADES_B_LEVEL)) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Obtener el formato de una firma CAdES-T
	 */
	byte[ ] cadesT = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-T.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesT).equals(SignatureFormatDetector.FORMAT_CADES_T) && !SignatureFormatDetector.getSignatureFormat(cadesT).equals(SignatureFormatDetector.FORMAT_CADES_T_LEVEL)) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Obtener el formato de una firma CAdES-C
	 */
	byte[ ] cadesC = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-C.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesC).equals(SignatureFormatDetector.FORMAT_CADES_C)) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Obtener el formato de una firma CAdES-X1
	 */
	byte[ ] cadesX1 = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-X1.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesX1).equals(SignatureFormatDetector.FORMAT_CADES_X1)) {
	    assertTrue(false);
	}

	/*
	 * Test 6: Obtener el formato de una firma CAdES-X2
	 */
	byte[ ] cadesX2 = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-X2.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesX2).equals(SignatureFormatDetector.FORMAT_CADES_X2)) {
	    assertTrue(false);
	}

	/*
	 * Test 7: Obtener el formato de una firma CAdES-XL1
	 */
	byte[ ] cadesXL1 = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-XL1.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesXL1).equals(SignatureFormatDetector.FORMAT_CADES_XL1)) {
	    assertTrue(false);
	}

	/*
	 * Test 8: Obtener el formato de una firma CAdES-XL2
	 */
	byte[ ] cadesXL2 = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-XL2.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesXL2).equals(SignatureFormatDetector.FORMAT_CADES_XL2)) {
	    assertTrue(false);
	}

	/*
	 * Test 9: Obtener el formato de una firma CAdES-A
	 */
	byte[ ] cadesA = UtilsFileSystemCommons.readFile("signatures/ASN1/CAdES-A.p7s", true);
	if (!SignatureFormatDetector.getSignatureFormat(cadesA).equals(SignatureFormatDetector.FORMAT_CADES_A)) {
	    assertTrue(false);
	}
    }

    /**
     * Method that tests all the allowed XML signature formats.
     */
    public final void testXMLSignatures() {
	/*
	 * Test 1: Obtener el formato de una firma XAdES-BES
	 */
	byte[ ] xadesBES = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-BES.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesBES).equals(SignatureFormatDetector.FORMAT_XADES_BES) && !SignatureFormatDetector.getSignatureFormat(xadesBES).equals(SignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Obtener el formato de una firma XAdES-EPES
	 */
	byte[ ] xadesEPES = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-EPES.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesEPES).equals(SignatureFormatDetector.FORMAT_XADES_EPES) && !SignatureFormatDetector.getSignatureFormat(xadesEPES).equals(SignatureFormatDetector.FORMAT_XADES_B_LEVEL)) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Obtener el formato de una firma XAdES-T
	 */
	byte[ ] xadesT = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-T.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesT).equals(SignatureFormatDetector.FORMAT_XADES_T) && !SignatureFormatDetector.getSignatureFormat(xadesT).equals(SignatureFormatDetector.FORMAT_XADES_T_LEVEL)) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Obtener el formato de una firma XAdES-C
	 */
	byte[ ] xadesC = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-C.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesC).equals(SignatureFormatDetector.FORMAT_XADES_C)) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Obtener el formato de una firma XAdES-X1
	 */
	byte[ ] xadesX1 = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-X1.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesX1).equals(SignatureFormatDetector.FORMAT_XADES_X1)) {
	    assertTrue(false);
	}

	/*
	 * Test 6: Obtener el formato de una firma XAdES-X2
	 */
	byte[ ] xadesX2 = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-X2.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesX2).equals(SignatureFormatDetector.FORMAT_XADES_X2)) {
	    assertTrue(false);
	}

	/*
	 * Test 7: Obtener el formato de una firma XAdES-XL1
	 */
	byte[ ] xadesXL1 = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-XL1.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesXL1).equals(SignatureFormatDetector.FORMAT_XADES_XL1)) {
	    assertTrue(false);
	}

	/*
	 * Test 8: Obtener el formato de una firma XAdES-XL2
	 */
	byte[ ] xadesXL2 = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-XL2.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesXL2).equals(SignatureFormatDetector.FORMAT_XADES_XL2)) {
	    assertTrue(false);
	}

	/*
	 * Test 9: Obtener el formato de una firma XAdES-A
	 */
	byte[ ] xadesA = UtilsFileSystemCommons.readFile("signatures/XML/XAdES-A.xml", true);
	if (!SignatureFormatDetector.getSignatureFormat(xadesA).equals(SignatureFormatDetector.FORMAT_XADES_A)) {
	    assertTrue(false);
	}
    }

    /**
     * Method that tests all the allowed PDF signature formats.
     */
    public final void testPDFSignatures() {
	/*
	 * Test 1: Obtener el formato de una firma PDF
	 */
	byte[ ] pdf = UtilsFileSystemCommons.readFile("signatures/PDF/PDF.pdf", true);
	if (!SignatureFormatDetector.getSignatureFormat(pdf).equals(SignatureFormatDetector.FORMAT_PDF)) {
	    assertTrue(false);
	}

	/*
	 * Test 2: Obtener el formato de una firma PAdES-Basic
	 */
	byte[ ] padesBasic = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-Basic.pdf", true);
	if (!SignatureFormatDetector.getSignatureFormat(padesBasic).equals(SignatureFormatDetector.FORMAT_PADES_BASIC)) {
	    assertTrue(false);
	}

	/*
	 * Test 3: Obtener el formato de una firma PAdES-BES
	 */
	byte[ ] padesBES = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-BES.pdf", true);
	if (!SignatureFormatDetector.getSignatureFormat(padesBES).equals(SignatureFormatDetector.FORMAT_PADES_BES) && !SignatureFormatDetector.getSignatureFormat(padesBES).equals(SignatureFormatDetector.FORMAT_PADES_B_LEVEL)) {
	    assertTrue(false);
	}

	/*
	 * Test 4: Obtener el formato de una firma PAdES-EPES
	 */
	byte[ ] padesEPES = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-EPES.pdf", true);
	if (!SignatureFormatDetector.getSignatureFormat(padesEPES).equals(SignatureFormatDetector.FORMAT_PADES_EPES) && !SignatureFormatDetector.getSignatureFormat(padesEPES).equals(SignatureFormatDetector.FORMAT_PADES_B_LEVEL)) {
	    assertTrue(false);
	}

	/*
	 * Test 5: Obtener el formato de una firma PAdES-LTV
	 */
	byte[ ] padesLTV = UtilsFileSystemCommons.readFile("signatures/PDF/PAdES-LTV.pdf", true);
	if (!SignatureFormatDetector.getSignatureFormat(padesLTV).equals(SignatureFormatDetector.FORMAT_PADES_LTV)) {
	    assertTrue(false);
	}
      }

}
