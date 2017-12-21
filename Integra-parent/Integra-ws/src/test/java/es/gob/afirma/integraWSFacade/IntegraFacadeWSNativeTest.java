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
 * <b>File:</b><p>es.gob.afirma.integraWSFacade.IntegraFacadeWSNativeTest.java.</p>
 * <b>Description:</b><p>Class that defines tests for {@link IntegraFacadeWSNative}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.integraWSFacade;

import java.util.Map;

import junit.framework.TestCase;

import org.junit.Test;
import org.junit.runner.RunWith;

import es.gob.afirma.general.SorterRunner;
import es.gob.afirma.integraFacade.IntegraFacadeWSNative;
import es.gob.afirma.integraFacade.pojo.CertificateInfoRequest;
import es.gob.afirma.integraFacade.pojo.CertificateInfoResponse;
import es.gob.afirma.integraFacade.pojo.ContentRequest;
import es.gob.afirma.integraFacade.pojo.ContentResponse;
import es.gob.afirma.integraFacade.pojo.DocumentRequest;
import es.gob.afirma.integraFacade.pojo.DocumentResponse;
import es.gob.afirma.integraFacade.pojo.SignatureTransactionResponse;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that defines tests for {@link IntegraFacadeWSNative}.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 10/04/2015.
 */
@RunWith(SorterRunner.class)
public class IntegraFacadeWSNativeTest extends TestCase {

    /**
     * Constant attribute that represents the application name.
     */
    private static final String APPLICATION_NAME = "afirmaTest";

    /**
     * Constant attribute that represents certificate file name.
     */
    private static final String CERTIFICATE_NAME = "confianzaocsp.crt";

    /**
     * Test for {@link IntegraFacadeWSNative#storingDocument(DocumentRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testStoringDocument() throws Exception {

	// prueba almacenamiento o custodia documento con valores erróneos (sin
	// documento)

	byte[ ] content = UtilsFileSystemCommons.getArrayByteFileBase64Encoded("ficheroAfirmar.txt", true);

	// prueba almacenamiento o custodia documento con valores erróneos (sin
	// documento)
	DocumentRequest docReq = new DocumentRequest();
	docReq.setApplicationId(APPLICATION_NAME);
	docReq.setDocument(content);
	docReq.setName("ficheroAfirmar");
	docReq.setType("txt");

	DocumentResponse docRes = IntegraFacadeWSNative.getInstance().storingDocument(docReq);

	/* pruebas*/
	if (docRes != null) {
	    if (docRes.getError() != null) {
		System.out.println("DocRes ERROR.codigoError: " + docRes.getError().getCodeError());
		System.out.println("DocRes ERROR.descripción: " + docRes.getError().getDescription());
		assertTrue(false);
	    } else {
		System.out.println("DocRes:" + docRes.getDescription());
		System.out.println("DocRes.contenido:" + docRes.getDocumentId());
		System.out.println("DocRes.estado:" + docRes.isState());
	    }
	}
    }

    /**
     * Test for {@link IntegraFacadeWSNative#deleteDocumentContent(ContentRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testDeleteDocument() throws Exception {

	String idDocumento = "";

	byte[ ] content = UtilsFileSystemCommons.getArrayByteFileBase64Encoded("ficheroAfirmar.txt", true);

	// prueba almacenamiento o custodia documento con valores erróneos (sin
	// documento)
	DocumentRequest docReq = new DocumentRequest();
	docReq.setApplicationId(APPLICATION_NAME);
	docReq.setDocument(content);
	docReq.setName("ficheroAfirmar");
	docReq.setType("txt");

	DocumentResponse docRes = IntegraFacadeWSNative.getInstance().storingDocument(docReq);

	/* pruebas*/
	if (docRes != null) {
	    if (docRes.getError() == null) {

		idDocumento = docRes.getDocumentId();
	    }
	}

	// prueba eliminación del contenido de un documento
	ContentRequest conReq = new ContentRequest();
	conReq.setApplicationId(APPLICATION_NAME);
	conReq.setTransactionId(idDocumento);
	ContentResponse conRes = IntegraFacadeWSNative.getInstance().deleteDocumentContent(conReq);

	/*pruebas*/
	if (conRes != null) {
	    if (conRes.getError() != null) {
		System.out.println("ConRes ERROR.codigoError: " + conRes.getError().getCodeError());
		System.out.println("ConRes ERROR.descripción: " + conRes.getError().getDescription());
		assertTrue(false);
	    } else {
		System.out.println("ConREs:" + conRes.getDescription());
		System.out.println("ConRes.estado:" + conRes.isState());
	    }
	}

    }

    /**
     * Test for {@link IntegraFacadeWSNative#getDocumentContent(ContentRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGetDocumentContent() throws Exception {

	// prueba obtener contenido de documento con valores erróneos (sin
	// documento)
	String idTransaction = "145346464856296185";

	ContentRequest conReq = new ContentRequest();
	conReq.setApplicationId(APPLICATION_NAME);
	conReq.setTransactionId(idTransaction);
	ContentResponse conRes = IntegraFacadeWSNative.getInstance().getDocumentContent(conReq);

	/* pruebas*/

	if (conRes != null) {
	    if (conRes.getError() != null) {
		System.out.println("ConRes ERROR.codigoError: " + conRes.getError().getCodeError());
		System.out.println("ConRes ERROR.descripción: " + conRes.getError().getDescription());
		assertTrue(false);
	    } else {
		System.out.println("ConREs:" + conRes.getDescription());
		System.out.println("conRes.contenido:" + conRes.getContent());
		System.out.println("ConRes.estado:" + conRes.isState());
	    }
	}

    }

    /**
     * Test for {@link IntegraFacadeWSNative#getContentDocumentId(ContentRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGetContentDocumentId() throws Exception {

	// prueba obtener contenido de documento con valores erróneos (sin
	// documento)
	String idDocument = "2";

	ContentRequest conReq = new ContentRequest();
	conReq.setApplicationId(APPLICATION_NAME);
	conReq.setTransactionId(idDocument);
	ContentResponse conRes = IntegraFacadeWSNative.getInstance().getContentDocumentId(conReq);

	/* pruebas*/

	if (conRes != null) {
	    if (conRes.getError() != null) {
		System.out.println("ConRes ERROR.codigoError: " + conRes.getError().getCodeError());
		System.out.println("ConRes ERROR.descripción: " + conRes.getError().getDescription());
		assertTrue(false);
	    } else {
		System.out.println("ConREs:" + conRes.getDescription());
		System.out.println("conRes.contenido:" + conRes.getContent());
		System.out.println("ConRes.estado:" + conRes.isState());
	    }
	}

    }

    /**
     * Test for {@link IntegraFacadeWSNative#getDocumentId(ContentRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGetIdDocument() throws Exception {

	// prueba obtener contenido de documento con valores erróneos (sin
	// documento)
	String idTransaction = "145346464856296185";

	ContentRequest conReq = new ContentRequest();
	conReq.setApplicationId(APPLICATION_NAME);
	conReq.setTransactionId(idTransaction);
	ContentResponse conRes = IntegraFacadeWSNative.getInstance().getDocumentId(conReq);

	/* pruebas*/

	if (conRes != null) {
	    if (conRes.getError() != null) {
		System.out.println("ConRes ERROR.codigoError: " + conRes.getError().getCodeError());
		System.out.println("ConRes ERROR.descripción: " + conRes.getError().getDescription());
		assertTrue(false);
	    } else {
		System.out.println("ConREs:" + conRes.getDescription());
		System.out.println("conRes.idDocumento:" + conRes.getContent());
		System.out.println("ConRes.estado:" + conRes.isState());
	    }
	}

    }

    /**
     * Test for {@link IntegraFacadeWSNative#getSignatureTransaction(ContentRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGetSignatureTransaction() throws Exception {

	// prueba obtener contenido de documento con valores erróneos (sin
	// documento)
	String idTransaction = "145346464856296185";

	ContentRequest conReq = new ContentRequest();
	conReq.setApplicationId(APPLICATION_NAME);
	conReq.setTransactionId(idTransaction);
	SignatureTransactionResponse sigTraRes = IntegraFacadeWSNative.getInstance().getSignatureTransaction(conReq);

	/* pruebas*/

	if (sigTraRes != null) {
	    if (sigTraRes.getError() != null) {
		System.out.println("SigTraRes ERROR.codigoError: " + sigTraRes.getError().getCodeError());
		System.out.println("SigTraRes ERROR.descripción: " + sigTraRes.getError().getDescription());
		assertTrue(false);
	    } else {
		System.out.println("SigTraRes:" + sigTraRes.getDescription());
		System.out.println("SigTraRes.firmaElectronica:" + sigTraRes.getSignature());
		System.out.println("SigTraRes.estado:" + sigTraRes.isState());
		System.out.println("SigTraREs.formato firma" + sigTraRes.getSignatureFormat());
	    }
	}
    }

    /**
     * Test for {@link IntegraFacadeWSNative#getCertificateInfo(CertificateInfoRequest)}.
     * @throws Exception If the test fails.
     */
    @Test
    public void testGetCertificateInfo() throws Exception {

	byte[ ] certificate = UtilsFileSystemCommons.readFileBase64Encoded(CERTIFICATE_NAME, true).getBytes();
	CertificateInfoRequest cerInfReq = new CertificateInfoRequest();
	cerInfReq.setApplicationId(APPLICATION_NAME);
	cerInfReq.setCertificate(certificate);
	CertificateInfoResponse cerInfRes = IntegraFacadeWSNative.getInstance().getCertificateInfo(cerInfReq);

	/* pruebas*/
	if (cerInfRes != null) {
	    if (cerInfRes.getError() != null) {
		System.out.println("CerInfRes ERROR.codigoError: " + cerInfRes.getError().getCodeError());
		System.out.println("CerInfRes ERROR.descripción: " + cerInfRes.getError().getDescription());
		assertTrue(false);
	    } else {
		Map<String, Object> mapResult = cerInfRes.getMapInfoCertificate();
		if (mapResult != null && !mapResult.isEmpty()) {
		    for (String key: mapResult.keySet()) {
			System.out.println("Resultado:\n");
			System.out.println("(" + key + "," + mapResult.get(key).toString() + ")");
		    }
		}
	    }
	}
    }
}
