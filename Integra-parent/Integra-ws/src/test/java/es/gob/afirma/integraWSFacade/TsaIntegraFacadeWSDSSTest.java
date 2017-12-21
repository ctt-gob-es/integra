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
 * <b>File:</b><p>es.gob.afirma.testwebservices.DSSServicesTest.java.</p>
 * <b>Description:</b><p>Class that allows to tests the @Firma and TS@ DSS services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>015/03/2016.</p>
 * @author Javier Pantoja.
 * @version 1.0, 15/03/2016.
 */
package es.gob.afirma.integraWSFacade;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.apache.xml.security.c14n.Canonicalizer;

import es.gob.afirma.integraFacade.TsaIntegraFacadeWSDSS;
import es.gob.afirma.integraFacade.pojo.DocumentHash;
import es.gob.afirma.integraFacade.pojo.DocumentTypeEnum;
import es.gob.afirma.integraFacade.pojo.HashAlgorithmEnum;
import es.gob.afirma.integraFacade.pojo.TimestampRequest;
import es.gob.afirma.integraFacade.pojo.TimestampResponse;
import es.gob.afirma.integraFacade.pojo.TimestampTypeEnum;
import es.gob.afirma.integraFacade.pojo.TransformData;
import es.gob.afirma.utils.CryptoUtilXML;
import es.gob.afirma.utils.DSSConstants;
import es.gob.afirma.utils.DSSTagsResponse;
import es.gob.afirma.utils.DSSConstants.ResultProcessIds;
import es.gob.afirma.utils.UtilsFileSystemCommons;

/**
 * <p>Class that allows to tests the @Firma and TS@ DSS services.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 13/04/2015.
 */
public class TsaIntegraFacadeWSDSSTest extends TestCase {

    /**
     * Attribute that represents tsa application name for tests.
     */
    private static final String TSA_APPLICATION_NAME = "pruebasTest";

    /**
     * Method that tests the DSS services from TS@.
     */
    public void testDSSTimestampTSAIntegra() {

	TimestampRequest timestampReq = new TimestampRequest();
	DocumentHash docH = new DocumentHash();
	byte[ ] file;
	List<String> canonicalizer;

	/*
	 * Prueba 1a:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: DocumentHash
	 */

	// Obtenemos el fichero que se va a sellar

	file = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.DOCUMENT_HASH);
	docH.setDigestValue(file);
	docH.setDigestMethod(HashAlgorithmEnum.SHA1);
	timestampReq.setDocumentHash(docH);

	timestampReq.setTimestampType(TimestampTypeEnum.XML);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */

	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 1b:
	 * - Tipo de Sello de Tiempo: RFC 3161
	 * - Input Document: DocumentHash
	 */

	file = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.DOCUMENT_HASH);
	docH.setDigestValue(file);
	docH.setDigestMethod(HashAlgorithmEnum.SHA1);
	timestampReq.setDocumentHash(docH);

	timestampReq.setTimestampType(TimestampTypeEnum.RFC_3161);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 2a:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: DocumentHash con transformada
	 */
	// Obtenemos el fichero que se va a sellar

	file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);

	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.DOCUMENT_HASH_TRANSFORMED_DATA);
	docH = new DocumentHash();
	canonicalizer = new ArrayList<>();
	canonicalizer.add(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	TransformData td = new TransformData("SHA1", canonicalizer);
	docH.setTransform(td);
//	if (HashAlgorithmEnum.SHA1.equals(CryptoUtilXML.translateDigestAlgorithmToXMLURI(td.getAlgorithm()))) {
	    docH.setDigestMethod(HashAlgorithmEnum.SHA1);
//	} else if (HashAlgorithmEnum.SHA256.equals(CryptoUtilXML.translateDigestAlgorithmToXMLURI(td.getAlgorithm()))) {
//	    docH.setDigestMethod(HashAlgorithmEnum.SHA256);
//	} else if (HashAlgorithmEnum.SHA384.equals(CryptoUtilXML.translateDigestAlgorithmToXMLURI(td.getAlgorithm()))) {
//	    docH.setDigestMethod(HashAlgorithmEnum.SHA384);
//	} else if (HashAlgorithmEnum.SHA512.equals(CryptoUtilXML.translateDigestAlgorithmToXMLURI(td.getAlgorithm()))) {
//	    docH.setDigestMethod(HashAlgorithmEnum.SHA512);
//	}
	docH.setDigestValue(file);
	timestampReq.setDocumentHash(docH);

	timestampReq.setTimestampType(TimestampTypeEnum.XML);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 2b:
	 * - Tipo de Sello de Tiempo: RFC 3161
	 * - Input Document: DocumentHash con transformada
	 */

	file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);

	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.DOCUMENT_HASH_TRANSFORMED_DATA);
	docH = new DocumentHash();
	canonicalizer = new ArrayList<>();
	canonicalizer.add(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	td = new TransformData("SHA1", canonicalizer);
	docH.setTransform(td);
//	if (HashAlgorithmEnum.SHA1.equals(CryptoUtilXML.translateDigestAlgorithmToXMLURI(td.getAlgorithm()))) {
	    docH.setDigestMethod(HashAlgorithmEnum.SHA1);
//	} else if (HashAlgorithmEnum.SHA256.equals(CryptoUtilXML.translateDigestAlgorithmToXMLURI(td.getAlgorithm()))) {
//	    docH.setDigestMethod(HashAlgorithmEnum.SHA256);
//	} else if (HashAlgorithmEnum.SHA384.equals(CryptoUtilXML.translateDigestAlgorithmToXMLURI(td.getAlgorithm()))) {
//	    docH.setDigestMethod(HashAlgorithmEnum.SHA384);
//	} else if (HashAlgorithmEnum.SHA512.equals(CryptoUtilXML.translateDigestAlgorithmToXMLURI(td.getAlgorithm()))) {
//	    docH.setDigestMethod(HashAlgorithmEnum.SHA512);
//	}
	docH.setDigestValue(file);
	timestampReq.setDocumentHash(docH);

	timestampReq.setTimestampType(TimestampTypeEnum.RFC_3161);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 3a:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: Base64Data
	 */

	file = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.BASE64_DATA);
	timestampReq.setDataToStamp(file);

	timestampReq.setTimestampType(TimestampTypeEnum.XML);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 3b:
	 * - Tipo de Sello de Tiempo: RFC 3161
	 * - Input Document: Base64Data
	 */
	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.BASE64_DATA);
	timestampReq.setDataToStamp(file);
	timestampReq.setTimestampType(TimestampTypeEnum.RFC_3161);

	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 4:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: TransformedData
	 */
	file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);

	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.TRANSFORMED_DATA);
	canonicalizer = new ArrayList<>();
	canonicalizer.add(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
	td = new TransformData("SHA1", canonicalizer);
	timestampReq.setTransformData(td);
	timestampReq.setDataToStamp(file);

	timestampReq.setTimestampType(TimestampTypeEnum.XML);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 5:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: Base64XML
	 */
	file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);

	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.BASE64_XML);
	timestampReq.setDataToStamp(file);

	timestampReq.setTimestampType(TimestampTypeEnum.XML);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 6:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: InlineXML
	 */
	file = UtilsFileSystemCommons.readFile("ficheroAfirmar2.xml", true);

	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.INLINE_XML);
	timestampReq.setDataToStamp(file);

	timestampReq.setTimestampType(TimestampTypeEnum.XML);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

	/*
	 * Prueba 7:
	 * - Tipo de Sello de Tiempo: XML
	 * - Input Document: EscapedXML
	 */
	file = UtilsFileSystemCommons.readFile("ficheroAfirmarEscapado.xml", true);

	timestampReq = new TimestampRequest();
	timestampReq.setApplicationId(TSA_APPLICATION_NAME);
	timestampReq.setDocumentType(DocumentTypeEnum.ESCAPED_XML);
	timestampReq.setDataToStamp(file);

	timestampReq.setTimestampType(TimestampTypeEnum.XML);
	try {
	    /*
	     * INICIO SELLADO
	     */
	    TimestampResponse timestampRes = TsaIntegraFacadeWSDSS.getInstance().generateTimestamp(timestampReq);
	    assertNotNull(timestampRes.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampRes.getResult().getResultMajor());
	    assertNotNull(timestampRes.getTimestamp());
	    /*
	     * FIN SELLADO
	     */

	    /*
	     * INICIO VALIDACIÓN
	     */
	    timestampReq.setTimestampTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResVerify = TsaIntegraFacadeWSDSS.getInstance().verifyTimestamp(timestampReq);
	    assertNotNull(timestampResVerify.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResVerify.getResult().getResultMajor());
	    timestampReq.setTimestampTimestampToken(null);
	    /*
	     * FIN VALIDACIÓN
	     */

	    /*
	     * INICIO RESELLADO
	     */
	    timestampReq.setTimestampPreviousTimestampToken(timestampRes.getTimestamp());
	    TimestampResponse timestampResRenew = TsaIntegraFacadeWSDSS.getInstance().renewTimestamp(timestampReq);
	    assertNotNull(timestampResRenew.getResult());
	    assertEquals(ResultProcessIds.SUCESS, timestampResRenew.getResult().getResultMajor());
	    timestampReq.setTimestampPreviousTimestampToken(null);
	    /*
	     * FIN RESELLADO
	     */
	} catch (Exception e) {
	    assertTrue(false);
	}

    }

}
