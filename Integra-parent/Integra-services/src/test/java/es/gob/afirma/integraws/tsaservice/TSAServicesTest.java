package es.gob.afirma.integraws.tsaservice;

import junit.framework.TestCase;

import org.junit.Test;

import es.gob.afirma.integraFacade.pojo.DocumentTypeEnum;
import es.gob.afirma.integraFacade.pojo.TimestampTypeEnum;
import es.gob.afirma.integraws.beans.RequestTimestamp;
import es.gob.afirma.integraws.beans.ResponseTimestamp;
import es.gob.afirma.integraws.ws.impl.TSAServices;
import es.gob.afirma.utils.UtilsFileSystemCommons;

public class TSAServicesTest extends TestCase {

    /**
     * Constant attribute that represents application name for tsa.
     */
    private static final String TSA_APPLICATION_NAME = "pruebasTest";
    
    @Test
    public final void testGenerateTimestamp() {

	RequestTimestamp request = new RequestTimestamp();
	request.setApplicationId(TSA_APPLICATION_NAME);
	
	byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	request.setDataToStamp(bytearray);
	
	request.setDocumentType(DocumentTypeEnum.BASE64_DATA);
	request.setTimestampType(TimestampTypeEnum.XML);
	request.setIdClient("prueba");
	
	TSAServices service = new TSAServices();
	ResponseTimestamp resp = service.generateTimestamp(request);
	
	assertTrue(resp.isIntegraSuccess());
	
    }

    @Test
    public final void testVerifyTimestamp() {
	
	RequestTimestamp requestPrev = new RequestTimestamp();
	requestPrev.setApplicationId(TSA_APPLICATION_NAME);
	
	byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	requestPrev.setDataToStamp(bytearray);
	
	requestPrev.setDocumentType(DocumentTypeEnum.BASE64_DATA);
	requestPrev.setTimestampType(TimestampTypeEnum.XML);
	requestPrev.setIdClient("prueba");
	
	TSAServices service = new TSAServices();
	ResponseTimestamp respPrev = service.generateTimestamp(requestPrev);
	
	assertTrue(respPrev.isIntegraSuccess());
	
	byte[] timestamp = respPrev.getTimestamp();
	
	RequestTimestamp request = new RequestTimestamp();
	request.setApplicationId(TSA_APPLICATION_NAME);

	request.setDataToStamp(bytearray);
	
	request.setDocumentType(DocumentTypeEnum.BASE64_DATA);
	request.setTimestampType(TimestampTypeEnum.XML);
	request.setIdClient("prueba");
	
	request.setTimestampTimestampToken(timestamp);
	
	ResponseTimestamp resp = service.verifyTimestamp(request);
	
	assertTrue(resp.isIntegraSuccess());
	
    }

    @Test
    public final void testRenewTimestamp() {
	
	RequestTimestamp requestPrev = new RequestTimestamp();
	requestPrev.setApplicationId(TSA_APPLICATION_NAME);
	
	byte[ ] bytearray = UtilsFileSystemCommons.readFile("ficheroAfirmar.txt", true);

	requestPrev.setDataToStamp(bytearray);
	
	requestPrev.setDocumentType(DocumentTypeEnum.BASE64_DATA);
	requestPrev.setTimestampType(TimestampTypeEnum.XML);
	requestPrev.setIdClient("prueba");
	
	TSAServices service = new TSAServices();
	ResponseTimestamp respPrev = service.generateTimestamp(requestPrev);
	
	assertTrue(respPrev.isIntegraSuccess());
	
	byte[] timestamp = respPrev.getTimestamp();
	
	RequestTimestamp request = new RequestTimestamp();
	request.setApplicationId(TSA_APPLICATION_NAME);

	request.setDataToStamp(bytearray);
	
	request.setDocumentType(DocumentTypeEnum.BASE64_DATA);
	request.setTimestampType(TimestampTypeEnum.XML);
	request.setIdClient("prueba");
	
	request.setTimestampPreviousTimestampToken(timestamp);
	
	ResponseTimestamp resp = service.renewTimestamp(request);
	
	assertTrue(resp.isIntegraSuccess());
		
    }

    
}
