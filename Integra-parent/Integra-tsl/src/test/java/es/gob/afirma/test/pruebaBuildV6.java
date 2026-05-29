package es.gob.afirma.test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import es.gob.afirma.tsl.access.TSLManager;
import es.gob.afirma.tsl.exceptions.TSLManagingException;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;

public class pruebaBuildV6 {

	public static void main(String[] args) {
		File file = new File("C:\\Users\\Jairo.Figueroa\\Downloads\\TSL_HR_V6_Copia.xml"); 
		ByteArrayInputStream inputStream;
		try {
			inputStream = getInputStreamFromFile(file);
			
			ITSLObject iTSLObject = TSLManager.getInstance().buildTsl(inputStream);
			
			iTSLObject.getSchemeInformation().getTslVersionIdentifier();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TSLManagingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public static ByteArrayInputStream getInputStreamFromFile(File file) throws IOException {
	    // Lee todo el contenido del archivo en un array de bytes
	    byte[] fileBytes = Files.readAllBytes(file.toPath());

	    // Crea el ByteArrayInputStream a partir del contenido leído
	    return new ByteArrayInputStream(fileBytes);
	}
}
