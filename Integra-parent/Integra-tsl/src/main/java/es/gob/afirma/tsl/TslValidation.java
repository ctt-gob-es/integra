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
 * <b>File:</b><p>es.gob.afirma.tsl.TslValidation.java.</p>
 * <b>Description:</b><p> Class that implements the necessary methods to perform certificate validation using a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 27/09/2021.
 */
package es.gob.afirma.tsl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Map;

import org.apache.log4j.Logger;

import es.gob.afirma.tsl.access.TSLManager;
import es.gob.afirma.tsl.certValidation.ifaces.ITSLValidatorResult;
import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.exceptions.TSLManagingException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.TSLObject;
import es.gob.afirma.tsl.utils.UtilsCertificateTsl;
import es.gob.afirma.tsl.utils.UtilsFileSystemCommons;
import es.gob.afirma.tsl.utils.UtilsHTTP;
import es.gob.afirma.tsl.utils.UtilsStringChar;

/** 
 * <p>Class that implements the necessary methods to perform certificate validation using a TSL.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 27/09/2021.
 */
public class TslValidation implements ITslValidation {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = Logger.getLogger(TslValidation.class);

    /**
     * Constructor method for the class TslValidation.java. 
     */
    public TslValidation() {
	super();
    }


    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.ITslValidation#getTSLObjectFromPath(java.lang.String)
     */
    @Override
    public ITSLObject getTSLObjectFromPath(String pathTsl) throws TSLManagingException {
	ITSLObject tslObject = null;

	File xmlFile = null;
	byte[ ] tslByteArray = null;
	if (!UtilsStringChar.isNullOrEmptyTrim(pathTsl)) {
	    xmlFile = new File(pathTsl);
	    if (xmlFile.exists()) {

		tslByteArray = UtilsFileSystemCommons.readFile(pathTsl, false);
		ByteArrayInputStream bais = null;
		bais = new ByteArrayInputStream(tslByteArray);
		// se construye la TSL
		tslObject = TSLManager.getInstance().buildTsl(bais);

	    } else {
		throw new TSLManagingException(Language.getResIntegraTsl(ILogTslConstant.TM_LOG002));
	    }
	}

	return tslObject;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.ITslValidation#downloadTLSbyHTTP(java.lang.String)
     */
    @Override
    public ITSLObject downloadTLSbyHTTP(String uriTSL, int connectionTimeout, int readTimeout) throws TSLManagingException {
	ITSLObject tslObject = null;
	ByteArrayInputStream inStream = null;

	// se descarga la TSL en un array de bytes
	byte[ ] buffer;

	try {
	    buffer = UtilsHTTP.getDataFromURI(uriTSL, connectionTimeout, readTimeout, null, null, null);
	    inStream = new ByteArrayInputStream(buffer);
	    tslObject = TSLManager.getInstance().buildTsl(inStream);
	} catch (CommonUtilsException e) {
	    throw new TSLManagingException(Language.getFormatResIntegraTsl(ILogTslConstant.TM_LOG008, new Object[ ] { uriTSL }), e);
	}

	return tslObject;
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.tsl.ITslValidation#getLogicalFieldsTSL(byte[], es.gob.afirma.tsl.parsing.impl.common.TSLObject)
     */
    @Override
    public Map<String, String> getLogicalFieldsTSL(byte[ ] certByteArrayB64, TSLObject tslObject) throws TSLManagingException {
	long startOperationTime = Calendar.getInstance().getTimeInMillis();
	LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG042));
	Map<String, String> result = null;
	ITSLValidatorResult tslValidatorResult = null;
	// Inicialmente consideramos que todo es OK para proceder.
	boolean allIsOk = true;
	// se comprueban los parámetros de entrada
	String resultCheckParams = checkParameterValidateCertificateTsl(certByteArrayB64, tslObject);
	if (resultCheckParams != null) {
	    allIsOk = false;
	    LOGGER.error(resultCheckParams);
	}

	// Comprobamos que se parsea correctamente el certificado a detectar.
	X509Certificate x509cert = null;
	if (allIsOk) {
	    try {
		x509cert = UtilsCertificateTsl.getX509Certificate(certByteArrayB64);
	    } catch (CommonUtilsException e) {
		allIsOk = false;
		LOGGER.error(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG012));
	    }
	}
	// si todo correcto, se continua con el proceso
	if (allIsOk) {
	    tslValidatorResult = TSLManager.getInstance().validateX509withTSL(x509cert, x509cert.getNotBefore(), false, true, tslObject);
	    
	    
	    if (tslValidatorResult == null) {
		LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG040));
	    } else {
		
		result = tslValidatorResult.getMappings();
	    }
	}
	if(result != null){
	    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG041));
	    LOGGER.info(Language.getFormatResIntegraTsl(ILogTslConstant.TSLVAL_LOG043, new Object[ ] { Calendar.getInstance().getTimeInMillis() - startOperationTime }));
	}else{
	    LOGGER.info(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG044));
	}
	

	return result;
    }

 

    /**
     * Method that checks required parameters for {@link es.gob.afirma.tsl.TslValidation#validateCertificateTsl} method.
     * @param certByteArrayB64 Certificate to detect (byte[]).
     * @param tslObject TSL object representation to use.
     * @return {@link String} with the parameter that not are correctly defined, otherwise <code>null</code>.
     */
    private String checkParameterValidateCertificateTsl(final byte[ ] certByteArrayB64, final TSLObject tslObject) {
	StringBuffer result = new StringBuffer();
	boolean checkError = false;

	result.append(Language.getResIntegraTsl(ILogTslConstant.TSLVAL_LOG003));
	if (certByteArrayB64 == null) {
	    checkError = true;
	    result.append(UtilsStringChar.EMPTY_STRING);
	    result.append(UtilsStringChar.SYMBOL_OPEN_BRACKET_STRING);
	    result.append(ITslValidation.PARAM_CERTIFICATE);
	    result.append(UtilsStringChar.SYMBOL_CLOSE_BRACKET_STRING);
	}

	if (tslObject == null) {
	    checkError = true;
	    result.append(UtilsStringChar.EMPTY_STRING);
	    result.append(UtilsStringChar.SYMBOL_OPEN_BRACKET_STRING);
	    result.append(ITslValidation.PARAM_CERTIFICATE);
	    result.append(UtilsStringChar.SYMBOL_CLOSE_BRACKET_STRING);
	}

	if (checkError) {
	    return result.toString();
	} else {
	    return null;
	}

    }

   
}
