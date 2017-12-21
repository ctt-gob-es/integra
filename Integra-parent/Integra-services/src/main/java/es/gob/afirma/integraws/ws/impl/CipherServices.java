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
 * <b>File:</b><p>es.gob.afirma.integraws.ws.impl.CipherServices.java.</p>
 * <b>Description:</b><p> Class that contains cipher service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.ws.impl;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.encryption.CipherIntegra;
import es.gob.afirma.exception.CipherException;
import es.gob.afirma.hsm.HSMKeystore;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.IntegraFacadeConstants;
import es.gob.afirma.integraws.beans.RequestCipher;
import es.gob.afirma.integraws.beans.ResponseCipher;
import es.gob.afirma.integraws.ws.ICipherServices;
import es.gob.afirma.integraws.ws.IWSConstantKeys;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IntegraProperties;


/** 
 * <p>Class that contains cipher service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class CipherServices implements ICipherServices{

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(CipherServices.class);
    
   
    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.ICipherServices#encrypt(es.gob.afirma.integraws.beans.RequestCipher)
     */
    public final ResponseCipher encrypt (RequestCipher request) {
	
	if (request.getIdClient() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	}
	if (request.getAlias() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_006));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_006));
	}
	if (request.getText() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_014));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_014));
	}
	if (request.getAlgorithmCipher() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_015));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_015));
	}
	
	Key pk = getPrivateKey(request.getIdClient(), request.getAlias());
	
	if (pk == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_007));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_007));
	}
	
	CipherIntegra cipherIntegra;
	try {
	    cipherIntegra = new CipherIntegra(request.getAlgorithmCipher(), pk);
	    
	    String cipherText = cipherIntegra.encrypt(request.getText());
	    
	    return new ResponseCipher(cipherText, true);
	} catch (CipherException e) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_010), e);
	    return new ResponseCipher(false, e.getMessage());
	}
    }
    
    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.ICipherServices#decrypt(es.gob.afirma.integraws.beans.RequestCipher)
     */
    public final ResponseCipher decrypt(RequestCipher request) {
	if (request.getIdClient() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	}
	if (request.getAlias() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_006));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_006));
	}
	if (request.getText() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_014));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_014));
	}
	if (request.getAlgorithmCipher() == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_015));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_015));
	}
	
	Key pk = getPrivateKey(request.getIdClient(), request.getAlias());
	
	if (pk == null) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_007));
	    return new ResponseCipher(false, Language.getResIntegra(IWSConstantKeys.IWS_007));
	}
	
	CipherIntegra cipherIntegra;
	try {
	    cipherIntegra = new CipherIntegra(request.getAlgorithmCipher(), pk);
	    
	    String decipherText = cipherIntegra.decrypt(request.getText());
	    
	    return new ResponseCipher(decipherText, true);
	} catch (CipherException e) {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_010), e);
	    return new ResponseCipher(false, e.getMessage());
	}
    }
    
    /**
     * Obtains the private key from a indicated keystore.
     * @param idClient id del cliente que invoca al servicio
     * @param alias Alias del certificado
     * @return private key
     */
    private Key getPrivateKey(String idClient, String alias) {
	Key key = null;
	try {
	    Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);

	    String useHSM = (String) integraProperties.get(IntegraFacadeConstants.KEY_USE_HSM);

	    if (useHSM != null && "true".equals(useHSM)) {
		key = HSMKeystore.getPrivateKey(alias);
	    } else {

		String keystorePath = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE);

		String keystorePass = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE_PASS);

		String keystoreType = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE_TYPE);

		InputStream is = new FileInputStream(keystorePath);
		KeyStore ks = KeyStore.getInstance(keystoreType);
		char[ ] password = keystorePass.toCharArray();
		ks.load(is, password);
		key = ks.getKey(alias, password);
	    }
	} catch (Exception e) {
	    LOGGER.error(e.getMessage(), e);
	    return null;
	}
	return key;
    }

    
}
