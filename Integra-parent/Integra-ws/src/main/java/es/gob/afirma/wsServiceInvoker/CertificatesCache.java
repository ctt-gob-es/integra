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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.CertificatesCache.java.</p>
 * <b>Description:</b><p>Class that represents the certificates validation responses cache for @Firma certificates validation web service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/02/2014.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.wsServiceInvoker;

import java.math.BigInteger;
import java.util.Calendar;
import java.util.Properties;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;
import es.gob.afirma.properties.IIntegraConstants;
import es.gob.afirma.properties.IntegraProperties;

/**
 * <p>Class that represents the certificates validation responses cache for @Firma certificates validation web service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public final class CertificatesCache {

    /**
     * Attribute that represents the class logger.
     */
    private static final Logger LOGGER = Logger.getLogger(CertificatesCache.class);

    /**
     * Attribute that represents the instance of the class.
     */
    private static CertificatesCache instance;

    /**
     * Attribute that represents the information of the certificates validation responses cache.
     */
    private CacheStorage cache;

    /**
     * Attribute that represents the life time, in seconds, for each od the entries of the certificates validation responses cache.
     */
    private int lifeTimeNumber = 0;

    /**
     * Constructor method for the class CertificatesCache.java.
     * @param idClient Parameter that represents the client application identifier.
     * @throws WSServiceInvokerException If there is an error.
     */
    private CertificatesCache(String idClient) throws WSServiceInvokerException {
    	cache = new CacheStorage();
    	Properties prop = new IntegraProperties().getIntegraProperties(idClient);
    	if (prop != null) {
    		// Obtenemos el número de entradas máximas que puede tener la caché
    		String maxEntries = prop.getProperty(WSServiceInvokerConstants.WS_CERTIFICATES_CACHE_ENTRIES_PROP);
    		if (maxEntries == null) {
    			throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.CC_LOG003, new Object[ ] { WSServiceInvokerConstants.WS_CERTIFICATES_CACHE_ENTRIES_PROP, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
    		}
    		int maxEntriesNumber;
    		try {
    			maxEntriesNumber = Integer.valueOf(maxEntries);
    		} catch (NumberFormatException e) {
    			throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.CC_LOG004, new Object[ ] { WSServiceInvokerConstants.WS_CERTIFICATES_CACHE_ENTRIES_PROP, IIntegraConstants.DEFAULT_PROPERTIES_FILE, maxEntries }), e);
    		}
    		this.cache.setMaxSize(maxEntriesNumber);
    		
    		// Obtenemos el número de segundos de validez que tiene cada entrada
    		String lifeTime = prop.getProperty(WSServiceInvokerConstants.WS_CERTIFICATES_CACHE_LIFETIME_PROP);
    		if (lifeTime == null) {
    			throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.CC_LOG003, new Object[ ] { WSServiceInvokerConstants.WS_CERTIFICATES_CACHE_LIFETIME_PROP, IIntegraConstants.DEFAULT_PROPERTIES_FILE }));
    		}
    		try {
    			lifeTimeNumber = Integer.valueOf(lifeTime);
    		} catch (NumberFormatException e) {
    			throw new WSServiceInvokerException(Language.getFormatResIntegra(ILogConstantKeys.CC_LOG004, new Object[ ] { WSServiceInvokerConstants.WS_CERTIFICATES_CACHE_LIFETIME_PROP, IIntegraConstants.DEFAULT_PROPERTIES_FILE, lifeTime }), e);
    		}
    	}
    }

    /**
     * Method that obtains the unique instance of the class.
     * @param idClient Parameter that represents the client application identifier.
     * @return the unique instance of the class.
     * @throws WSServiceInvokerException If there is an error.
     */
    public static CertificatesCache getInstance(String idClient) throws WSServiceInvokerException {
	if (instance == null) {
	    LOGGER.info(Language.getResIntegra(ILogConstantKeys.CC_LOG001));
	    instance = new CertificatesCache(idClient);
	}
	return instance;
    }

    /**
     * Method that adds/updates an element into the certificates validation responses cache.
     * @param key Parameter that represents the key of the element to add/update. This key is the issuer and the serial number of the certificate.
     * @param xmlResponse Parameter that represents the XML with the certificate validation response from @Firma.
     * @return a boolean that indicates if the element has been added/updated (true) or not (false).
     */
    public boolean put(CertificateCacheKey key, String xmlResponse) {
	// Comprobamos que la clave no es nula y que el valor a insertar no es
	// nulo
	if (key == null || xmlResponse == null || xmlResponse.isEmpty()) {
	    return false;
	}
	// Obtenemos el emisor
	String issuer = key.getIssuer();
	// Obtenemos el número de serie
	BigInteger serialNumber = key.getSerialNumber();
	// Obtenemos el servicio al que se ha realizado la petición
	String requestType = key.getRequestType();

	// Comprobamos que la caché existe
	if (cache == null) {
	    // Inicializamos la caché
	    cache = new CacheStorage();
	}

	// Comprobamos si el elemento a añadir existe previamente y lo agregamos si no
	synchronized (cache) {
		if (!cache.containsKey(key)) {
			// Añadimos la entrada a la caché para el momento actual
			CertificateCacheValue ccv = new CertificateCacheValue(Calendar.getInstance().getTime(), xmlResponse);
			cache.put(key, ccv);
			LOGGER.debug(Language.getFormatResIntegra(ILogConstantKeys.CC_LOG002, new Object[ ] { issuer, serialNumber, requestType }));
		}
	}
	
	return true;
    }

    /**
     * Method that retrieves from the certificates validation responses cache the response XML for certain certificate.
     * @param key Parameter that represents the key (issuer and serial number) for the certificates validation responses cache.
     * @return the response XML of the certificate or null if the entry doesn't exist or the entry has expired.
     */
    public String get(CertificateCacheKey key) {
	// Comprobamos que la clave no es nula
	if (key == null || cache == null) {
	    return null;
	}
	// Comprobamos si el elemento existe
	CertificateCacheValue ccv = cache.get(key);
	if (ccv != null) {
		// En caso de existir comprobamos si su tiempo de vida se ha
		// superado
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(ccv.getInsertDate());
		calendar.add(Calendar.SECOND, lifeTimeNumber);

		Calendar now = Calendar.getInstance();
		if (now.getTime().compareTo(calendar.getTime()) > 0) {
			// Eliminamos la entrada de la caché
			synchronized (cache) {
				cache.remove(key);
			}
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.CC_LOG005, new Object[ ] { key.getIssuer(), key.getSerialNumber() }));
			return null;
		} else {
			return ccv.getXmlResponse();
		}
	} else {
	    return null;
	}
    }

}
