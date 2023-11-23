// Copyright (C) 2012-23 MINHAP, Gobierno de Espana
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
 * <b>File:</b><p>es.gob.afirma.afirma5ServiceInvoker.CacheStorage.java.</p>
 * <b>Description:</b><p>Class that storage the cached data.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/10/2023.</p>
 * @author Gobierno de Espa&ntilde;a.
 * @version 1.0, 26/10/2023.
 */
package es.gob.afirma.wsServiceInvoker;

import java.math.BigInteger;
import java.util.LinkedHashMap;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.Logger;

/**
 * Almac&eacute;n en el que cachear certificados.
 */
public class CacheStorage extends LinkedHashMap<CertificateCacheKey, CertificateCacheValue> {

	/** Serial Id. */
	private static final long serialVersionUID = -9015691546070864519L;

    /**
     * Attribute that represents the class logger.
     */
    private static final Logger LOGGER = Logger.getLogger(CacheStorage.class);
	
	/** Tama&ntilde;o m&aacute;ximo de la cach&eacute;. */
	private int maxSize;

	/**
	 * Crea el almac&eacute;n de la cach&eacute; con el m&aacute;ximo tama&ntilde;o posible.
	 */
	CacheStorage() {
		this(Integer.MAX_VALUE);
	}
	
	/**
	 * Crea el almac&eacute;n de la cach&eacute;.
	 * @param maxSize N&uacute;mero m&aacute;ximo de entradas que pueden almacenarse.
	 */
	CacheStorage(int maxSize) {
		super();
		this.maxSize = maxSize;
	}
		
	@Override
	protected boolean removeEldestEntry(java.util.Map.Entry<CertificateCacheKey, CertificateCacheValue> eldest) {
		boolean removed = size() > this.maxSize;
		if (removed) {
			final String issuer = eldest.getKey().getIssuer();
			final BigInteger serialNumber = eldest.getKey().getSerialNumber();
			final String requestType = eldest.getKey().getRequestType();
			LOGGER.info(Language.getFormatResIntegra(ILogConstantKeys.CC_LOG005, new Object[ ] { issuer, serialNumber, requestType }));
		}
		return removed;
	}
	
	/**
	 * Recuperar el n&uacute;mero m&aacute;ximo de entradas que pueden almacenarse.
	 * @return N&uacute;mero m&aacute;ximo de entradas.
	 */
	public int getMaxSize() {
		return this.maxSize;
	}

	/**
	 * Altera el tama&ntilde;o m&aacute;ximo. En caso de haberse superado ya este tama&ntilde;o
	 * NO se eliminan los elementos sobrantes.
	 * @param maxSize Tama&ntilde;o m&aacute;ximo.
	 */
	public void setMaxSize(int maxSize) {
		this.maxSize = maxSize;
	}
}
