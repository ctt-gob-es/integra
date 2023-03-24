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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsConnection.java.</p>
 * <b>Description:</b><p>Utilities class relating to general connections properties and operations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.tsl.utils;

import org.apache.log4j.Logger; 
import es.gob.afirma.tsl.logger.IntegraLogger;


import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;

/** 
 * <p>Utilities class relating to general connections properties and operations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 17/11/2020.
 */
public final class UtilsConnection {


	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsConnection.class);

	/**
	 * Constructor method for the class UtilsConnection.java.
	 */
	private UtilsConnection() {
		super();
	}
	/**
	 * Gets the maximum sixe allowed for resource connections.
	 * @return The maximum size allowed for resource connections (in bytes).
	 */
	public static int getMaxSizeConnection() {

		int result = NumberConstants.INT_5242880;
		try {
			String value = StaticTslConfig.getProperty(StaticTslConfig.CONECTION_MAXSIZE);
			if (UtilsStringChar.isNullOrEmptyTrim(value)) {
				LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_CONNECTION_001, new Object[ ] { StaticTslConfig.CONECTION_MAXSIZE, result }));
			} else {
				try {
					result = Integer.parseInt(value);
				} catch (Exception e) {
					LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_CONNECTION_000, new Object[ ] { StaticTslConfig.CONECTION_MAXSIZE, result }));
				}
			}
		} catch (Exception e) {
			LOGGER.warn(Language.getFormatResIntegraTsl(ILogTslConstant.UTILS_CONNECTION_001, new Object[ ] { StaticTslConfig.CONECTION_MAXSIZE, result }));
		}
		return result;

	}

}
