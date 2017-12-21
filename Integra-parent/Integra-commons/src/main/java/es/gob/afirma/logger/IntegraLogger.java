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
 * <b>File:</b><p>es.gob.afirma.i18n.Language.java.</p>
 * <b>Description:</b><p>Class that manages the access to the log4j.properties file.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>24/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 09/06/2016.
 */
package es.gob.afirma.logger;

import java.io.File;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import es.gob.afirma.utils.NumberConstants;

/**
 * <p>Class that manages the access to the log4j.properties file.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 09/06/2016.
 */
public final class IntegraLogger {

    /**
     * Attribute that represents logger object. 
     */
    private static IntegraLogger logger;

    /**
     * Constructor method for the class IntegraLogger.java. 
     */
    private IntegraLogger() {
	if (System.getProperty("integra.config") != null) {
	    String path = new File(System.getProperty("integra.config") + File.separator + "log4j.properties").getPath();

	    PropertyConfigurator.configureAndWatch(path, NumberConstants.LONG_60000);
	}
    }

    /**
     * Returns the instance of logger.
     * @return instance of logger.
     */
    public static IntegraLogger getInstance() {
	if (logger == null) {
	    logger = new IntegraLogger();
	}
	return logger;
    }

    /**
     * Returns the log4j logger.
     * @param clazz 
     * @return the log4j logger.
     */
    public Logger getLogger(Class<?> clazz) {
	return Logger.getLogger(clazz);
    }

}
