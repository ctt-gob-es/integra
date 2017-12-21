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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsResources.java.</p>
 * <b>Description:</b><p>Class that provides functionality to control the close of resources.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>13/01/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 13/01/2014.
 */
package es.gob.afirma.utils;

import org.apache.log4j.Logger;

import com.lowagie.text.pdf.PdfStamper;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.logger.IntegraLogger;

/**
 * <p>Class that provides functionality to control the close of resources.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/01/2014.
 */
public final class UtilsResourcesPDF {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsResourcesPDF.class);

    /**
     * Constructor method for the class UtilsResources.java.
     */
    private UtilsResourcesPDF() {
    }

    /**
     * Method that handles the closing of a {@link PdfStamper} resource.
     * @param stamper Parameter that represents a {@link PdfStamper} resource.
     */
    public static void safeClosePDFStamper(PdfStamper stamper) {
	if (stamper != null) {
	    try {
		stamper.close();
	    } catch (Exception e) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.UR_LOG001, new Object[ ] { stamper.getClass().getName() }), e);
	    }
	}
    }

}
