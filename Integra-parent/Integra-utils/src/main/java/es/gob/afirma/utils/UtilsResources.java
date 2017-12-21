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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import com.lowagie.text.pdf.PdfStamper;

/**
 * <p>Class that provides functionality to control the close of resources.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 13/01/2014.
 */
public final class UtilsResources {

    /**
     * Constructor method for the class UtilsResources.java.
     */
    private UtilsResources() {
    }

    /**
     * Method that handles the closing of a {@link InputStream} resource.
     * @param is Parameter that represents a {@link InputStream} resource.
     */
    public static void safeCloseInputStream(InputStream is) {
	UtilsResourcesCommons.safeCloseInputStream(is);
    }

    /**
     * Method that handles the closing of a {@link OutputStream} resource.
     * @param os Parameter that represents a {@link OutputStream} resource.
     */
    public static void safeCloseOutputStream(OutputStream os) {
	UtilsResourcesCommons.safeCloseOutputStream(os);
    }

    /**
     * Method that handles the closing of a {@link Socket} resource.
     * @param socket Parameter that represents a {@link Socket} resource.
     */
    public static void safeCloseSocket(Socket socket) {
	UtilsResourcesCommons.safeCloseSocket(socket);
    }

    /**
     * Method that handles the closing of a {@link PdfStamper} resource.
     * @param stamper Parameter that represents a {@link PdfStamper} resource.
     */
    public static void safeClosePDFStamper(PdfStamper stamper) {
	UtilsResourcesPDF.safeClosePDFStamper(stamper);
    }

}
