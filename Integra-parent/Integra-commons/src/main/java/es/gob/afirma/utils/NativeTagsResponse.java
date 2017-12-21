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
 * <b>File:</b><p>es.gob.afirma.utils.NativeTagsResponse.java.</p>
 * <b>Description:</b><p>Class that defines constants with XPaths and tags of XML responses from @Firma native services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>07/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 07/11/2014.
 */
package es.gob.afirma.utils;

/**
 * <p>Class that defines constants with XPaths and tags of XML responses from @Firma native services.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 07/11/2014.
 */
public final class NativeTagsResponse {

    /**
     * Constructor method for the class NativeTagsRequest.java.
     */
    private NativeTagsResponse() {
    }

    /**
     * Constant attribute that represents the XPath for the tag <code>codigoError</code>.
     */
    public static final String ERROR_RESPONSE_CODE = "codigoError";

    /**
     * Constant attribute that represents the XPath for the tag <code>descripcion</code>.
     */
    public static final String ERROR_RESPONSE_DESCRIPTION = "descripcion";

    /**
     * Constant attribute that represents the XPath for the tag <code>descripcion</code>.
     */
    public static final String ERROR_RESPONSE_EXCEPTION = "exceptionAsociado";

    /**
     * Constant attribute that represents the XPath for the tag <code>estado</code>.
     */
    public static final String STATE = "estado";

    /**
     * Constant attribute that represents the XPath for the tag <code>descripcion</code>.
     */
    public static final String DESCRIPTION = "descripcion";

    /**
     * Constant attribute that represents the XPath for the tag <code>idDocumento</code>.
     */
    public static final String ID_DOCUMENT = "idDocumento";

    /**
     * Constant attribute that represents the XPath for the tag <code>content</code>.
     */
    public static final String DOCUMENT = "documento";

    /**
     * Constant attribute that represents the XPath for the tag <code>firmaElectronica</code>.
     */
    public static final String FIRMA_ELECTRONICA = "firmaElectronica";

    /**
     * Constant attribute that represents the XPath for the tag <code>formatoFirma</code>.
     */
    public static final String FORMATO_FIRMA = "formatoFirma";
}
