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
 * <b>File:</b><p>es.gob.afirma.transformers.parseTransformers.ParseTransformerConstants.java.</p>
 * <b>Description:</b><p>Interface that defines the constants used on the transform of responses from the web services of @Firma, eVisor and TS@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2014.
 */
package es.gob.afirma.transformers.parseTransformers;

/**
 * <p>Interface that defines the constants used on the transform of responses from the web services of @Firma, eVisor and TS@.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 19/11/2014.
 */
public interface ParseTransformerConstants {

    /**
     * Constant attribute that represents error node in Spanish language.
     */
    String EXCEPTION_ELEMENT_SP = "Excepcion";

    /**
     * Constant attribute that represents error node in international language.
     */
    String EXCEPTION_ELEMENT = "Exception";

    /**
     * Constant attribute that represents response node in international language.
     */
    String RESPONSE_ELEMENT = "response";

    /**
     * Constant attribute that represents response tag in Spanish language.
     */
    String RESPONSE_ELEMENT_SP = "respuesta";

    /**
     * Constant attribute that identifies the key for an error response.
     */
    String ERROR_KEY = "errorResponse";

    /**
     * Constant attribute that identifies the key for a correct response.
     */
    String OK_KEY = "okResponse";

}
