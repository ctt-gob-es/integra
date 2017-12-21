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
 * <b>File:</b><p>es.gob.afirma.transformers.xmlTransformers.IXmlTransformer.java.</p>
 * <b>Description:</b><p>Interface that defines the common methods for the generators of input parameters and output parameters for the web services of @Firma,
 * eVisor and TS@.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 29/12/2014.
 */
package es.gob.afirma.transformers.xmlTransformers;

import es.gob.afirma.transformers.TransformersException;

/**
 * <p>Interface that defines the common methods for the generators of input parameters and output parameters for the web services of @Firma,
 * eVisor and TS@.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 29/12/2014.
 */
public interface IXmlTransformer {

    /**
     * Method that obtains the name of the service used to configure the generator.
     * @return the name of the service used to configure the generator.
     */
    String getService();

    /**
     * Method that obtains the name of the method to invoke.
     * @return the name of the method to invoke.
     */
    String getMethod();

    /**
     * Method that obtains the type of the parameter to generate (input or output). The allowed values are:
     * <ul>
     * <li>request: For input parameter.</li>
     * <li>response: For output parameter.</li>
     * </ul>
     * @return the type of the parameter to generate (request or response).
     */
    String getType();

    /**
     * Method that obtains the version of the parameter used to configure the generator.
     * @return the version of the parameter used to configure the generator.
     */
    String getMessageVersion();

    /**
     * Method that transforms a structure to an input or output parameter of a web service.
     * @param params Values of the input or output parameters on XML format.
     * @return a String that represents the input or output parameter on XML format.
     * @throws TransformersException If the method fails.
     */
    Object transform(Object params) throws TransformersException;
}
