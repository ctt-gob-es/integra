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
// https://eupl.eu/1.1/es/

/**
 * <b>File:</b><p>es.gob.afirma.transformers.parseTransformers.IParseTransformer.java.</p>
 * <b>Description:</b><p>Interface that defines the common methods for the XML parsers of the @Firma, eVisor and TS@ web services responses.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2014.
 */
package es.gob.afirma.transformers.parseTransformers;

import es.gob.afirma.transformers.TransformersException;

/**
 * <p>Interface that defines the common methods for the XML parsers of the @Firma, eVisor and TS@ web services responses.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 19/11/2014.
 */
public interface IParseTransformer {

    /**
     * Method that obtains the name of the service used to configure the parser.
     * @return the name of the service used to configure the parser.
     */
    String getRequest();

    /**
     * Method that obtains the name of the method of the web service used to configure the parser.
     * @return the name of the method of the web service used to configure the parser.
     */
    String getMethod();

    /**
     * Method that obtains the version of the message used to configure the parser.
     * @return the version of the message used to configure the parser.
     */
    String getMessageVersion();

    /**
     * Method that transforms the response to a java object.
     * @param xmlResponse Parameter that represents the XML response.
     * @return an object that represents the processed XML response.
     * @throws TransformersException If the method fails.
     */
    Object transform(String xmlResponse) throws TransformersException;
}
