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
 * <b>File:</b><p>es.gob.afirma.ocsp.IOCSPConstants.java.</p>
 * <b>Description:</b><p>Interface that defines all the constants related to the communication with an OCSP server to validate certificates.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/05/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 14/05/2015.
 */
package es.gob.afirma.properties;

/**
 * <p>Interface that defines all the constants related to the communication with an OCSP server to validate certificates.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 14/05/2015.
 */
public interface IIntegraConstants {

    /**
     * Constant attribute that identifies the name of the properties file where to configure the properties related to the general properties.
     */
    String PROPERTIES_FILE = "integraxxxxxxxx.properties";

    /**
     * Constant attribute that identifies the name of the default properties file where to configure the properties related to the general properties.
     */
    String DEFAULT_PROPERTIES_FILE = "integra.properties";

    /**
     * Constant attribute that identifies the name of the mapping files properties file.
     */
    String MAPPING_PROPERTIES_FILE = "mappingFiles.properties";

}
