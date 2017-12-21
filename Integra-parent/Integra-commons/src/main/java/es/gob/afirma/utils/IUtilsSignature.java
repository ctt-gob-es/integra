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
 * <b>File:</b><p>es.gob.afirma.utils.IUtilsSignature.java.</p>
 * <b>Description:</b><p>Interface that defines constants related to signature modes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 03/02/2016.
 */
package es.gob.afirma.utils;

/** 
 * <p>Interface that defines constants related to signature modes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 03/02/2016.
 */
public interface IUtilsSignature {

    /**
     * Constant attribute that identifies the detached signature mode for XML signatures.
     */
    String DETACHED_SIGNATURE_MODE = "Detached";

    /**
     * Constant attribute that identifies the enveloped signature mode for XML signatures.
     */
    String ENVELOPED_SIGNATURE_MODE = "Enveloped";

    /**
     * Constant attribute that identifies the enveloping signature mode for XML signatures.
     */
    String ENVELOPING_SIGNATURE_MODE = "Enveloping";

    /**
     * Constant attribute that identifies the implicit signature mode for ASN.1 signatures.
     */
    String IMPLICIT_SIGNATURE_MODE = "Implicit";

    /**
     * Constant attribute that identifies the explicit signature mode for ASN.1 signatures.
     */
    String EXPLICIT_SIGNATURE_MODE = "Explicit";

    /**
     * Constant attribute that identifies the third certificate validation level. In this level, the revocation status level of the certificate,
     * the validity status period of the certificate and the expired status of the certificate are validated.
     */
    int VALIDATION_LEVEL_COMPLETE = 2;

    /**
     * Constant attribute that identifies the second certificate validation level. In this level, the validity status period of the certificate
     * and the expired status of the certificate are validated.
     */
    int VALIDATION_LEVEL_SIMPLE = 1;

    /**
     * Constant attribute that identifies the certificate validation level most simple. In this level, the certificate isn't validated.
     */
    int VALIDATION_LEVEL_NONE = 0;
}
