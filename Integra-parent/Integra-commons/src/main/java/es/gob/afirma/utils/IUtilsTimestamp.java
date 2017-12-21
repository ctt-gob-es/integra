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
 * <b>File:</b><p>es.gob.afirma.utils.IUtilsTimestamp.java.</p>
 * <b>Description:</b><p>Interface that defines constants related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 03/02/2016.
 */
package es.gob.afirma.utils;

/** 
 * <p>Interface that defines constants related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 03/02/2016.
 */
public interface IUtilsTimestamp {

    /**
     * Constant attribute that identifies the RFC 3161 timestamp type.
     */
    String TIMESTAMP_TYPE_RFC_3161 = "RFC 3161";

    /**
     * Constant attribute that identifies the XML timestamp type.
     */
    String TIMESTAMP_TYPE_XML = "XML";

    /**
     * Constant attribute that identifies the communication with TS@ via RFC 3161 - SSL service to obtain the timestamp.
     */
    String TSA_RFC3161_SSL_COMMUNICATION = "RFC3161-SSL";

    /**
     * Constant attribute that identifies the communication with TS@ via RFC 3161 - HTTPS service to obtain the timestamp.
     */
    String TSA_RFC3161_HTTPS_COMMUNICATION = "RFC3161-HTTPS";

    /**
     * Constant attribute that identifies the communication with TS@ via RFC 3161 - TCP service to obtain the timestamp.
     */
    String TSA_RFC3161_TCP_COMMUNICATION = "RFC3161-TCP";

    /**
     * Constant attribute that identifies the communication with TS@ via web service to obtain the timestamp.
     */
    String TSA_DSS_COMMUNICATION = "DSS";

    /**
     * Constant attribute that identifies the ASN1 timestamp type.
     */
    String TIMESTAMP_TYPE_ASN1 = "ASN.1";
}
