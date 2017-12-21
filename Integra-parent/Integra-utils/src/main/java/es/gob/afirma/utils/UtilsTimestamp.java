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
 * <b>File:</b><p>es.gob.afirma.utils.UtilsTimestamp.java.</p>
 * <b>Description:</b><p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>05/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 05/11/2014.
 */
package es.gob.afirma.utils;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Element;

import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.tsaServiceInvoker.TSAServiceInvokerException;

/**
 * <p>Class that contains methods related to the manage of timestamps.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 05/11/2014.
 */
public final class UtilsTimestamp {

    /**
     * Attribute that represents the object that manages the log of the class.
     */
    public static final Logger LOGGER = IntegraLogger.getInstance().getLogger(UtilsTimestamp.class);

    /**
     * Constructor method for the class TimestampUtils.java.
     */
    private UtilsTimestamp() {
    }

    // /**
    // * Method that obtains a timestamp from TS@.
    // * @param dataToStamp Parameter that represents the data to stamp.
    // * @param applicationID Parameter that represents the identifier of the
    // client application.
    // * @param signatureType Parameter that represents the timestamp type to
    // generate. The allowed values are:
    // * <ul>
    // * <li>{@link DSSConstants.TimestampForm#RFC_3161} for ASN.1
    // timestamp.</li>
    // * <li>{@link DSSConstants.TimestampForm#XML} for XML timestamp.</li>
    // * </ul>
    // * @return an object that represents the timestamp. This object can be:
    // * <ul>
    // * <li>An instance of {@link TimeStampToken} when the timestamp is ASN.1
    // type.</li>
    // * <li>An instance of {@link org.w3c.dom.Element} when the timestamp is
    // XML type.</li>
    // * </ul>
    // * @throws SigningException If the method fails.
    // */
    // public static Object getTimestampFromDssService(byte[ ] dataToStamp,
    // String applicationID, String signatureType) throws SigningException {
    // return UtilsTimestampWS.getTimestampFromDssService(dataToStamp,
    // applicationID, signatureType);
    // }

    /**
     * Method that obtains an ASN.1 timestamp from TS@ RFC 3161 service.
     * @param dataToStamp Parameter that represents the data to stamp.
     * @param applicationID Parameter that represents the identifier of the client application.
     * @param tsaCommunicationMode Parameter that represents the protocol defined to communicate with TS@. The allowed values are:
     * <ul>
     * <li>{@link #TSA_RFC3161_TCP_COMMUNICATION} for TCP communication.</li>
     * <li>{@link #TSA_RFC3161_HTTPS_COMMUNICATION} for HTTPS communication.</li>
     * <li>{@link #TSA_RFC3161_SSL_COMMUNICATION} for SSL communication.</li>
     * </ul>
     * @param idClient Parameter that represents the client application identifier.
     * @return an object that represents the ASN.1 timestamp.
     * @throws SigningException If the method fails.
     */
    public static TimeStampToken getTimestampFromRFC3161Service(byte[ ] dataToStamp, String applicationID, String tsaCommunicationMode, String idClient) throws SigningException {
	return UtilsTimestampOcspRfc3161.getTimestampFromRFC3161Service(dataToStamp, applicationID, tsaCommunicationMode, idClient);
    }

    /**
     * Method that obtains an ASN.1 timestamp from TS@ RFC 3161 service.
     * @param dataToStamp Parameter that represents the data to stamp.
     * @param applicationID Parameter that represents the identifier of the client application.
     * @param tsaCommunicationMode Parameter that represents the protocol defined to communicate with TS@. The allowed values are:
     * <ul>
     * <li>{@link #TSA_RFC3161_TCP_COMMUNICATION} for TCP communication.</li>
     * <li>{@link #TSA_RFC3161_HTTPS_COMMUNICATION} for HTTPS communication.</li>
     * <li>{@link #TSA_RFC3161_SSL_COMMUNICATION} for SSL communication.</li>
     * </ul>
     * @return an object that represents the ASN.1 timestamp.
     * @throws SigningException If the method fails.
     */
    public static TimeStampToken getTimestampFromRFC3161Service(byte[ ] dataToStamp, String applicationID, String tsaCommunicationMode) throws SigningException {
	return UtilsTimestampOcspRfc3161.getTimestampFromRFC3161Service(dataToStamp, applicationID, tsaCommunicationMode);
    }

    /**
     * Method that obtain the the signing certificate of a timestamp.
     * @param tst Parameter that represents the timestamp.
     * @return an object that represents the certificate.
     * @throws SigningException If the method fails.
     */
    public static X509Certificate getSigningCertificate(TimeStampToken tst) throws SigningException {
	return UtilsTimestampPdfBc.getSigningCertificate(tst);
    }

    /**
     * Method that validates a XML timestamp.
     * @param tst Parameter that represents the XML timestamp.
     * @throws SigningException If the validation fails.
     */
    public static void validateXMLTimestamp(Element tst) throws SigningException {
	UtilsTimestampXML.validateXMLTimestamp(tst);
    }

    /**
     * Method that validates an ASN.1 timestamp.
     * @param tst Parameter that represents the ASN.1 timestamp to validate.
     * @throws SigningException If the method fails or the timestamp isn't valid.
     */
    public static void validateASN1Timestamp(TimeStampToken tst) throws SigningException {
	UtilsTimestampPdfBc.validateASN1Timestamp(tst);
    }

    /**
     * Method that obtains the timestamp from the information about a signer of a signature, if it contains a timestamp.
     * @param signerInformation Parameter that represents the information of the signer.
     * @return an object that represents the timestamp, or <code>null</code>.
     * @throws SigningException If the timestamp is malformed.
     */
    public static TimeStampToken getTimeStampToken(SignerInformation signerInformation) throws SigningException {
	return UtilsTimestampPdfBc.getTimeStampToken(signerInformation);
    }

    /**
     * Method that checks if the input document associated to a renovation of a XML time-stamp is structurally correct.
     * @param inputDocuments Parameter that represents the <code>dss:InputDocuments</code> element of the time-stamp renovation request.
     * @param signature Parameter that represents the <code>ds:Signature</code> element of the time-stamp renovation request.
     * @throws TSAServiceInvokerException If the validation fails.
     */
    public static void checkInputDocumentXMLTimeStamp(Element inputDocuments, Element signature) throws TSAServiceInvokerException {
	UtilsTimestampWS.checkInputDocumentXMLTimeStamp(inputDocuments, signature);
    }

    /**
     * Method that checks if the input document associated to a renovation of a RFC 3161 time-stamp is structurally correct.
     * @param inputDocuments Parameter that represents the <code>dss:InputDocuments</code> element of the time-stamp renovation request.
     * @param tst Parameter that represents thr RFC 3161 time-stamp.
     * @throws TSAServiceInvokerException If the input document isn't valid.
     */
    public static void checkInputDocumentRFC3161TimeStamp(Element inputDocuments, TimeStampToken tst) throws TSAServiceInvokerException {
	UtilsTimestampWS.checkInputDocumentRFC3161TimeStamp(inputDocuments, tst);
    }

    /**
     * Method that obtains the gentime from a XML timestamp.
     * @param xmlTimestamp Parameter that represents the XML timestamp.
     * @return an object that represents the gentime.
     * @throws SigningException If the gentime cannot parse to UTC format.
     */
    public static Date getGenTimeXMLTimestamp(Element xmlTimestamp) throws SigningException {
	return UtilsTimestampXML.getGenTimeXMLTimestamp(xmlTimestamp);
    }

}
