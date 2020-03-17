// Copyright (C) 2017 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraws.ws.impl.TSAServices.java.</p>
 * <b>Description:</b><p> Class that contains tsa service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.2, 17/03/2020.
 */
package es.gob.afirma.integraws.ws.impl;

import org.apache.log4j.Logger;

import es.gob.afirma.i18n.ILogConstantKeys;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.TSAFacadeBind;
import es.gob.afirma.integraFacade.ValidateRequest;
import es.gob.afirma.integraFacade.pojo.Result;
import es.gob.afirma.integraFacade.pojo.TimestampRequest;
import es.gob.afirma.integraFacade.pojo.TimestampResponse;
import es.gob.afirma.integraws.beans.RequestTimestamp;
import es.gob.afirma.integraws.beans.ResponseTimestamp;
import es.gob.afirma.integraws.ws.ITSAServices;
import es.gob.afirma.integraws.ws.IWSConstantKeys;
import es.gob.afirma.logger.IntegraLogger;

/**
 * <p>Class that contains tsa service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 17/03/2020.
 */
public class TSAServices implements ITSAServices {

    /**
     *  Attribute that represents the object that manages the log of the class.
     */
    private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(TSAServices.class);

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.ITSAServices#generateTimestamp(es.gob.afirma.integraws.beans.RequestTimestamp)
     */
    public final ResponseTimestamp generateTimestamp(RequestTimestamp timestampReq) {

	TimestampRequest req = new TimestampRequest();

	if (timestampReq != null) {
	    if (timestampReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    if (timestampReq.getDataToStamp() == null && timestampReq.getDocumentHash() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_017));
		return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_017));
	    }
	    req.setApplicationId(timestampReq.getApplicationId());
	    req.setDataToStamp(timestampReq.getDataToStamp());
	    req.setDocumentHash(timestampReq.getDocumentHash());
	    req.setDocumentType(timestampReq.getDocumentType());
	    req.setTimestampPreviousTimestampToken(timestampReq.getTimestampPreviousTimestampToken());
	    req.setTimestampTimestampToken(timestampReq.getTimestampTimestampToken());
	    req.setTimestampType(timestampReq.getTimestampType());
	    req.setTransformData(timestampReq.getTransformData());

	    String resultValidate = ValidateRequest.validateTimestampRequest(timestampReq);

	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseTimestamp(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    try {
		TimestampResponse resultTSA = TSAFacadeBind.getInstance().generateTimestamp(timestampReq, timestampReq.getIdClient());

		if (resultTSA.getResult() == null) {
		    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_011));
		    return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_011));
		}

		return new ResponseTimestamp(resultTSA, true);
	    } catch (Exception e) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_010));
		return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_010));
	    }
	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.ITSAServices#verifyTimestamp(es.gob.afirma.integraws.beans.RequestTimestamp)
     */
    public final ResponseTimestamp verifyTimestamp(RequestTimestamp timestampReq) {

	TimestampRequest req = new TimestampRequest();

	if (timestampReq != null) {
	    if (timestampReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(timestampReq.getApplicationId());
	    req.setDataToStamp(timestampReq.getDataToStamp());
	    req.setDocumentHash(timestampReq.getDocumentHash());
	    req.setDocumentType(timestampReq.getDocumentType());
	    req.setTimestampPreviousTimestampToken(timestampReq.getTimestampPreviousTimestampToken());
	    req.setTimestampTimestampToken(timestampReq.getTimestampTimestampToken());
	    req.setTimestampType(timestampReq.getTimestampType());
	    req.setTransformData(timestampReq.getTransformData());

	    String resultValidate = ValidateRequest.validateTimestampRequest(timestampReq);

	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseTimestamp(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }
	    try {
		TimestampResponse resultTSA = TSAFacadeBind.getInstance().verifyTimestamp(timestampReq, timestampReq.getIdClient());

		if (resultTSA.getResult() == null || resultTSA.getResult().getResultMajor().toLowerCase().contains("error") || resultTSA.getResult().getResultMajor().toLowerCase().contains("invalid")) {
		    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_011));
		    return generateErrorTSAResponse(resultTSA.getResult());
		}

		return new ResponseTimestamp(resultTSA, true);
	    } catch (Exception e) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_010));
		return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_010));
	    }

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * {@inheritDoc}
     * @see es.gob.afirma.integraws.ws.ITSAServices#renewTimestamp(es.gob.afirma.integraws.beans.RequestTimestamp)
     */
    public final ResponseTimestamp renewTimestamp(RequestTimestamp timestampReq) {

	TimestampRequest req = new TimestampRequest();

	if (timestampReq != null) {
	    if (timestampReq.getIdClient() == null) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
		return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
	    }
	    req.setApplicationId(timestampReq.getApplicationId());
	    req.setDataToStamp(timestampReq.getDataToStamp());
	    req.setDocumentHash(timestampReq.getDocumentHash());
	    req.setDocumentType(timestampReq.getDocumentType());
	    req.setTimestampPreviousTimestampToken(timestampReq.getTimestampPreviousTimestampToken());
	    req.setTimestampTimestampToken(timestampReq.getTimestampTimestampToken());
	    req.setTimestampType(timestampReq.getTimestampType());
	    req.setTransformData(timestampReq.getTransformData());

	    String resultValidate = ValidateRequest.validateTimestampRequest(timestampReq);

	    if (resultValidate != null) {
		LOGGER.error(Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
		return new ResponseTimestamp(false, Language.getFormatResIntegra(ILogConstantKeys.IFWS_LOG020, new Object[ ] { resultValidate }));
	    }

	    try {
		TimestampResponse resultTSA = TSAFacadeBind.getInstance().renewTimestamp(timestampReq, timestampReq.getIdClient());

		if (resultTSA.getResult() == null) {
		    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_011));
		    return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_011));
		}

		return new ResponseTimestamp(resultTSA, true);
	    } catch (Exception e) {
		LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_010));
		return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_010));
	    }

	} else {
	    LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_001));
	    return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_001));
	}
    }

    /**
     * Auxiliary method that generates an error response with the TSA error message if it is indicates or with a generic error message if not.
     * @param result TSA result object.
     * @return a response object with the information about the error.
     */
    private ResponseTimestamp generateErrorTSAResponse(Result result) {
	if (result != null) {
	    String responseMsg = result.getResultMessage();
	    if (responseMsg != null && !responseMsg.isEmpty()) {
		return new ResponseTimestamp(false, responseMsg);
	    }
	}
	return new ResponseTimestamp(false, Language.getResIntegra(IWSConstantKeys.IWS_011));
    }
}
