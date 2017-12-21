// Copyright (C) 2012-15 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraFacade.IntegraFacadeWSDSSBind.java.</p>
 * <b>Description:</b><p> Class to bind protected methods of IntegraFacadeWSDSS.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraFacade;

import es.gob.afirma.integraFacade.pojo.ArchiveRequest;
import es.gob.afirma.integraFacade.pojo.ArchiveResponse;
import es.gob.afirma.integraFacade.pojo.AsynchronousResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureRequest;
import es.gob.afirma.integraFacade.pojo.BatchVerifySignatureResponse;
import es.gob.afirma.integraFacade.pojo.CoSignRequest;
import es.gob.afirma.integraFacade.pojo.CounterSignRequest;
import es.gob.afirma.integraFacade.pojo.PendingRequest;
import es.gob.afirma.integraFacade.pojo.ServerSignerRequest;
import es.gob.afirma.integraFacade.pojo.ServerSignerResponse;
import es.gob.afirma.integraFacade.pojo.UpgradeSignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateRequest;
import es.gob.afirma.integraFacade.pojo.VerifyCertificateResponse;
import es.gob.afirma.integraFacade.pojo.VerifySignatureRequest;
import es.gob.afirma.integraFacade.pojo.VerifySignatureResponse;

/** 
 * <p>Class to bind protected methods of IntegraFacadeWSDSS.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public final class IntegraFacadeWSDSSBind {

    /**
     * Attribute that represents the instance of the class.
     */
    private static IntegraFacadeWSDSSBind instance;

    /**
     * Constructor method for the class IntegraFacadeWSDSSBind.java.
     */
    private IntegraFacadeWSDSSBind() {
    }

    /**
     * Method that obtains an instance of the class.
     * @return the unique instance of the class.
     */
    public static IntegraFacadeWSDSSBind getInstance() {
	if (instance == null) {
	    instance = new IntegraFacadeWSDSSBind();
	}
	return instance;
    }

    /**
     * Method that obtains the response of the server signature service.
     * @param serSigReq Parameter that represents the request of the server signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server signature service.
     */
    public ServerSignerResponse sign(ServerSignerRequest serSigReq, String idClient) {
	return IntegraFacadeWSDSS.getInstance().sign(serSigReq, idClient);
    }

    /**
     * Method that obtains the response of the server co-signature service.
     * @param coSigReq Parameter that represents the request of the server co-signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server co-signature service.
     */
    public ServerSignerResponse coSign(CoSignRequest coSigReq, String idClient) {
	return IntegraFacadeWSDSS.getInstance().coSign(coSigReq, idClient);
    }

    /**
     * Method that obtains the response of the server counter-signature service.
     * @param couSigReq Parameter that represents the request of the server counter-signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the server counter-signature service.
     */
    public ServerSignerResponse counterSign(CounterSignRequest couSigReq, String idClient) {
	return IntegraFacadeWSDSS.getInstance().counterSign(couSigReq, idClient);
    }

    /**
     * Method that obtains the response of the upgrade signature service.
     * @param upgSigReq Parameter that represents the request of the upgrade signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the upgrade signature service.
     */
    public ServerSignerResponse upgradeSignature(UpgradeSignatureRequest upgSigReq, String idClient) {
	return IntegraFacadeWSDSS.getInstance().upgradeSignature(upgSigReq, idClient);
    }

    /**
     * Method that obtains the response of the async processes service.
     * @param pendingRequest Parameter that represents the request of the async processes service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the async processes service.
     */
    public AsynchronousResponse asynchronousRequest(PendingRequest pendingRequest, String idClient) {
	return IntegraFacadeWSDSS.getInstance().asynchronousRequest(pendingRequest, idClient);
    }

    /**
     * Method that obtains the response of the verify certificates on batch service.
     * @param batVerCerReq Parameter that represents the request of the verify certificates on batch service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the verify certificates on batch service.
     */
    public BatchVerifyCertificateResponse batchVerifyCertificate(BatchVerifyCertificateRequest batVerCerReq, String idClient) {
	return IntegraFacadeWSDSS.getInstance().batchVerifyCertificate(batVerCerReq, idClient);
    }

    /**
     * Method that obtains the response of the verify signatures on batch service.
     * @param batVerSigReq Parameter that represents the request of the verify signatures on batch service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the verify signatures on batch service.
     */
    public BatchVerifySignatureResponse batchVerifySignature(BatchVerifySignatureRequest batVerSigReq, String idClient) {
	return IntegraFacadeWSDSS.getInstance().batchVerifySignature(batVerSigReq, idClient);
    }

    /**
     * Method that obtains the response of the archive signatures retrieve service.
     * @param archiveRequest Parameter that represents the request of the archive signatures retrieve service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the archive signatures retrieve service.
     */
    public ArchiveResponse getArchiveRetrieval(ArchiveRequest archiveRequest, String idClient) {
	return IntegraFacadeWSDSS.getInstance().getArchiveRetrieval(archiveRequest, idClient);
    }

    /**
     * Method that obtains the response of the verify signature service.
     * @param verSigReq Parameter that represents the request of the verify signature service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the verify signature service.
     */
    public VerifySignatureResponse verifySignature(VerifySignatureRequest verSigReq, String idClient) {
	return IntegraFacadeWSDSS.getInstance().verifySignature(verSigReq, idClient);
    }

    /**
     * Method that obtains the response of the verify certificate service.
     * @param verCerReq Parameter that represents the request of the verify certificate service.
     * @param idClient client identifier of ws invocation.
     * @return an object that represents the response of the verify certificate service.
     */
    public VerifyCertificateResponse verifyCertificate(VerifyCertificateRequest verCerReq, String idClient) {
	return IntegraFacadeWSDSS.getInstance().verifyCertificate(verCerReq, idClient);
    }

}
