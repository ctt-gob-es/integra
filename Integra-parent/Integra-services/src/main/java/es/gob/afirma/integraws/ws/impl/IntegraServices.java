// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.integraws.ws.impl.IntegraServices.java.</p>
 * <b>Description:</b><p> Class that contains integra sing service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/05/2016.</p>
 * @author Gobierno de España.
 * @version 1.3, 13/04/2020.
 */
package es.gob.afirma.integraws.ws.impl;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.gob.afirma.hsm.HSMKeystore;
import es.gob.afirma.i18n.Language;
import es.gob.afirma.integraFacade.IntegraFacade;
import es.gob.afirma.integraFacade.IntegraFacadeBind;
import es.gob.afirma.integraFacade.IntegraFacadeConstants;
import es.gob.afirma.integraFacade.IntegraFacadeWSDSSBind;
import es.gob.afirma.integraFacade.pojo.ServerSignerResponse;
import es.gob.afirma.integraFacade.pojo.SignatureFormatEnum;
import es.gob.afirma.integraFacade.pojo.UpgradeSignatureRequest;
import es.gob.afirma.integraws.beans.RequestGetSignedData;
import es.gob.afirma.integraws.beans.RequestPAdESRubricSign;
import es.gob.afirma.integraws.beans.RequestSign;
import es.gob.afirma.integraws.beans.RequestUpgradeSign;
import es.gob.afirma.integraws.beans.RequestVerifySign;
import es.gob.afirma.integraws.beans.ResponseGetSignedData;
import es.gob.afirma.integraws.beans.ResponseSign;
import es.gob.afirma.integraws.beans.ResponseUpgradeSign;
import es.gob.afirma.integraws.beans.ResponseVerifySign;
import es.gob.afirma.integraws.beans.SignerToUpgrade;
import es.gob.afirma.integraws.beans.ValidationResultWS;
import es.gob.afirma.integraws.ws.IIntegraServices;
import es.gob.afirma.integraws.ws.IWSConstantKeys;
import es.gob.afirma.logger.IntegraLogger;
import es.gob.afirma.properties.IntegraProperties;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.signature.validation.PDFValidationResult;
import es.gob.afirma.signature.validation.ValidationResult;
import es.gob.afirma.utils.DSSConstants.SignTypesURIs;
import es.gob.afirma.utils.DSSConstants.SignatureForm;
import es.gob.afirma.utils.UtilsCertificate;
import es.gob.afirma.utils.UtilsSignatureOp;

/**
 * <p>Class that contains integra sing service implementations.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.3, 13/04/2020.
 */
public class IntegraServices implements IIntegraServices {

	/**
	 *  Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = IntegraLogger.getInstance().getLogger(IntegraServices.class);

	/**
	 * Attribute that represents the success result.
	 */
	private static final String SUCCESS = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";

	/**
	 * Attribute that represents the warning result.
	 */
	private static final String WARNING = "urn:oasis:names:tc:dss:1.0:resultmajor:Warning";

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.integraws.ws.IIntegraServices#generateSignature(es.gob.afirma.integraws.beans.RequestSign)
	 */
	public final ResponseSign generateSignature(RequestSign request) {

		Properties integraProperties = new IntegraProperties().getIntegraProperties(request.getIdClient());

		try {
			checkGenerateSignatureParams(request);

			PrivateKeyEntry pk = getPrivateKey(request.getIdClient(), request.getAlias());
			checkPK(pk);

			boolean includeTimestamp = includeTimestamp(request.getSignatureFormat(), integraProperties);
			byte[ ] signature = IntegraFacadeBind.generateSignature(getFacadeSignatureType(request.getSignatureFormat()), request.getDataToSign(), pk, request.isIncludeSignaturePolicy(), includeTimestamp, request.getIdClient());
			String message = null;

			String format = getFormatIfNoUpdated(request.isIncludeSignaturePolicy(), includeTimestamp, request.getSignatureFormat());

			if (upgradeSignature(request, integraProperties)) {
				UpgradeSignatureRequest req = new UpgradeSignatureRequest();

				req.setApplicationId(integraProperties.getProperty(IntegraFacadeConstants.KEY_AFIRMA_APP_ID));
				req.setIgnoreGracePeriod(true);
				req.setSignature(signature);
				req.setSignatureFormat(request.getSignatureFormat());

				ServerSignerResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().upgradeSignature(req, request.getIdClient());

				if (resultAfirma.getResult() == null || !SUCCESS.equals(resultAfirma.getResult().getResultMajor()) && !WARNING.equals(resultAfirma.getResult().getResultMajor())) {
					LOGGER.error(Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }) + " " + Language.getResIntegra(IWSConstantKeys.IWS_009));
					message = Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }) + " " + Language.getResIntegra(IWSConstantKeys.IWS_009);
				} else {
					if (resultAfirma.getUpdatedSignature() != null) {
						signature = resultAfirma.getUpdatedSignature();
					} else {
						signature = resultAfirma.getSignature();
					}
					if (WARNING.equals(resultAfirma.getResult().getResultMajor())) {
						message = resultAfirma.getResult().getResultMessage();
					}
				}
			} else {
				if (!isIntegraFormat(request.getSignatureFormat())) {
					LOGGER.error(Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }));
					message = Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format });
				}
			}

			ResponseSign resp = new ResponseSign(signature, true);
			if (message != null) {
				resp.setIntegraErrorMsg(message);
			}
			return resp;
		} catch (SigningException e) {
			return new ResponseSign(false, e.getMessage());
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.integraws.ws.IIntegraServices#generateSignaturePAdESRubric(es.gob.afirma.integraws.beans.RequestPAdESRubricSign)
	 */
	public final ResponseSign generateSignaturePAdESRubric(RequestPAdESRubricSign request) {

		if (request.getIdClient() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
			return new ResponseSign(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
		}
		if (request.getAlias() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_006));
			return new ResponseSign(false, Language.getResIntegra(IWSConstantKeys.IWS_006));
		}
		if (request.getImage() == null || request.getImagePage() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_016));
			return new ResponseSign(false, Language.getResIntegra(IWSConstantKeys.IWS_016));
		}

		try {
			PrivateKeyEntry pk = getPrivateKey(request.getIdClient(), request.getAlias());
			if (pk == null) {
				LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_007));
				return new ResponseSign(false, Language.getResIntegra(IWSConstantKeys.IWS_007));
			}
			return new ResponseSign(IntegraFacadeBind.generateSignaturePAdESRubric(getFacadeSignatureType(SignatureFormatEnum.PAdES), request.getDataToSign(), pk, request.isIncludeSignaturePolicy(), request.isIncludeTimestamp(), request.getImage(), request.getImagePage(), request.getLowerLeftX(), request.getLowerLeftY(), request.getUpperRightX(), request.getUpperRightY(), request.getIdClient()), true);
		} catch (SigningException e) {
			return new ResponseSign(false, e.getMessage());
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.integraws.ws.IIntegraServices#generateMultiSignaturePAdESRubric(es.gob.afirma.integraws.beans.RequestPAdESRubricSign)
	 */
	public final ResponseSign generateMultiSignaturePAdESRubric(RequestPAdESRubricSign request) {

		if (request.getIdClient() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
			return new ResponseSign(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
		}
		if (request.getAlias() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_006));
			return new ResponseSign(false, Language.getResIntegra(IWSConstantKeys.IWS_006));
		}

		try {
			PrivateKeyEntry pk = getPrivateKey(request.getIdClient(), request.getAlias());
			if (pk == null) {
				LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_007));
				return new ResponseSign(false, Language.getResIntegra(IWSConstantKeys.IWS_007));
			}
			return new ResponseSign(IntegraFacadeBind.generateMultiSignaturePAdESRubric(getFacadeSignatureType(SignatureFormatEnum.PAdES), request.getDataToSign(), pk, request.isIncludeSignaturePolicy(), request.isIncludeTimestamp(), request.getImage(), request.getImagePage(), request.getLowerLeftX(), request.getLowerLeftY(), request.getUpperRightX(), request.getUpperRightY(), request.getIdClient()), true);
		} catch (SigningException e) {
			return new ResponseSign(false, e.getMessage());
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.integraws.ws.IIntegraServices#generateCoSignature(es.gob.afirma.integraws.beans.RequestSign)
	 */
	public final ResponseSign generateCoSignature(RequestSign request) {
		try {
			checkGenerateCoAndCounterSignatureParams(request);

			Properties integraProperties = new IntegraProperties().getIntegraProperties(request.getIdClient());

			PrivateKeyEntry pk = getPrivateKey(request.getIdClient(), request.getAlias());
			checkPK(pk);

			boolean includeTimestamp = includeTimestamp(request.getSignatureFormat(), integraProperties);
			byte[ ] signature = IntegraFacadeBind.generateCoSignature(getFacadeSignatureType(request.getSignatureFormat()), request.getSignature(), request.getDataToSign(), pk, request.isIncludeSignaturePolicy(), includeTimestamp, request.getIdClient());
			String message = null;

			String format = getFormatIfNoUpdated(request.isIncludeSignaturePolicy(), includeTimestamp, request.getSignatureFormat());

			if (upgradeSignature(request, integraProperties)) {
				UpgradeSignatureRequest req = new UpgradeSignatureRequest();

				req.setApplicationId(integraProperties.getProperty(IntegraFacadeConstants.KEY_AFIRMA_APP_ID));
				req.setIgnoreGracePeriod(true);
				req.setSignature(signature);
				req.setSignatureFormat(request.getSignatureFormat());
				req.setTargetSigner(getCertificate(request.getIdClient(), request.getAlias()));

				ServerSignerResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().upgradeSignature(req, request.getIdClient());

				if (resultAfirma.getResult() == null || !SUCCESS.equals(resultAfirma.getResult().getResultMajor()) && !WARNING.equals(resultAfirma.getResult().getResultMajor())) {
					LOGGER.error(Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }) + " " + Language.getResIntegra(IWSConstantKeys.IWS_009));
					message = Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }) + " " + Language.getResIntegra(IWSConstantKeys.IWS_009);
				} else {
					if (resultAfirma.getUpdatedSignature() != null) {
						signature = resultAfirma.getUpdatedSignature();
					} else {
						signature = resultAfirma.getSignature();
					}
					if (WARNING.equals(resultAfirma.getResult().getResultMajor())) {
						message = resultAfirma.getResult().getResultMessage();
					}
				}
			} else {
				if (!isIntegraFormat(request.getSignatureFormat())) {
					LOGGER.error(Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }));
					message = Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format });
				}
			}

			ResponseSign resp = new ResponseSign(signature, true);
			if (message != null) {
				resp.setIntegraErrorMsg(message);
			}
			return resp;
		} catch (SigningException e) {
			return new ResponseSign(false, e.getMessage());
		}
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.integraws.ws.IIntegraServices#generateCounterSignature(es.gob.afirma.integraws.beans.RequestSign)
	 */
	public final ResponseSign generateCounterSignature(RequestSign request) {
		try {
			checkGenerateCoAndCounterSignatureParams(request);

			Properties integraProperties = new IntegraProperties().getIntegraProperties(request.getIdClient());

			PrivateKeyEntry pk = getPrivateKey(request.getIdClient(), request.getAlias());
			checkPK(pk);

			boolean includeTimestamp = includeTimestamp(request.getSignatureFormat(), integraProperties);
			byte[ ] signature = IntegraFacadeBind.generateCounterSignature(getFacadeSignatureType(request.getSignatureFormat()), request.getSignature(), pk, request.isIncludeSignaturePolicy(), includeTimestamp(request.getSignatureFormat(), integraProperties), request.getIdClient());
			String message = null;

			String format = getFormatIfNoUpdated(request.isIncludeSignaturePolicy(), includeTimestamp, request.getSignatureFormat());

			if (upgradeSignature(request, integraProperties)) {
				UpgradeSignatureRequest req = new UpgradeSignatureRequest();

				req.setApplicationId(integraProperties.getProperty(IntegraFacadeConstants.KEY_AFIRMA_APP_ID));
				req.setIgnoreGracePeriod(true);
				req.setSignature(signature);
				req.setSignatureFormat(request.getSignatureFormat());
				req.setTargetSigner(getCertificate(request.getIdClient(), request.getAlias()));

				ServerSignerResponse resultAfirma = IntegraFacadeWSDSSBind.getInstance().upgradeSignature(req, request.getIdClient());

				if (resultAfirma.getResult() == null || !SUCCESS.equals(resultAfirma.getResult().getResultMajor()) && !WARNING.equals(resultAfirma.getResult().getResultMajor())) {
					LOGGER.error(Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }) + " " + Language.getResIntegra(IWSConstantKeys.IWS_009));
					message = Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }) + " " + Language.getResIntegra(IWSConstantKeys.IWS_009);
				} else {
					if (resultAfirma.getUpdatedSignature() != null) {
						signature = resultAfirma.getUpdatedSignature();
					} else {
						signature = resultAfirma.getSignature();
					}
					if (WARNING.equals(resultAfirma.getResult().getResultMajor())) {
						message = resultAfirma.getResult().getResultMessage();
					}
				}
			} else {
				if (!isIntegraFormat(request.getSignatureFormat())) {
					LOGGER.error(Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format }));
					message = Language.getFormatResIntegra(IWSConstantKeys.IWS_013, new String[ ] { request.getSignatureFormat().name(), format });
				}
			}

			ResponseSign resp = new ResponseSign(signature, true);
			if (message != null) {
				resp.setIntegraErrorMsg(message);
			}
			return resp;
		} catch (SigningException e) {
			return new ResponseSign(false, e.getMessage());
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.integraws.ws.IIntegraServices#upgradeSignature(es.gob.afirma.integraws.beans.RequestUpgradeSign)
	 */
	public final ResponseUpgradeSign upgradeSignature(RequestUpgradeSign request) {

		if (request.getIdClient() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
			return new ResponseUpgradeSign(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
		}

		List<X509Certificate> signerList = null;

		if (request.getListSigners() != null && !request.getListSigners().isEmpty()) {
			signerList = new ArrayList<X509Certificate>();
			for (SignerToUpgrade signer: request.getListSigners()) {
				try {
					signerList.add(UtilsCertificate.generateCertificate(signer.getSigner()));
				} catch (CertificateException e) {
					return new ResponseUpgradeSign(false, e.getMessage());
				}
			}
		}

		if (request.getSignature() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_008));
			return new ResponseUpgradeSign(false, Language.getResIntegra(IWSConstantKeys.IWS_008));
		}

		try {
		    byte [] signature = IntegraFacadeBind.upgradeSignature(request.getSignature(), signerList, request.getIdClient());
			return new ResponseUpgradeSign(signature, true, UtilsSignatureOp.getExpirationDate(signature));
		} catch (SigningException e) {
			return new ResponseUpgradeSign(false, e.getMessage());
		}
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.integraws.ws.IIntegraServices#verifySignature(es.gob.afirma.integraws.beans.RequestVerifySign)
	 */
	public final ResponseVerifySign verifySignature(RequestVerifySign request) {

		if (request.getIdClient() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
			return new ResponseVerifySign(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
		}
		if (request.getSignature() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_008));
			return new ResponseVerifySign(false, Language.getResIntegra(IWSConstantKeys.IWS_008));
		}
		Object vr = IntegraFacadeBind.verifySignature(request.getSignature(), request.getSignedData(), request.getIdClient());
		if (vr instanceof ValidationResult) {
			ValidationResultWS vrws = new ValidationResultWS((ValidationResult) vr);
			return new ResponseVerifySign(vrws, true);
		} else if (vr instanceof PDFValidationResult) {
			ValidationResultWS vrws = new ValidationResultWS((PDFValidationResult) vr);
			return new ResponseVerifySign(vrws, true);
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.integraws.ws.IIntegraServices#getSignedData(es.gob.afirma.integraws.beans.RequestGetSignedData)
	 */
	public final ResponseGetSignedData getSignedData(RequestGetSignedData request) {
		if (request.getIdClient() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
			return new ResponseGetSignedData(false, Language.getResIntegra(IWSConstantKeys.IWS_002));
		}
		if (request.getSignature() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_008));
			return new ResponseGetSignedData(false, Language.getResIntegra(IWSConstantKeys.IWS_008));
		}

		try {
			return new ResponseGetSignedData(IntegraFacade.getSignedData(request.getSignature()), true);
		} catch (SigningException e) {
			return new ResponseGetSignedData(false, e.getMessage());
		}
	}

	/**
	 * Method that checks a private key.
	 * @param pk private key to check.
	 * @throws SigningException if private key is not valid.
	 */
	private void checkPK(PrivateKeyEntry pk) throws SigningException {
		if (pk == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_007));
			throw new SigningException(Language.getResIntegra(IWSConstantKeys.IWS_007));
		}

	}

	/**
	 * Method that checks the request params for generate signature.
	 * @param request RequestSign object.
	 * @throws SigningException if any required value is not present.
	 */
	private void checkGenerateSignatureParams(RequestSign request) throws SigningException {
		if (request.getIdClient() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
			throw new SigningException(Language.getResIntegra(IWSConstantKeys.IWS_002));
		}
		if (request.getAlias() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_006));
			throw new SigningException(Language.getResIntegra(IWSConstantKeys.IWS_006));
		}
		if (request.getSignatureFormat() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_012));
			throw new SigningException(Language.getResIntegra(IWSConstantKeys.IWS_012));
		}

	}

	/**
	 * Method that checks the request params for generate co or counter signature.
	 * @param request RequestSign object.
	 * @throws SigningException if any required value is not present.
	 */
	private void checkGenerateCoAndCounterSignatureParams(RequestSign request) throws SigningException {
		if (request.getIdClient() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_002));
			throw new SigningException(Language.getResIntegra(IWSConstantKeys.IWS_002));
		}
		if (request.getAlias() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_006));
			throw new SigningException(Language.getResIntegra(IWSConstantKeys.IWS_006));
		}
		if (request.getSignatureFormat() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_012));
			throw new SigningException(Language.getResIntegra(IWSConstantKeys.IWS_012));
		}
		if (request.getSignature() == null) {
			LOGGER.error(Language.getResIntegra(IWSConstantKeys.IWS_008));
			throw new SigningException(Language.getResIntegra(IWSConstantKeys.IWS_008));
		}
	}

	/**
	 * Method that indicates if a Signature format enum is a integra valid format.
	 * @param signatureFormat format to check
	 * @return true if is a integra format, false otherwise.
	 */
	private boolean isIntegraFormat(SignatureFormatEnum signatureFormat) {
		if (signatureFormat.getUriFormat() == null) {
			return true;
		} else {
			if (isCAdESXAdES(signatureFormat.getUriFormat()) || isPAdES(signatureFormat.getUriFormat()) || isBaseline(signatureFormat.getUriFormat())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method that indicates if a uriFormat is a baseline format valid for integra sign.
	 * @param uriFormat format to check
	 * @return true if uriFormat is a baseline format valid for integra sign, false otherwise.
	 */
	private boolean isBaseline(String uriFormat) {
		return uriFormat.equals(SignatureForm.B_LEVEL) || uriFormat.equals(SignatureForm.T_LEVEL);
	}

	/**
	 * Method that indicates if a uriFormat is a pades format valid for integra sign.
	 * @param uriFormat format to check
	 * @return true if uriFormat is a pades format valid for integra sign, false otherwise.
	 */
	private boolean isPAdES(String uriFormat) {
		return uriFormat.equals(SignatureForm.PADES_BASIC) || uriFormat.equals(SignatureForm.PADES_BES) || uriFormat.equals(SignatureForm.PADES_EPES) || uriFormat.equals(SignatureForm.PADES_LTV);
	}

	/**
	 * Method that indicates if a uriFormat is a cades/xades format valid for integra sign.
	 * @param uriFormat format to check
	 * @return true if uriFormat is a cades/xades format valid for integra sign, false otherwise.
	 */
	private boolean isCAdESXAdES(String uriFormat) {
		return uriFormat.equals(SignatureForm.BES) || uriFormat.equals(SignatureForm.EPES) || uriFormat.equals(SignatureForm.T);
	}

	/**
	 * Method that returns a string representation of final format if the sign are not updated from @firma.
	 * @param includeSignaturePolicy indicates if signature policy are included.
	 * @param includeTimestamp indicates if timestamp are included.
	 * @param signatureFormat original format required.
	 * @return string representation of final format if the sign are not updated from @firma.
	 */
	private String getFormatIfNoUpdated(boolean includeSignaturePolicy, boolean includeTimestamp, SignatureFormatEnum signatureFormat) {
		String format = "";
		if (includeSignaturePolicy) {
			format = getFormatIfNotUpdatedWithPolicy(signatureFormat, includeTimestamp);
		} else {
			format = getFormatIfNotUpdatedWithoutPolicy(signatureFormat, includeTimestamp);
		}
		if (format.isEmpty()) {
			if (signatureFormat.getUriType().equals(SignTypesURIs.CADES_BASELINE_2_2_1)) {
				format = includeTimestamp ? SignatureFormatEnum.CAdES_T_LEVEL.name() : SignatureFormatEnum.CAdES_B_LEVEL.name();
			} else if (signatureFormat.getUriType().equals(SignTypesURIs.PADES_BASELINE_2_1_1)) {
				format = includeTimestamp ? SignatureFormatEnum.PAdES_T_LEVEL.name() : SignatureFormatEnum.PAdES_B_LEVEL.name();
			} else if (signatureFormat.getUriType().equals(SignTypesURIs.XADES_BASELINE_2_1_1)) {
				format = includeTimestamp ? SignatureFormatEnum.XAdES_T_LEVEL.name() : SignatureFormatEnum.XAdES_B_LEVEL.name();
			}
		}
		return format;
	}

	/**
	 * Method that returns a string representation of final format if the sign are not updated from @firma and dont have signature policy.
	 * @param includeTimestamp indicates if timestamp are included.
	 * @param signatureFormat original format required.
	 * @return string representation of final format if the sign are not updated from @firma and dont have signature policy.
	 */
	private String getFormatIfNotUpdatedWithoutPolicy(SignatureFormatEnum signatureFormat, boolean includeTimestamp) {
		if (signatureFormat.getUriType().equals(SignTypesURIs.CADES)) {
			return includeTimestamp ? SignatureFormatEnum.CAdES_T.name() : SignatureFormatEnum.CAdES_BES.name();
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.PADES)) {
			return includeTimestamp ? SignatureFormatEnum.PAdES_LTV.name() : SignatureFormatEnum.PAdES_BES.name();
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_1_1) || signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_2_2) || signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_3_2)) {
			return includeTimestamp ? SignatureFormatEnum.XAdES_T.name() : SignatureFormatEnum.XAdES_BES.name();
		}
		return "";
	}

	/**
	 * Method that returns a string representation of final format if the sign are not updated from @firma and have signature policy.
	 * @param includeTimestamp indicates if timestamp are included.
	 * @param signatureFormat original format required.
	 * @return string representation of final format if the sign are not updated from @firma and have signature policy.
	 */
	private String getFormatIfNotUpdatedWithPolicy(SignatureFormatEnum signatureFormat, boolean includeTimestamp) {
		if (signatureFormat.getUriType().equals(SignTypesURIs.CADES)) {
			return includeTimestamp ? SignatureFormatEnum.CAdES_T.name() : SignatureFormatEnum.CAdES_EPES.name();
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.PADES)) {
			return includeTimestamp ? SignatureFormatEnum.PAdES_LTV.name() : SignatureFormatEnum.PAdES_EPES.name();
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_1_1) || signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_2_2) || signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_3_2)) {
			return includeTimestamp ? SignatureFormatEnum.XAdES_T.name() : SignatureFormatEnum.XAdES_EPES.name();
		}
		return "";
	}

	/**
	 * Method that returns a string representation of signature formata needed for integra facade.
	 * @param signatureFormat original signature format.
	 * @return string representation of signature formata needed for integra facade.
	 */
	private String getFacadeSignatureType(SignatureFormatEnum signatureFormat) {

		if (signatureFormat.getUriType().equals(SignTypesURIs.CADES_BASELINE_2_2_1)) {
			return "CAdES Baseline";
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.PADES_BASELINE_2_1_1)) {
			return "PAdES Baseline";
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.XADES_BASELINE_2_1_1)) {
			return "XAdES Baseline";
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.CADES)) {
			return "CAdES";
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.PADES)) {
			return "PAdES";
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_1_1)) {
			return "XAdES";
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_2_2)) {
			return "XAdES";
		} else if (signatureFormat.getUriType().equals(SignTypesURIs.XADES_V_1_3_2)) {
			return "XAdES";
		}

		return "";
	}

	/**
	 * Method that indicates if integra facade need include a timestamp in the signature.
	 * @param sfe signature format.
	 * @param integraProperties integra properties file values.
	 * @return true if integra facade need include a timestamp in the signature, false otherwise.
	 */
	private boolean includeTimestamp(SignatureFormatEnum sfe, Properties integraProperties) {
		String upgradeInAfirma = (String) integraProperties.get(IntegraFacadeConstants.KEY_UPPER_FORMAT_UPGRADE_AFIRMA);
		if (upgradeInAfirma != null && upgradeInAfirma.equals("true")) {
			return false;
		}
		// CHECKSTYLE:OFF expression complexity needed
		if (sfe.getUriFormat() != null && !sfe.getUriFormat().equals(SignatureForm.BES) && !sfe.getUriFormat().equals(SignatureForm.EPES) && !sfe.getUriFormat().equals(SignatureForm.B_LEVEL) && !sfe.getUriFormat().equals(SignatureForm.PADES_BASIC) && !sfe.getUriFormat().equals(SignatureForm.PADES_BES) && !sfe.getUriFormat().equals(SignatureForm.PADES_EPES)) {
			// CHECKSTYLE:ON
			return true;
		}
		return false;
	}

	/**
	 * Method that indicates if the signature need to be upgrade from @firma.
	 * @param request request object
	 * @param integraProperties integra properties file values.
	 * @return true if the signature need to be upgrade from @firma, false otherwise.
	 */
	private boolean upgradeSignature(RequestSign request, Properties integraProperties) {

		String upgradeInAfirma = (String) integraProperties.get(IntegraFacadeConstants.KEY_UPPER_FORMAT_UPGRADE_AFIRMA);
		if (upgradeInAfirma != null && upgradeInAfirma.equals("true")) {
			if (SignatureForm.B_LEVEL.equals(request.getSignatureFormat().getUriFormat())) {
				return false;
			}
			if (!request.getSignatureFormat().getUriType().equals(SignTypesURIs.PADES)) {
				if (request.getSignatureFormat().getUriFormat() == null || request.getSignatureFormat().getUriFormat().equals(SignatureForm.BES) || request.getSignatureFormat().getUriFormat().equals(SignatureForm.EPES)) {
					return false;
				}
				return true;
			} else {
				if (request.getSignatureFormat().getUriFormat() != null && request.getSignatureFormat().getUriFormat().equals(SignatureForm.PADES_LTV)) {
					return true;
				}
				return false;
			}
		}
		return false;
	}

	/**
	 * Obtains the private key from a indicated keystore.
	 * @param idClient id del cliente que invoca al servicio
	 * @param alias Alias del certificado
	 * @return private key
	 */
	private PrivateKeyEntry getPrivateKey(String idClient, String alias) {
		KeyStore.Entry key = null;
		try {
			Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);

			String useHSM = (String) integraProperties.get(IntegraFacadeConstants.KEY_USE_HSM);

			if (useHSM != null && "true".equals(useHSM)) {
				key = HSMKeystore.getPrivateKeyEntry(alias);
			} else {

				String keystorePath = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE);

				String keystorePass = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE_PASS);

				String keystoreType = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE_TYPE);

				InputStream is = new FileInputStream(keystorePath);
				KeyStore ks = KeyStore.getInstance(keystoreType);
				char[ ] password = keystorePass.toCharArray();
				ks.load(is, password);
				key = ks.getEntry(alias, new KeyStore.PasswordProtection(password));
			}
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			return null;
		}
		return (KeyStore.PrivateKeyEntry) key;
	}

	/**
	 * Obtains the certificate from a indicated keystore.
	 * @param idClient id del cliente que invoca al servicio
	 * @param alias Alias del certificado
	 * @return private key
	 */
	private byte[ ] getCertificate(String idClient, String alias) {

		try {
			Properties integraProperties = new IntegraProperties().getIntegraProperties(idClient);

			String useHSM = (String) integraProperties.get(IntegraFacadeConstants.KEY_USE_HSM);

			if (useHSM != null && "true".equals(useHSM)) {
				return HSMKeystore.getCertificate(alias).getEncoded();
			} else {
				String keystorePath = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE);

				String keystorePass = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE_PASS);

				String keystoreType = (String) integraProperties.get(IntegraFacadeConstants.KEY_WS_KEYSTORE_TYPE);

				InputStream is = new FileInputStream(keystorePath);
				KeyStore ks = KeyStore.getInstance(keystoreType);
				char[ ] password = keystorePass.toCharArray();
				ks.load(is, password);
				return ks.getCertificate(alias).getEncoded();
			}
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			return null;
		}
	}
}
