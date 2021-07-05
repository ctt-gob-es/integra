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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.extensions.ExpiredCertsRevocationInfo.java.</p>
 * <b>Description:</b><p>Class that represents a TSL extension that indicates the time from which
 * on the service issues CRL and/or OCSP responses that keep revocation notices for revoked certificates
 * also after they have expired.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 15/06/2021.
 */
package es.gob.afirma.tsl.parsing.impl.common.extensions;

import java.util.Date;

import es.gob.afirma.tsl.i18n.Language;
import es.gob.afirma.tsl.exceptions.TSLMalformedException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.parsing.ifaces.IAnyTypeExtension;
import es.gob.afirma.tsl.parsing.ifaces.ITSLCommonURIs;
import es.gob.afirma.tsl.parsing.ifaces.ITSLElementsAndAttributes;
import es.gob.afirma.tsl.parsing.ifaces.ITSLObject;
import es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance;


/** 
 * <p>Class that represents a TSL extension that indicates the time from which
 * on the service issues CRL and/or OCSP responses that keep revocation notices for revoked certificates
 * also after they have expired.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 15/06/2021.
 */
public class ExpiredCertsRevocationInfo extends Extension {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -366367987588570350L;

	/**
	 * Attribute that represents the expired date.
	 */
	private Date expiredDate = null;

	/**
	 * Constructor method for the class ExpiredCertsRevocationInfo.java.
	 * @param isCritical Flag to indicate if this extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType Extension type. Refer to its location inside the XML. It could be one of the following:
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 */
	private ExpiredCertsRevocationInfo(boolean isCritical, int extensionType) {
		super(isCritical, extensionType, IAnyTypeExtension.IMPL_EXPIRED_CERTS_REVOCATION_INFO);
	}

	/**
	 * Constructor method for the class ExpiredCertsRevocationInfo.java.
	 * @param expired Expired date to set.
	 * @param isCritical Flag to indicate if this extension is critical (<code>true</code>) or not (<code>false</code>).
	 * @param extensionType Extension type. Refer to its location inside the XML. It could be one of the following:
	 * <ul>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SCHEME}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_TSP_INFORMATION}</li>
	 * 	<li>Scheme Extension: {@link IAnyTypeExtension#TYPE_SERVICE_INFORMATION}</li>
	 * </ul>
	 */
	public ExpiredCertsRevocationInfo(Date expired, boolean isCritical, int extensionType) {
		this(isCritical, extensionType);
		expiredDate = expired;
	}

	/**
	 * Gets the value of the attribute {@link #expiredDate}.
	 * @return the value of the attribute {@link #expiredDate}.
	 */
	public final Date getExpiredDate() {
		return expiredDate;
	}

	/**
	 * Sets the value of the attribute {@link #expiredDate}.
	 * @param expiredDateParam The value for the attribute {@link #expiredDate}.
	 */
	public final void setExpiredDate(Date expiredDateParam) {
		this.expiredDate = expiredDateParam;
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.extensions.Extension#checkExtensionTypeSpec119612Vers020101()
	 */
	@Override
	protected final void checkExtensionTypeSpec119612Vers020101() throws TSLMalformedException {

		// Esta extensión tan solo puede ser del tipo
		// 'ServiceInformationExtension'.
		if (getExtensionType() != IAnyTypeExtension.TYPE_SERVICE_INFORMATION) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG001, new Object[ ] { extensionTypeToString(IAnyTypeExtension.TYPE_SERVICE_INFORMATION), extensionTypeToString(getExtensionType()) }));
		}

	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.afirma.tsl.parsing.impl.common.extensions.Extension#checkExtensionValueSpec119612Vers020101(es.gob.afirma.tsl.parsing.ifaces.ITSLObject, es.gob.afirma.tsl.parsing.impl.common.ServiceHistoryInstance, boolean)
	 */
	@Override
	protected final void checkExtensionValueSpec119612Vers020101(ITSLObject tsl, ServiceHistoryInstance shi, boolean isCritical) throws TSLMalformedException {

		// Según la especificación, la extensión NO puede ser crítica.
		if (isCritical) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG002, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_EXPIREDCERTSREVOCATIONINFO }));
		}

		// El tipo del servicio asociado debe ser CA(PKC), CA(QC),
		// NationalRootCA-QC, OCPS, OCSP(QC), CRL o CRL(QC).
		String serviceType = shi.getServiceTypeIdentifier().toString();

		boolean isServiceTypeOK = serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CA_PKC) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CA_QC) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_NATIONALROOTCA);
		isServiceTypeOK = isServiceTypeOK || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_OCSP) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_OCSP_QC);
		isServiceTypeOK = isServiceTypeOK || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_CRL) || serviceType.equals(ITSLCommonURIs.TSL_SERVICETYPE_CERTSTATUS_CRL_QC);
		if (!isServiceTypeOK) {
			throw new TSLMalformedException(Language.getFormatResIntegraTsl(ILogTslConstant.EXT_LOG003, new Object[ ] { ITSLElementsAndAttributes.ELEMENT_EXTENSION_EXPIREDCERTSREVOCATIONINFO, serviceType }));
		}

	}


}
