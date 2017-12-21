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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.SignatureFormat.java.</p>
 * <b>Description:</b><p>Class that represents the different signature forms.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import es.gob.afirma.utils.DSSConstants.SignTypesURIs;
import es.gob.afirma.utils.DSSConstants.SignatureForm;

/**
 * <p>Class that represents the different signature forms.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/11/2014.
 */
public enum SignatureFormatEnum {

    /**
     * Attribute that represents type and format of a signature.
     */
    CMS(SignTypesURIs.CMS, null), CAdES(SignTypesURIs.CADES, null), CAdES_BES(SignTypesURIs.CADES, SignatureForm.BES), CAdES_EPES(SignTypesURIs.CADES, SignatureForm.EPES), CAdES_T(SignTypesURIs.CADES, SignatureForm.T), CAdES_X(SignTypesURIs.CADES, SignatureForm.X), CAdES_X1(SignTypesURIs.CADES, SignatureForm.X_1), CAdES_X2(SignTypesURIs.CADES, SignatureForm.X_2), CAdES_XL(SignTypesURIs.CADES, SignatureForm.X_L), CAdES_XL1(SignTypesURIs.CADES, SignatureForm.X_L_1), CAdES_XL2(SignTypesURIs.CADES, SignatureForm.X_L_2), CAdES_A(SignTypesURIs.CADES, SignatureForm.A), CAdES_BASELINE(SignTypesURIs.CADES_BASELINE_2_2_1, null), CAdES_B_LEVEL(SignTypesURIs.CADES_BASELINE_2_2_1, SignatureForm.B_LEVEL), CAdES_T_LEVEL(SignTypesURIs.CADES_BASELINE_2_2_1, SignatureForm.T_LEVEL), CAdES_LT_LEVEL(SignTypesURIs.CADES_BASELINE_2_2_1, SignatureForm.LT_LEVEL), CAdES_LTA_LEVEL(SignTypesURIs.CADES_BASELINE_2_2_1, SignatureForm.LTA_LEVEL),XAdES(SignTypesURIs.XADES_V_1_3_2, null), XAdES_BES(SignTypesURIs.XADES_V_1_3_2, SignatureForm.BES), XAdES_EPES(SignTypesURIs.XADES_V_1_3_2, SignatureForm.EPES), XAdES_T(SignTypesURIs.XADES_V_1_3_2, SignatureForm.T), XAdES_C(SignTypesURIs.XADES_V_1_3_2, SignatureForm.C), XAdES_X(SignTypesURIs.XADES_V_1_3_2, SignatureForm.X), XAdES_X1(SignTypesURIs.XADES_V_1_3_2, SignatureForm.X_1), XAdES_X2(SignTypesURIs.XADES_V_1_3_2, SignatureForm.X_2), XAdES_XL(SignTypesURIs.XADES_V_1_3_2, SignatureForm.X_L), XAdES_XL1(SignTypesURIs.XADES_V_1_3_2, SignatureForm.X_L_1), XAdES_XL2(SignTypesURIs.XADES_V_1_3_2, SignatureForm.X_L_2), XAdES_A(SignTypesURIs.XADES_V_1_3_2, SignatureForm.A), XAdES_BASELINE(SignTypesURIs.XADES_BASELINE_2_1_1, null), XAdES_B_LEVEL(SignTypesURIs.XADES_BASELINE_2_1_1, SignatureForm.B_LEVEL), XAdES_T_LEVEL(SignTypesURIs.XADES_BASELINE_2_1_1, SignatureForm.T_LEVEL), XAdES_LT_LEVEL(SignTypesURIs.XADES_BASELINE_2_1_1, SignatureForm.LT_LEVEL), XAdES_LTA_LEVEL(SignTypesURIs.XADES_BASELINE_2_1_1, SignatureForm.LTA_LEVEL), ODF(SignTypesURIs.ODF, null), PDF(SignTypesURIs.PDF, null), PAdES(SignTypesURIs.PADES, SignatureForm.PADES_BASIC), PAdES_BES(SignTypesURIs.PADES, SignatureForm.PADES_BES), PAdES_EPES(SignTypesURIs.PADES, SignatureForm.PADES_EPES), PAdES_LTV(SignTypesURIs.PADES, SignatureForm.PADES_LTV), PAdES_BASELINE(SignTypesURIs.PADES_BASELINE_2_1_1, null), PAdES_B_LEVEL(SignTypesURIs.PADES_BASELINE_2_1_1, SignatureForm.B_LEVEL), PAdES_T_LEVEL(SignTypesURIs.PADES_BASELINE_2_1_1, SignatureForm.T_LEVEL), PAdES_LT_LEVEL(SignTypesURIs.PADES_BASELINE_2_1_1, SignatureForm.LT_LEVEL), PAdES_LTA_LEVEL(SignTypesURIs.PADES_BASELINE_2_1_1, SignatureForm.LTA_LEVEL);

    /**
     * Attribute that represents the URI of the signature type.
     */
    private final String uriType;

    /**
     * Attribute that represents the URI of the signature format.
     */
    private final String uriFormat;

    /**
     * Constructor method for the class HashAlgorithmEnum.java.
     * @param uriTypeParam Parameter that represents the URI of the signature type.
     * @param uriFormatParam Parameter that represents the URI of the signature format.
     */
    private SignatureFormatEnum(String uriTypeParam, String uriFormatParam) {
	this.uriType = uriTypeParam;
	this.uriFormat = uriFormatParam;
    }

    /**
     * Gets the value of the attribute {@link #uriType}.
     * @return the value of the attribute {@link #uriType}.
     */
    public String getUriType() {
	return uriType;
    }

    /**
     * Gets the value of the attribute {@link #uriFormat}.
     * @return the value of the attribute {@link #uriFormat}.
     */
    public String getUriFormat() {
	return uriFormat;
    }

}
