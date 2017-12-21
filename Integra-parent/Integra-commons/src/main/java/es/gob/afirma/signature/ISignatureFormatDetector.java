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
 * <b>File:</b><p>es.gob.afirma.signature.ISignatureFormatDetector.java.</p>
 * <b>Description:</b><p>Interface that defines the recognized signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>14/01/2016.</p>
 * @author Gobierno de España.
 * @version 1.2, 14/03/2017.
 */
package es.gob.afirma.signature;

/**
 * <p>Interface that defines the recognized signature formats.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 14/03/2017.
 */
public interface ISignatureFormatDetector {

    /**
     * Constant attribute that identifies the unrecognized signature format.
     */
    String FORMAT_UNRECOGNIZED = "UNRECOGNIZED";

    /**
     * Constant attribute that identifies CAdES-A signature format.
     */
    String FORMAT_CADES_A = "CAdES-A";

    /**
     * Constant attribute that identifies CAdES-XL1 signature format.
     */
    String FORMAT_CADES_XL1 = "CAdES-XL1";

    /**
     * Constant attribute that identifies CAdES-XL2 signature format.
     */
    String FORMAT_CADES_XL2 = "CAdES-XL2";

    /**
     * Constant attribute that identifies CAdES-X1 signature format.
     */
    String FORMAT_CADES_X1 = "CAdES-X1";

    /**
     * Constant attribute that identifies CAdES-X2 signature format.
     */
    String FORMAT_CADES_X2 = "CAdES-X2";

    /**
     * Constant attribute that identifies CAdES-C signature format.
     */
    String FORMAT_CADES_C = "CAdES-C";

    /**
     * Constant attribute that identifies CAdES-T signature format.
     */
    String FORMAT_CADES_T = "CAdES-T";

    /**
     * Constant attribute that identifies CAdES-EPES signature format.
     */
    String FORMAT_CADES_EPES = "CAdES-EPES";

    /**
     * Constant attribute that identifies CAdES-BES signature format.
     */
    String FORMAT_CADES_BES = "CAdES-BES";

    /**
     * Constant attribute that identifies CMS signature format.
     */
    String FORMAT_CMS = "CMS";

    /**
     * Constant attribute that identifies CMS-T signature format.
     */
    String FORMAT_CMS_T = "CMS-T";

    /**
     * Constant attribute that identifies XAdES-A signature format.
     */
    String FORMAT_XADES_A = "XAdES-A";

    /**
     * Constant attribute that identifies XAdES-XL1 signature format.
     */
    String FORMAT_XADES_XL1 = "XAdES-XL1";

    /**
     * Constant attribute that identifies XAdES-XL2 signature format.
     */
    String FORMAT_XADES_XL2 = "XAdES-XL2";

    /**
     * Constant attribute that identifies XAdES-X1 signature format.
     */
    String FORMAT_XADES_X1 = "XAdES-X1";

    /**
     * Constant attribute that identifies XAdES-X2 signature format.
     */
    String FORMAT_XADES_X2 = "XAdES-X2";

    /**
     * Constant attribute that identifies XAdES-C signature format.
     */
    String FORMAT_XADES_C = "XAdES-C";

    /**
     * Constant attribute that identifies XAdES-T signature format.
     */
    String FORMAT_XADES_T = "XAdES-T";

    /**
     * Constant attribute that identifies XAdES-EPES signature format.
     */
    String FORMAT_XADES_EPES = "XAdES-EPES";

    /**
     * Constant attribute that identifies XAdES-BES signature format.
     */
    String FORMAT_XADES_BES = "XAdES-BES";

    /**
     * Constant attribute that identifies PDF signature format.
     */
    String FORMAT_PDF = "PDF";

    /**
     * Constant attribute that identifies PAdES-Basic signature format.
     */
    String FORMAT_PADES_BASIC = "PAdES-Basic";

    /**
     * Constant attribute that identifies PAdES-BES signature format.
     */
    String FORMAT_PADES_BES = "PAdES-BES";

    /**
     * Constant attribute that identifies PAdES-EPES signature format.
     */
    String FORMAT_PADES_EPES = "PAdES-EPES";

    /**
     * Constant attribute that identifies PAdES-LTV signature format.
     */
    String FORMAT_PADES_LTV = "PAdES-LTV";

    /**
     * Constant attribute that identifies CAdES B-Level signature format.
     */
    String FORMAT_CADES_B_LEVEL = "CAdES B-Level";

    /**
     * Constant attribute that identifies CAdES T-Level signature format.
     */
    String FORMAT_CADES_T_LEVEL = "CAdES T-Level";

    /**
     * Constant attribute that identifies CAdES LT-Level signature format.
     */
    String FORMAT_CADES_LT_LEVEL = "CAdES LT-Level";

    /**
     * Constant attribute that identifies CAdES LTA-Level signature format.
     */
    String FORMAT_CADES_LTA_LEVEL = "CAdES LTA-Level";

    /**
     * Constant attribute that identifies XAdES B-Level signature format.
     */
    String FORMAT_XADES_B_LEVEL = "XAdES B-Level";

    /**
     * Constant attribute that identifies XAdES T-Level signature format.
     */
    String FORMAT_XADES_T_LEVEL = "XAdES T-Level";

    /**
     * Constant attribute that identifies XAdES LT-Level signature format.
     */
    String FORMAT_XADES_LT_LEVEL = "XAdES LT-Level";

    /**
     * Constant attribute that identifies XAdES LTA-Level signature format.
     */
    String FORMAT_XADES_LTA_LEVEL = "XAdES LTA-Level";

    /**
     * Constant attribute that identifies PAdES B-Level signature format.
     */
    String FORMAT_PADES_B_LEVEL = "PAdES B-Level";

    /**
     * Constant attribute that identifies PAdES T-Level signature format.
     */
    String FORMAT_PADES_T_LEVEL = "PAdES T-Level";

    /**
     * Constant attribute that identifies PAdES LT-Level signature format.
     */
    String FORMAT_PADES_LT_LEVEL = "PAdES LT-Level";

    /**
     * Constant attribute that identifies PAdES LTA-Level signature format.
     */
    String FORMAT_PADES_LTA_LEVEL = "PAdES LTA-Level";

    /**
     * Constant attribute that identifies ASiC-S B-Level signature format.
     */
    String FORMAT_ASIC_S_B_LEVEL = "ASiC-S B-Level";

    /**
     * Constant attribute that identifies ASiC-S T-Level signature format.
     */
    String FORMAT_ASIC_S_T_LEVEL = "ASiC-S T-Level";

    /**
     * Constant attribute that identifies ASiC-S LT-Level signature format.
     */
    String FORMAT_ASIC_S_LT_LEVEL = "ASiC-S LT-Level";

    /**
     * Constant attribute that identifies ASiC-S LTA-Level signature format.
     */
    String FORMAT_ASIC_S_LTA_LEVEL = "ASiC-S LTA-Level";

    /**
     * Constant attribute that represents the string to identify the CAdES basic profile.
     */
    String CADES_BASIC_FORMAT = "CADES";

    /**
     * Constant attribute that represents the string to identify the <i>PKCS7</i> basic format.
     */
    String PKCS7_BASIC_FORMAT = "PKCS7";

}
