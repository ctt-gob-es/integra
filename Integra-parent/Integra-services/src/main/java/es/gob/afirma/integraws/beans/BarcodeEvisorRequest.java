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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.BarcodeEvisorRequest.java.</p>
 * <b>Description:</b><p> Class that represents the request object for barcode information contained in RequestEvisorGenerateReport class.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

import java.util.List;

/** 
 * <p>Class that represents the request object for barcode information contained in RequestEvisorGenerateReport class.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class BarcodeEvisorRequest {

    /**
     * Attribute that represents barcode type. 
     */
    private BarcodeTypeEnum barcodeType;

    /**
     * Attribute that represents barcode message. 
     */
    private String barcodeMessage;

    /**
     * Attribute that represents the list of configuration parameters to generate barcode. 
     */
    private List<ParameterEvisorRequest> configurationParameterList;

    /**
     * Gets the value of the attribute {@link #barcodeType}.
     * @return the value of the attribute {@link #barcodeType}.
     */
    public final BarcodeTypeEnum getBarcodeType() {
	return barcodeType;
    }

    /**
     * Sets the value of the attribute {@link #barcodeType}.
     * @param barcodeTypeParam The value for the attribute {@link #barcodeType}.
     */
    public final void setBarcodeType(BarcodeTypeEnum barcodeTypeParam) {
	this.barcodeType = barcodeTypeParam;
    }

    /**
     * Gets the value of the attribute {@link #barcodeMessage}.
     * @return the value of the attribute {@link #barcodeMessage}.
     */
    public final String getBarcodeMessage() {
	return barcodeMessage;
    }

    /**
     * Sets the value of the attribute {@link #barcodeMessage}.
     * @param barcodeMessageParam The value for the attribute {@link #barcodeMessage}.
     */
    public final void setBarcodeMessage(String barcodeMessageParam) {
	this.barcodeMessage = barcodeMessageParam;
    }

    /**
     * Gets the value of the attribute {@link #configurationParameterList}.
     * @return the value of the attribute {@link #configurationParameterList}.
     */
    public final List<ParameterEvisorRequest> getConfigurationParameterList() {
	return configurationParameterList;
    }

    /**
     * Sets the value of the attribute {@link #configurationParameterList}.
     * @param configurationParameterListParam The value for the attribute {@link #configurationParameterList}.
     */
    public final void setConfigurationParameterList(List<ParameterEvisorRequest> configurationParameterListParam) {
	this.configurationParameterList = configurationParameterListParam;
    }

}
