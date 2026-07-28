// Copyright (C) 2018, Gobierno de España
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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.mreport.items.Barcode.java.</p>
 * <b>Description:</b><p> Class that represents a bar code to include into signature report.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 28/08/2020.
 */
package es.gob.afirma.mreport.items;

import java.util.LinkedHashMap;

/** 
 * <p>Class that represents a bar code to include into signature report.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/08/2020.
 */
public class Barcode {

    /**
     * Attribute that represents the type of bar code to create. 
     */
    private String type = null;

    /**
     * Attribute that represents the message used to create the bar code. 
     */
    private String message = null;

    /**
     * Attribute that represents additional parameters of configuration. 
     */
    private LinkedHashMap<String, String> configuration = new LinkedHashMap<String, String>();

    /**
     * Constructor method for the class BarcodeImage.java.
     * @param barcodeType	Type of bar code to create.
     * @param codeMessage 	 Message used to create the bar code.
     */
    public Barcode(String barcodeType, String codeMessage) {
	super();
	this.type = barcodeType;
	this.message = codeMessage;
    }

    /**
     * Gets the value of the type of bar code to create.
     * @return the value of the type of bar code to create.
     */
    public String getType() {
	return type;
    }

    /**
     * Sets the value of the type of bar code to create.
     * @param barcodeType The value for the type of bar code to create.
     */
    public void setType(String barcodeType) {
	this.type = barcodeType;
    }

    /**
     * Gets the value of the message used to create the bar code.
     * @return the value of the message used to create the bar code.
     */
    public String getMessage() {
	return message;
    }

    /**
     * Sets the value of the message used to create the bar code.
     * @param codeMessage The value for the message used to create the bar code.
     */
    public void setMessage(String codeMessage) {
	this.message = codeMessage;
    }

    /**
     * Gets the value of additional parameters of configuration.
     * @return the value of additional parameters of configuration.
     */
    public LinkedHashMap<String, String> getConfiguration() {
	return configuration;
    }

    /**
     * Sets the value of additional parameters of configuration.
     * @param confParameters The value for additional parameters of configuration.
     */
    public void setConfiguration(LinkedHashMap<String, String> confParameters) {
	this.configuration = confParameters;
    }
}
