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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/** 
 * <b>File:</b><p>es.gob.signaturereport.barcode.BarcodeImage.java.</p>
 * <b>Description:</b><p> Class that represents the image of bar code.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 19/08/2020.
 */
package es.gob.afirma.mreport.items;

/** 
 * <p>Class that represents the image of bar code.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/08/2020.
 */
public class BarcodeImage extends AImage {

	/**
	 * Attribute that represents the bar code type. 
	 */
	private String barcodeType = null;

	/**
	 * Attribute that represents the bar code message. 
	 */
	private String message = null;

	/**
	 * Constructor method for the class BarcodeImage.java.
	 * @param type	Bar code type.
	 * @param msg 		Bar code message.
	 */
	public BarcodeImage(String type, String msg) {
		super();
		this.barcodeType = type;
		this.message = msg;
	}

	/**
	 * Gets the value of the bar code type.
	 * @return the value of the bar code type.
	 */
	public String getBarcodeType() {
		return barcodeType;
	}

	/**
	 * Sets the value of the bar code type.
	 * @param type The value for the bar code type.
	 */
	public void setBarcodeType(String type) {
		this.barcodeType = type;
	}

	/**
	 * Gets the value of the bar code message.
	 * @return the value of the bar code message.
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * Sets the value of the bar code message.
	 * @param barcodeMessage The value for the bar code message.
	 */
	public void setMessage(String barcodeMessage) {
		this.message = barcodeMessage;
	}

}
