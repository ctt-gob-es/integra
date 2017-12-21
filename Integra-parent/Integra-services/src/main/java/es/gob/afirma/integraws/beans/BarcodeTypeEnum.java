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
 * <b>File:</b><p>es.gob.afirma.integraws.beans.BarcodeTypeEnum.java.</p>
 * <b>Description:</b><p> Enum that contains Barcode types.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

/** 
 * <p>Enum that contains Barcode types.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public enum BarcodeTypeEnum {

    /**
     * Attribute that represents identifiers of barcode types.
     */
    CODABAR("Codabar"), CODE128("Code128"), CODE39("Code39"), DATAMATRIX("DataMatrix"), EAN128("EAN128"), PDF417("pdf417"), QRCODE("QRCode");

    /**
     * Attribute that represents the type of the barcode.
     */
    private final String type;

    /**
     * Constructor method for the class BarcodeTypeEnum.java.
     * @param typeParam Parameter that represents the type of the barcode.
     */
    private BarcodeTypeEnum(String typeParam) {
	this.type = typeParam;
    }

    /**
     * Gets the value of the attribute {@link #type}.
     * @return the value of the attribute {@link #type}.
     */
    public String getType() {
	return type;
    }
}
