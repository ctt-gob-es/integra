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
 * <b>File:</b><p>es.gob.signaturereport.barcode.BarcodeManagerI.java.</p>
 * <b>Description:</b><p> Interface that provides all necessary methods and constants for the management of bar codes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 28/08/2020.
 */
package es.gob.afirma.mreport.barcode;

import java.util.ArrayList;

import es.gob.afirma.mreport.exceptions.BarcodeException;
import es.gob.afirma.mreport.items.Barcode;
//import es.gob.afirma.modes.parameters.Barcode;
import es.gob.afirma.mreport.items.BarcodeImage;


/** 
 * <p>Interface that provides all necessary methods and constants for the management of bar codes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/08/2020.
 */
public interface BarcodeManagerI {
    
    /**
     * Attribute that identifies the type of bar code "Code39". 
     */
    String CODE39 = "Code39";
    /**
     * Attribute that identifies the type of bar code "Code128". 
     */
    String CODE128 = "Code128";
    /**
     * Attribute that identifies the type of bar code "EAN128". 
     */
    String EAN128 = "EAN128";
    /**
     * Attribute that identifies the type of bar code "Codabar". 
     */
    String CODABAR = "Codabar";
    /**
     * Attribute that identifies the type of bar code "PDF417". 
     */
    String PDF417 = "PDF417";
    /**
     * Attribute that identifies the type of bar code "DataMatrix". 
     */
    String DATAMATRIX = "DataMatrix";
    /**
     * Attribute that identifies the type of bar code "QRCode". 
     */
    String QRCODE = "QRCode";
    
    /**
     * Attribute that represents the "HumanReadablePlacement" property key. 
     */
    String H_READABLE_PLACEMENT="HumanReadablePlacement";
    
    /**
     * Attribute that represents the "rotation" property key. 
     */
    String ROTATION = "Rotation";
    
    /**
     * Attribute that represents the human readable placement of bar code is bottom. 
     */
    String HRP_BOTTOM = "BOTTOM";
    
    /**
     * Attribute that represents the human readable placement of bar code is top. 
     */
    String HRP_TOP = "TOP";
    
    /**
     * Attribute that represents the human readable placement of bar code is none. 
     */
    String HRP_NONE = "NONE";
    
    /**
     * Attribute that represents the content type of image used to create the barcode. 
     */
    String CONTENT_TYPE_IMG = "image/png";
    
    /**
     * Attribute that represents the format of image used to create the barcode. 
     */
    String FORMAT_IMG = "png";
    
    /**
     * Attribute that represents the resolution used to create "Code39" barcode. 
     */
    int CODE39_DPI = 96;
    
   
    /**
     * Attribute that represents the module width (inch) used to create "Code39" barcode.
     */
    double CODE39_MOD_WIDTH = 1;
    
    /**
     * Attribute that represents the resolution used to create "Code128" barcode. 
     */
    int CODE128_DPI = 96;
    
   
    /**
     * Attribute that represents the module width (inch) used to create "Code128" barcode.
     */
    double CODE128_MOD_WIDTH = 1;
    
    /**
     * Attribute that represents the resolution used to create "Codabar" barcode. 
     */
    int CODABAR_DPI = 96;
    
   
    /**
     * Attribute that represents the module width (inch) used to create "Codabar" barcode.
     */
    double CODABAR_MOD_WIDTH = 1;
    
    /**
     * Attribute that represents the resolution used to create "EAN128" barcode. 
     */
    int EAN128_DPI = 96;
    
   
    /**
     * Attribute that represents the module width (inch) used to create "EAN128" barcode.
     */
    double EAN128_MOD_WIDTH = 1;
    
    /**
     * Attribute that represents the resolution used to create "PDF417" barcode. 
     */
    int PDF417_DPI = 96;
    
    /**
     * Constant that represents a 96 number. 
     */
    int XCVI = 96;
    
    /**
     * Constant that represents a 76 number. 
     */
    int LXXVI = 76;
   
    /**
     * Attribute that represents the module width (inch) used to create "PDF417" barcode.
     */
    double PDF417_MOD_WIDTH = XCVI/LXXVI;
    
    /**
     * Attribute that represents the resolution used to create "DATAMATRIX" barcode. 
     */
    int DATAMATRIX_DPI = 96;  
   
    /**
     * Attribute that represents the module width (inch) used to create "PDF417" barcode.
     */
    double DATAMATRIX_MOD_WIDTH = XCVI/LXXVI;
    
    /**
     * Attribute that represents the width (pixels) used to create "QR Code" barcode.
     */
    int DEFAULT_QR_CODE_WIDTH = 200;
    /**
     * Attribute that represents the height (pixels) used to create "QR Code" barcode.
     */
    int DEFAULT_QR_CODE_HEIGHT = 200;
    
    /**
     * Attribute that represents the "QRCodeWidth" property key. 
     */
    String QR_CODE_WIDTH="QRCodeWidth";
    /**
     * Attribute that represents the "QRCodeHeight" property key. 
     */
    String QR_CODE_HEIGHT="QRCodeHeight";
    
    /**
     * Method for generating one or multiple barcodes.
     * @param barcodes	List of {@link Barcode} that contain information about a particular bar code type to generate.
     * @param includeURL	If the value is true then the BarcodeImage Objects will include a RFC2397 "data" URL.
     * @param includeContent	If the value is true then the BarcodeImage Objects will include the array of bytes that is associated to image of bar code.
     * @return	List of {@link BarcodeImage} that contain the bar code created.
     * @throws BarcodeException	If an error occurs.
     */
    ArrayList<BarcodeImage> generateBarcode(ArrayList<Barcode> barcodes,boolean includeURL, boolean includeContent) throws BarcodeException;

}
