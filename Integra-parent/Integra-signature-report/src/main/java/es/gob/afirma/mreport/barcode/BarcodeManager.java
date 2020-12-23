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
 * <b>File:</b><p>es.gob.afirma.mreport.barcode.BarcodeManager.java.</p>
 * <b>Description:</b><p> Class for the management of bar codes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 28/08/2020.
 */
package es.gob.afirma.mreport.barcode;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.krysalis.barcode4j.HumanReadablePlacement;
import org.krysalis.barcode4j.impl.AbstractBarcodeBean;
import org.krysalis.barcode4j.impl.codabar.CodabarBean;
import org.krysalis.barcode4j.impl.code128.Code128Bean;
import org.krysalis.barcode4j.impl.code128.EAN128Bean;
import org.krysalis.barcode4j.impl.code39.Code39Bean;
import org.krysalis.barcode4j.impl.datamatrix.DataMatrixBean;
import org.krysalis.barcode4j.impl.pdf417.PDF417Bean;
import org.krysalis.barcode4j.output.bitmap.BitmapCanvasProvider;
import org.krysalis.barcode4j.tools.UnitConv;

import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import es.gob.afirma.mreport.exceptions.BarcodeException;
import es.gob.afirma.mreport.exceptions.UtilsException;
import es.gob.afirma.mreport.i18.ILogConstantKeys;
import es.gob.afirma.mreport.i18.Language;
import es.gob.afirma.mreport.items.Barcode;
import es.gob.afirma.mreport.items.BarcodeImage;
import es.gob.afirma.mreport.utils.ImageUtils;
import es.gob.afirma.mreport.utils.URLUtils;
import es.gob.afirma.mreport.utils.UtilsBase64;

//import es.gob.signaturereport.modes.parameters.Barcode;
//import es.gob.signaturereport.tools.ImageUtils;
//import es.gob.signaturereport.tools.UtilsException;
//import es.gob.signaturereport.tools.URLUtils;
//import es.gob.signaturereport.tools.UtilsBase64;

/**
 * <p>Class for the management of bar codes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/08/2020.
 */
public class BarcodeManager implements BarcodeManagerI {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(BarcodeManager.class);

	/**
	 * Attribute that represents Base64 Tools.
	 */
	private final UtilsBase64 base64Tool = new UtilsBase64();

	/**
	 * Constructor method for the class BarcodeManager.java.
	 */
	public BarcodeManager() {
	}

	/**
	 * {@inheritDoc}
	 * @see es.gob.signaturereport.barcode.BarcodeManagerI#generateBarcode(java.util.ArrayList)
	 */
	public ArrayList<BarcodeImage> generateBarcode(ArrayList<Barcode> barcodes, boolean includeURL, boolean includeContent) throws BarcodeException {
		ArrayList<BarcodeImage> result = new ArrayList<BarcodeImage>();
		if (barcodes != null && !barcodes.isEmpty()) {
			for (int i = 0; i < barcodes.size(); i++) {
				Barcode barcode = barcodes.get(i);
				BarcodeImage bi = null;
				if (barcode.getType().equals(DATAMATRIX) || barcode.getType().equals(PDF417) || barcode.getType().equals(QRCODE)) {
					bi = create2DBarcodes(barcode, includeURL, includeContent);
				} else {
					bi = createLinearBarcodes(barcode, includeURL, includeContent);
				}
				if (bi != null) {
					if (bi.getContent() != null && barcode.getConfiguration()!=null && barcode.getConfiguration().containsKey(ROTATION)) {
						String angle = barcode.getConfiguration().get(ROTATION);
						byte[ ] image = bi.getContent();
						try {
							byte[ ] imageRot = ImageUtils.rotate(image, Double.parseDouble(angle), FORMAT_IMG);
							bi.setContent(imageRot);
						} catch (NumberFormatException e) {
							throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, Language.getFormatResSigReport(ILogConstantKeys.BRCD_007, new Object[ ] { angle }), e);
						} catch (UtilsException e) {
							throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, e.getDescription(), e);
						}
					}
					result.add(bi);
				}
			}
		}
		return result;
	}

	/**
	 * Creates a linear bar codes.
	 * @param barcode	Bar code information.
	 * @param includeURL	Parameter that indicates if the result will include a RFC 2397 URL.
	 * @param includeContent	Parameter that indicates if the result will include the bar codes image content.
	 * @return	A {@link BarcodeImage} class that encapsulates a bar codes.
	 * @throws BarcodeException	If an error occurs.
	 */
	private BarcodeImage createLinearBarcodes(Barcode barcode, boolean includeURL, boolean includeContent) throws BarcodeException {
		AbstractBarcodeBean bean = null;
		int dpi = CODE39_DPI;
		double width = CODE39_MOD_WIDTH;
		if (barcode.getType().equals(CODE39)) {
			bean = new Code39Bean();
			dpi = CODE39_DPI;
			width = CODE39_MOD_WIDTH;
		} else if (barcode.getType().equals(CODE128)) {
			bean = new Code128Bean();
			dpi = CODE128_DPI;
			width = CODE128_MOD_WIDTH;
		} else if (barcode.getType().equals(CODABAR)) {
			bean = new CodabarBean();
			dpi = CODABAR_DPI;
			width = CODABAR_MOD_WIDTH;
		} else if (barcode.getType().equals(EAN128)) {
			bean = new EAN128Bean();
			dpi = EAN128_DPI;
			width = EAN128_MOD_WIDTH;
		} else {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_003, new Object[ ] { barcode.getType() });
			LOGGER.error(msg);
			throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, msg);
		}
		ByteArrayOutputStream out = null;
		try {
			BarcodeImage barImg = new BarcodeImage(barcode.getType(), barcode.getMessage());
			barImg.setContentType(CONTENT_TYPE_IMG);
			bean.setModuleWidth(UnitConv.in2mm((width / dpi)));
			out = new ByteArrayOutputStream();
			BitmapCanvasProvider canvas = new BitmapCanvasProvider(out, CONTENT_TYPE_IMG, dpi, BufferedImage.TYPE_BYTE_BINARY, false, 0);
			if (barcode.getConfiguration() != null && barcode.getConfiguration().containsKey(H_READABLE_PLACEMENT)) {
				String hrp = barcode.getConfiguration().get(H_READABLE_PLACEMENT);
				if (hrp.equals(HRP_BOTTOM)) {
					bean.setMsgPosition(HumanReadablePlacement.HRP_BOTTOM);
				} else if (hrp.equals(HRP_TOP)) {
					bean.setMsgPosition(HumanReadablePlacement.HRP_TOP);
				} else if (hrp.equals(HRP_NONE)) {
					bean.setMsgPosition(HumanReadablePlacement.HRP_NONE);
				}
			}
			bean.generateBarcode(canvas, barcode.getMessage());
			canvas.finish();
			byte[ ] barContent = out.toByteArray();
			if (barContent != null && barcode.getConfiguration()!=null && barcode.getConfiguration().containsKey(ROTATION)) {
				String angle = barcode.getConfiguration().get(ROTATION);
				try {
					barContent = ImageUtils.rotate(barContent, Double.parseDouble(angle), FORMAT_IMG);
				} catch (NumberFormatException e) {
					throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, Language.getFormatResSigReport(ILogConstantKeys.BRCD_007, new Object[ ] { angle }), e);
				} catch (UtilsException e) {
					throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, e.getDescription(), e);
				}
			}

			if (includeURL) {
				String barEncoded = base64Tool.encodeBytes(barContent);
				String url = URLUtils.createRFC2397URL(CONTENT_TYPE_IMG, barEncoded);
				barImg.setLocation(url);
			}
			if (includeContent) {
				barImg.setContent(barContent);
			}
			return barImg;
		} catch (Exception e) {
			if (e instanceof IllegalArgumentException) {
				LOGGER.error(e.getMessage());
				throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, Language.getFormatResSigReport(ILogConstantKeys.BRCD_006, new Object[ ] { barcode.getMessage(), barcode.getType() }), e);
			} else {
				String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_001, new Object[ ] { barcode.getType() });
				LOGGER.error(msg, e);
				throw new BarcodeException(BarcodeException.UNKNOWN_ERROR, msg, e);
			}

		} finally {
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
					String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_002, new Object[ ] { barcode.getType() });
					LOGGER.error(msg, e);
					throw new BarcodeException(BarcodeException.UNKNOWN_ERROR, msg, e);
				}
			}
		}
	}

	/**
	 * Creates a 2D bar codes.
	 * @param barcode	Bar code information.
	 * @param includeURL	Parameter that indicates if the result will include a RFC 2397 URL.
	 * @param includeContent	Parameter that indicates if the result will include the bar codes image content.
	 * @return	A {@link BarcodeImage} class that encapsulates a bar codes.
	 * @throws BarcodeException	If an error occurs.
	 */
	private BarcodeImage create2DBarcodes(Barcode barcode, boolean includeURL, boolean includeContent) throws BarcodeException {
		AbstractBarcodeBean bean = null;
		int dpi = CODE39_DPI;
		double width = CODE39_MOD_WIDTH;
		if (barcode.getType().equals(PDF417)) {
			bean = new PDF417Bean();
			dpi = PDF417_DPI;
			width = PDF417_MOD_WIDTH;
		} else if (barcode.getType().equals(DATAMATRIX)) {
			bean = new DataMatrixBean();
			dpi = DATAMATRIX_DPI;
			width = DATAMATRIX_MOD_WIDTH;
		} else if (barcode.getType().equals(QRCODE)) {
			return createQRCode(barcode, includeURL, includeContent);
		} else {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_004, new Object[ ] { barcode.getType() });
			LOGGER.error(msg);
			throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, msg);
		}
		ByteArrayOutputStream out = null;
		try {
			BarcodeImage barImg = new BarcodeImage(barcode.getType(), barcode.getMessage());
			barImg.setContentType(CONTENT_TYPE_IMG);
			bean.setModuleWidth(UnitConv.in2mm((width / dpi)));
			out = new ByteArrayOutputStream();
			barImg.setContentType(CONTENT_TYPE_IMG);
			BitmapCanvasProvider canvas = new BitmapCanvasProvider(out, CONTENT_TYPE_IMG, dpi, BufferedImage.TYPE_BYTE_BINARY, false, 0);
			bean.generateBarcode(canvas, barcode.getMessage());
			canvas.finish();
			byte[ ] barContent = out.toByteArray();
			if (barContent != null && barcode.getConfiguration()!=null && barcode.getConfiguration().containsKey(ROTATION)) {
				String angle = barcode.getConfiguration().get(ROTATION);
				try {
					barContent = ImageUtils.rotate(barContent, Double.parseDouble(angle), FORMAT_IMG);
				} catch (NumberFormatException e) {
					throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, Language.getFormatResSigReport(ILogConstantKeys.BRCD_007, new Object[ ] { angle }), e);
				} catch (UtilsException e) {
					throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, e.getDescription(), e);
				}
			}
			if (includeURL) {
				String barEncoded = base64Tool.encodeBytes(barContent);
				String url = URLUtils.createRFC2397URL(CONTENT_TYPE_IMG, barEncoded);
				barImg.setLocation(url);
			}
			if (includeContent) {
				barImg.setContent(barContent);
			}
			return barImg;
		} catch (Exception e) {
			if (e instanceof IllegalArgumentException) {
				LOGGER.error(e.getMessage());
				throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, Language.getFormatResSigReport(ILogConstantKeys.BRCD_006, new Object[ ] { barcode.getMessage(), barcode.getType() }), e);
			} else {
				String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_001, new Object[ ] { barcode.getType() });
				LOGGER.error(msg, e);
				throw new BarcodeException(BarcodeException.UNKNOWN_ERROR, msg, e);
			}
		} finally {
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
					String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_002, new Object[ ] { barcode.getType() });
					LOGGER.error(msg, e);
					throw new BarcodeException(BarcodeException.UNKNOWN_ERROR, msg, e);
				}
			}
		}
	}

	/**
	 * Creates a QR codes.
	 * @param barcode	Bar code information.
	 * @param includeURL	Parameter that indicates if the result will include a RFC 2397 URL.
	 * @param includeContent	Parameter that indicates if the result will include the bar codes image content.
	 * @return	A {@link BarcodeImage} class that encapsulates a bar codes.
	 * @throws BarcodeException	If an error occurs.
	 */
	private BarcodeImage createQRCode(Barcode barcode, boolean includeURL, boolean includeContent) throws BarcodeException {
		QRCodeWriter writer = new QRCodeWriter();
		int width = DEFAULT_QR_CODE_WIDTH;
		int height = DEFAULT_QR_CODE_HEIGHT;
		if (barcode.getConfiguration() != null) {
			if (barcode.getConfiguration().containsKey(QR_CODE_WIDTH)) {
				String qrWidth = barcode.getConfiguration().get(QR_CODE_WIDTH);
				try {
					width = Integer.parseInt(qrWidth);
				} catch (NumberFormatException nfe) {
					String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_005, new Object[ ] { qrWidth, QR_CODE_WIDTH });
					LOGGER.error(msg);
					throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, msg, nfe);
				}
			}
			if (barcode.getConfiguration().containsKey(QR_CODE_HEIGHT)) {
				String qrHeight = barcode.getConfiguration().get(QR_CODE_HEIGHT);
				try {
					height = Integer.parseInt(qrHeight);
				} catch (NumberFormatException nfe) {
					String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_005, new Object[ ] { qrHeight, QR_CODE_HEIGHT });
					LOGGER.error(msg);
					throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, msg, nfe);
				}
			}
		}

		ByteArrayOutputStream out = null;
		try {
			BarcodeImage barImg = new BarcodeImage(barcode.getType(), barcode.getMessage());
			barImg.setContentType(CONTENT_TYPE_IMG);
			BitMatrix matrix = writer.encode(barcode.getMessage(), com.google.zxing.BarcodeFormat.QR_CODE, width, height);
			out = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(matrix, FORMAT_IMG, out);
			byte[ ] barContent = out.toByteArray();
			if (barContent != null && barcode.getConfiguration()!=null && barcode.getConfiguration().containsKey(ROTATION)) {
				String angle = barcode.getConfiguration().get(ROTATION);
				try {
					barContent = ImageUtils.rotate(barContent, Double.parseDouble(angle), FORMAT_IMG);
				} catch (NumberFormatException e) {
					throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, Language.getFormatResSigReport(ILogConstantKeys.BRCD_007, new Object[ ] { angle }), e);
				} catch (UtilsException e) {
					throw new BarcodeException(BarcodeException.INVALID_INPUT_PARAMETERS, e.getDescription(), e);
				}
			}
			if (includeURL) {
				String barEncoded = base64Tool.encodeBytes(barContent);
				String url = URLUtils.createRFC2397URL(CONTENT_TYPE_IMG, barEncoded);
				barImg.setLocation(url);
			}
			if (includeContent) {
				barImg.setContent(barContent);
			}
			return barImg;
		} catch (WriterException we) {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_001, new Object[ ] { barcode.getType() });
			LOGGER.error(msg, we);
			throw new BarcodeException(BarcodeException.UNKNOWN_ERROR, msg, we);
		} catch (IOException e) {
			String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_001, new Object[ ] { barcode.getType() });
			LOGGER.error(msg, e);
			throw new BarcodeException(BarcodeException.UNKNOWN_ERROR, msg, e);
		} finally {
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
					String msg = Language.getFormatResSigReport(ILogConstantKeys.BRCD_002, new Object[ ] { barcode.getType() });
					LOGGER.error(msg, e);
					throw new BarcodeException(BarcodeException.UNKNOWN_ERROR, msg, e);
				}
			}
		}

	}
}
