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
 * <b>File:</b><p>es.gob.signaturereport.tools.ImageUtils.java.</p>
 * <b>Description:</b><p>Utility class for processing images.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/08/2020.</p>
 * @author Spanish Government.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.mreport.utils;

import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.awt.image.AffineTransformOp;
import java.awt.image.BufferedImage;
import java.awt.image.BufferedImageOp;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

import es.gob.afirma.mreport.logger.Logger;

import es.gob.afirma.mreport.exceptions.UtilsException;
import es.gob.afirma.mreport.i18.ILogConstantKeys;
import es.gob.afirma.mreport.i18.Language;


/** 
 * <p>Utility class for processing images.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public final class ImageUtils {
	
	/**
	 * Attribute that represents the three quarters of rotation. 
	 */
	private static final int THREE_QUARTERS_ROTATION = 270;
	
	/**
	 * Attribute that represents the half rotation. 
	 */
	private static final int HALF_ROTATION = 180;
	
	/**
	 * Attribute that represents a quarter of rotation. 
	 */
	private static final int QUARTER_ROTATION = 90;
	
	
	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(ImageUtils.class);	
	
	/**
	 * Method to rotate an image 90,180 or 270 degrees.
	 * @param image	Image that will be rotate.
	 * @param angle	Rotated angle. The allowed values are 90, 180 or 270.
	 * @param imageFormat Format of image.
	 * @return	Rotated image.
	 * @throws UtilsException if the method fails.
	 */
	public static byte[] rotate(byte[] image, double angle, String imageFormat) throws UtilsException{
		if(angle==QUARTER_ROTATION || angle==HALF_ROTATION || angle == THREE_QUARTERS_ROTATION){
			
			
			try (InputStream in = new ByteArrayInputStream(image);
					ByteArrayOutputStream  out = new ByteArrayOutputStream();) {
				
				BufferedImage buffImage = ImageIO.read(in);
				AffineTransform rotateTransform = AffineTransform.getRotateInstance(Math.toRadians(angle),buffImage.getWidth() / 2.0, buffImage.getHeight() / 2.0);
				if(angle==QUARTER_ROTATION || angle == THREE_QUARTERS_ROTATION){
					AffineTransform at = AffineTransform.getRotateInstance(Math.toRadians(QUARTER_ROTATION),buffImage.getWidth() / 2.0, buffImage.getHeight() / 2.0);
					Point2D p2din, p2dout;

				    p2din = new Point2D.Double(0.0, 0.0);
				    p2dout = at.transform(p2din, null);
				    double ytrans = p2dout.getY();

				    p2din = new Point2D.Double(0, buffImage.getHeight());
				    p2dout = at.transform(p2din, null);
				    double xtrans = p2dout.getX();

				    AffineTransform tat = new AffineTransform();
				    tat.translate(-xtrans, -ytrans);
				    rotateTransform.preConcatenate(tat);
				}
				BufferedImageOp bio = new AffineTransformOp(rotateTransform, AffineTransformOp.TYPE_BILINEAR);
			    BufferedImage destinationBI = bio.filter(buffImage, null);
			    ImageIO.write(destinationBI, imageFormat, out);
			    return out.toByteArray();
			} catch (IOException e) {
				String msg = Language.getResSigReport(ILogConstantKeys.UTIL_036);
				LOGGER.error(msg,e);
				throw new UtilsException(UtilsException.UNKNOWN_ERROR, msg,e);
			}
		}else{
			throw new UtilsException(UtilsException.INVALID_ROTATED_ANGLE, Language.getFormatResSigReport(ILogConstantKeys.UTIL_035, new Object[]{angle}));
		}
	}
	
		
}
