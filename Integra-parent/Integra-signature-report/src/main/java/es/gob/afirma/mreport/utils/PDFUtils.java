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
 * <b>File:</b><p>es.gob.signaturereport.tools.PDFUtils.java.</p>
 * <b>Description:</b><p> Class that contains tools to manage of PDF files.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.mreport.utils;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import es.gob.afirma.mreport.logger.Logger;
import org.krysalis.barcode4j.tools.UnitConv;

import com.lowagie.text.Document;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.PdfCopy;
import com.lowagie.text.pdf.PdfImportedPage;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfWriter;

import es.gob.afirma.mreport.exceptions.SignatureReportException;
import es.gob.afirma.mreport.exceptions.UtilsException;
import es.gob.afirma.mreport.i18.ILogConstantKeys;
import es.gob.afirma.mreport.i18.Language;
import es.gob.afirma.mreport.items.FileAttachment;
import es.gob.afirma.mreport.items.MatrixPagesInclude;
import es.gob.afirma.mreport.items.PageIncludeFormat;

/**
 * <p>Class that contains tools to manage of PDF files.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 19/08/2020.
 */
public final class PDFUtils {

	/**
	 * Attribute that represents the object that manages the log of the class.
	 */
	private static final Logger LOGGER = Logger.getLogger(PDFUtils.class);
	
	/**
	 * Attribute that represents the default resolution (dpi) used to create PDF file.
	 */
	private static final int RESOLUTION_DEFAULT = 72;

	/**
	 * Attribute that represents the 3 number. 
	 */
	private static final int III = 3;	

	/**
	 * Attribute that represents the 90 number. 
	 */
	private static final float XC = 90;
	
	/**
	 * Attribute that represents the 270 number. 
	 */
	private static final float CCLXX = 270;
	
	/**
	 * Attribute that represents the 180 number. 
	 */
	private static final float CLXXX = 180;
	
	/**
	 * Constructor method for the class PDFUtils.java.
	 */
	private PDFUtils() {
	}

	/**
	 * Adds the supplied attachment list to supplied PDF.
	 * @param pdf	PDF file.
	 * @param attachments	 Attachment files.
	 * @return	Modified file.
	 * @throws SignatureReportException	if an error occurs.
	 */
	public static byte[ ] addAttachment(byte[ ] pdf, ArrayList<FileAttachment> attachments) throws SignatureReportException {
		byte[ ] doc = null;
	
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			PdfReader readerPdf = new PdfReader(pdf);
			
			PdfStamper stamper = new PdfStamper(readerPdf, out);
			for (int i = 0; i < attachments.size(); i++) {
				FileAttachment attachment = attachments.get(i);
				stamper.addFileAttachment(attachment.getDescription(), attachment.getContent(), null, attachment.getName());
			}
			stamper.close();
			doc = out.toByteArray();
		} catch (Exception e) {
			
			LOGGER.error("Error al agregar los adjuntos al informe de firma", e);
			throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, "Error al agregar los adjuntos al informe de firma", e);

		} 
		return doc;
	}

	/**
	 * Concatenates the supplied PDF files.
	 * @param pdf1	PDF file.
	 * @param pdf2	PDF file.
	 * @param identifier1	Token used to identifies the first input document.
	 * @param identifier2	Token used to identifies the second input document.
	 * @param rule	Concatenation rule.Ej: $identifier1(1)+ $identifier2(4-6). Concat the page 1 of the first document with the pages 4 to 6 of the second document. 
	 * @return	Concatenated PDF file.
	 * @throws UtilsException	If an error occurs.
	 */
	public static byte[ ] concatPDF(byte[ ] pdf1, byte[ ] pdf2, String identifier1, String identifier2, String rule) throws UtilsException {
		String[ ] p = rule.split("\\+");
		byte[ ] pdf = null;
		
		try (ByteArrayOutputStream out = new ByteArrayOutputStream();) {
			PdfReader readerPdf1 = new PdfReader(pdf1);
			PdfReader readerPdf2 = new PdfReader(pdf2);
			com.lowagie.text.Rectangle psize = readerPdf1.getPageSize(1);
			Document document = new Document(new com.lowagie.text.Rectangle(psize.getWidth(), psize.getHeight()));
			
			PdfCopy copy = new PdfCopy(document, out);
			document.open();
			for (int i = 0; i < p.length; i++) {
				String docId = null;
				int iniPage = -1;
				int endPage = -1;
				p[i] = p[i].trim();
				int pos = p[i].indexOf('(');
				if (pos > 0) {
					docId = p[i].substring(0, pos);
					String intval = p[i].substring(pos + 1, p[i].length() - 1).trim();
					String[ ] intvalSp = intval.split("-");
					iniPage = Integer.parseInt(intvalSp[0].trim());
					if (intvalSp.length == 2) {
						endPage = Integer.parseInt(intvalSp[1].trim());
					} else {
						// Una unica pagina
						endPage = iniPage;
					}
				} else {
					docId = p[i];
				}
				if (docId != null) {
					if (docId.equals(identifier1)) {
						if (iniPage < 0) {
							// Todo el documento
							iniPage = 1;
							endPage = readerPdf1.getNumberOfPages();
						} else if (iniPage <= readerPdf1.getNumberOfPages()) {
							if (endPage == -1) {
								// El documento hasta el final
								endPage = readerPdf1.getNumberOfPages();
							} else if (endPage > readerPdf1.getNumberOfPages()) {
								String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_019, new Object[ ] { String.valueOf(endPage), docId });
								LOGGER.error(msg);
								throw new UtilsException(UtilsException.INVALID_CONCATENATION_RULE, msg);
							}
						} else {
							String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_019, new Object[ ] { String.valueOf(iniPage), docId });
							LOGGER.error(msg);
							throw new UtilsException(UtilsException.INVALID_CONCATENATION_RULE, msg);

						}
						while (iniPage <= endPage) {
							copy.addPage(copy.getImportedPage(readerPdf1, iniPage));
							iniPage++;
						}
						copy.freeReader(readerPdf1);
					} else if (docId.equals(identifier2)) {
						if (iniPage < 0) {
							// Todo el documento
							iniPage = 1;
							endPage = readerPdf2.getNumberOfPages();
						} else if (iniPage <= readerPdf2.getNumberOfPages()) {
							if (endPage == -1) {
								// El documento hasta el final
								endPage = readerPdf2.getNumberOfPages();
							} else if (endPage > readerPdf2.getNumberOfPages()) {
								String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_019, new Object[ ] { String.valueOf(endPage), docId });
								LOGGER.error(msg);
								throw new UtilsException(UtilsException.INVALID_CONCATENATION_RULE, msg);
							}
						} else {
							String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_019, new Object[ ] { String.valueOf(iniPage), docId });
							LOGGER.error(msg);
							throw new UtilsException(UtilsException.INVALID_CONCATENATION_RULE, msg);

						}
						while (iniPage <= endPage) {
							copy.addPage(copy.getImportedPage(readerPdf2, iniPage));
							iniPage++;
						}
						copy.freeReader(readerPdf2);
					} else {
						String msg = Language.getFormatResSigReport(ILogConstantKeys.UTIL_018, new Object[ ] { docId });
						LOGGER.error(msg);
						throw new UtilsException(UtilsException.INVALID_CONCATENATION_RULE, msg);
					}
				} else {
					String msg = Language.getResSigReport(ILogConstantKeys.UTIL_017);
					LOGGER.error(msg);
					throw new UtilsException(UtilsException.INVALID_CONCATENATION_RULE, msg);
				}
			}
			document.close();
			pdf = out.toByteArray();
		} catch (NumberFormatException nfe) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_015);
			LOGGER.error(msg, nfe);
			throw new UtilsException(UtilsException.INVALID_CONCATENATION_RULE, msg, nfe);
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_016);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.UNKNOWN_ERROR, msg, e);
		} 
		return pdf;
	}

	/**
	 * Checks if the supplied document is a PDF document. 
	 * @param file	Document to check.
	 * @return	True if the document is a PDF file. Otherwise false
	 */
	public static boolean isPDFFile(byte[ ] file) {
		boolean pdf = false;
		if (file != null) {
			int i = 0;
			boolean end = false;
			while (i < file.length && !end) {
				if (file[i] != ' ' && file[i] != '\n' && file[i] != '\t' && file[i] != '\r') {
					end = true;
					pdf = i + III < file.length && file[i] == '%' && file[i + 1] == 'P' && file[i + 2] == 'D' && file[i + III] == 'F';
				}
				i++;
			}
		}
		return pdf;
	}

	/**
	 * Method that creates a PDF file by including a document in another with the specified rules.
	 * @param targetPdf	Target document.
	 * @param originPdf	Original document.
	 * @param pagesIncl	Rules.
	 * @return	A PDF document.
	 * @throws UtilsException	If an error occurs.
	 */
	public static byte[ ] includePages(byte[ ] targetPdf, byte[ ] originPdf, MatrixPagesInclude pagesIncl) throws UtilsException {
		byte[ ] pdf = null;
		
		try (ByteArrayOutputStream out = new ByteArrayOutputStream();) {
			
			PdfReader readerTarget = new PdfReader(targetPdf);
			PdfReader readerOrigin = new PdfReader(originPdf);
			Document document = new Document();
			
			PdfWriter writer = PdfWriter.getInstance(document, out);
			document.open();
			PdfContentByte directContent = writer.getDirectContent();
			PdfContentByte under = writer.getDirectContentUnder();
			for (int i = 1; i <= readerTarget.getNumberOfPages(); i++) {
				com.lowagie.text.Rectangle rectangle = readerTarget.getPageSize(i);
				document.setPageSize(rectangle);
				document.newPage();
				PdfImportedPage pageTarget = writer.getImportedPage(readerTarget, i);

				directContent.addTemplate(pageTarget, 0, 0);
				int[ ] originPages = pagesIncl.getPageToInclude(i);
				if (originPages != null) {
					for (int j = 0; j < originPages.length; j++) {
						PageIncludeFormat[ ] format = pagesIncl.getPagesFormat(i, originPages[j]);
						PdfImportedPage pageOrigen = writer.getImportedPage(readerOrigin, (originPages[j]));
						float rotate = 0;
						if(readerOrigin.getPageN((originPages[j])).getAsNumber(PdfName.ROTATE)!=null){
							rotate = readerOrigin.getPageN((originPages[j])).getAsNumber(PdfName.ROTATE).floatValue();
						}
						for (int k = 0; k < format.length; k++) {
							float a = 0;
							float b = 0;
							float c = 0;
							float d = 0;
							float e = 0;
							float f = 0;
							float width = 0;
							if (format[k].getWidth() > 0) {
								width = UnitConv.mm2px(format[k].getWidth(), RESOLUTION_DEFAULT);
							}
							float height = 0;
							if (format[k].getHeight() > 0) {
								height = UnitConv.mm2px(format[k].getHeight(), RESOLUTION_DEFAULT);
							}
							float xpos = UnitConv.mm2px(format[k].getXpos(), RESOLUTION_DEFAULT);
							float ypos = UnitConv.mm2px(format[k].getYpos(), RESOLUTION_DEFAULT);
							float xFactor = 1;
							if (width > 0) {
								xFactor = width / pageOrigen.getWidth();
							}

							float yFactor = 1;
							if (height > 0) {
								yFactor = height / pageOrigen.getHeight();
							}
							if(rotate == 0){
								a = xFactor;
								b = 0;
								c = 0;
								d = yFactor;
								e = xpos;
								f = ypos;
							}else if(rotate == XC){
								xFactor = width/pageOrigen.getHeight();
								yFactor = height/pageOrigen.getWidth();
								a = 0;
								b = -yFactor;
								c = xFactor;
								d=0;
								e=xpos;
								f=ypos+height;
							}else if(rotate == CCLXX){
								xFactor = width/pageOrigen.getHeight();
								yFactor = height/pageOrigen.getWidth();
								a = 0;
								b = yFactor;
								c = -xFactor;
								d=0;
								e=xpos+width;
								f=ypos;
							}else{
								float angle = (float) (-rotate * (Math.PI / CLXXX));
								float  rotWidth = (float) ( (pageOrigen.getHeight() * Math.sin(angle)) + (pageOrigen.getWidth() * Math.cos(angle))) ;
								xFactor = (float) (width / rotWidth);
								float  rotHeight = (float) ( (pageOrigen.getWidth() * Math.sin(angle)) + (pageOrigen.getHeight() * Math.cos(angle)) );
								yFactor = height / rotHeight;
								a = (float) (xFactor * Math.cos(angle));
								b = (float) (yFactor * Math.sin(angle));
								c = (float) (xFactor * - Math.sin(angle));
								d = (float) (yFactor * Math.cos(angle));
								e = (float) (xpos + (width * Math.sin(angle)));
								f = (float) (ypos + (height * Math.cos(angle)));
							}	
							if (format[k].getLayout().equals(PageIncludeFormat.BACK_LAYOUT)) {
								under.addTemplate(pageOrigen, a,b,c,d,e,f);
							} else {	
								directContent.addTemplate(pageOrigen, a,b,c,d,e,f);
							}

						}
					}
				}
			}
			document.close();
			readerOrigin.close();
			readerTarget.close();
			pdf = out.toByteArray();
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_014);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.UNKNOWN_ERROR, msg, e);
		} 
		return pdf;

	}

	/**
	 * Gets the page number of a PDF document.
	 * @param document	PDF document.
	 * @return	Page number.
	 * @throws UtilsException	If an error occurs.
	 */
	public static int getNumPages(byte[ ] document) throws UtilsException {
		try {
			PdfReader reader = new PdfReader(document);

			return reader.getNumberOfPages();
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_009);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.INVALID_PDF_FILE, msg, e);
		}
	}
	
	/**
	 * Gets a List of String that represents the orientation of each page.
	 * @param document	PDF document.
	 * @return a List of String that represents the orientation of each page.
	 * @throws UtilsException If an error occurs.
	 */
	public static List<String> getPagesOrientation(byte[ ] document) throws UtilsException {
		
		List<String> pages = new ArrayList<String>();
		try {
		
    		PdfReader reader = new PdfReader(document);
    		
    		int numPages = reader.getNumberOfPages();
    		
    		for (int i = 1; i <= numPages; i++) {
    			com.lowagie.text.Rectangle page = reader.getPageSize(i);
    			if (page.getWidth() > page.getHeight()) {
    				pages.add("H");
    			} else {
    				pages.add("V");
    			}
    		}
		
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_009);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.INVALID_PDF_FILE, msg, e);
		}

		return pages;
		
	}

	/**
	 * Methods that concatenates the supplied PDF files to a PDF file.
	 * @param files	List of PDF files.
	 * @return	Concatenated PDF file.
	 * @throws UtilsException	If an error occurs.
	 */
	public static byte[ ] concatPDFs(List<byte[ ]> files) throws UtilsException {
		Document pdfDoc = new Document(com.lowagie.text.PageSize.A4);
		
		try (ByteArrayOutputStream out = new ByteArrayOutputStream();) {
			PdfCopy copy = new PdfCopy(pdfDoc, out);
			pdfDoc.open();
			for (int i = 0; i < files.size(); i++) {
				PdfReader reader = new PdfReader(files.get(i));
				int numPages = reader.getNumberOfPages();
				for (int j = 1; j <= numPages; j++) {
					copy.addPage(copy.getImportedPage(reader, j));
				}
				copy.freeReader(reader);
			}
			pdfDoc.close();
			return out.toByteArray();
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_016);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.UNKNOWN_ERROR, msg, e);
		}
	}

	/**
	 * Method that converts a image file to PDF file.
	 * @param image	Image file.
	 * @return	PDF file.
	 * @throws UtilsException If an error occurs.
	 */
	public static byte[ ] imageToPDF(byte[ ] image) throws UtilsException {
		Document pdfDoc = new Document(com.lowagie.text.PageSize.A4);
		
		try (ByteArrayOutputStream out = new ByteArrayOutputStream();) {
			PdfWriter.getInstance(pdfDoc, out);
			pdfDoc.open();
			com.lowagie.text.Image img = com.lowagie.text.Image.getInstance(image);
			pdfDoc.add(img);
			pdfDoc.close();
			return out.toByteArray();
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.UTIL_047);
			LOGGER.error(msg, e);
			throw new UtilsException(UtilsException.UNKNOWN_ERROR, msg, e);
		} 
	}

}
