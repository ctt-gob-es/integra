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
 * <b>File:</b><p>es.gob.afirma.mreport.pdf.PdfReportManager.java.</p>
 * <b>Description:</b><p>Class for managing PDF reports.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>18/08/2020.</p>
 * @author Gobierno de España.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.mreport.pdf;

import java.io.UnsupportedEncodingException;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.commons.text.StringEscapeUtils;
import es.gob.afirma.mreport.logger.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.mreport.IReportManager;
import es.gob.afirma.mreport.ITemplateConfiguration;
import es.gob.afirma.mreport.barcode.BarcodeManager;
import es.gob.afirma.mreport.exceptions.BarcodeException;
import es.gob.afirma.mreport.exceptions.SignatureReportException;
import es.gob.afirma.mreport.exceptions.UtilsException;
import es.gob.afirma.mreport.i18.ILogConstantKeys;
import es.gob.afirma.mreport.i18.Language;
import es.gob.afirma.mreport.items.Barcode;
import es.gob.afirma.mreport.items.BarcodeImage;
import es.gob.afirma.mreport.items.DocInclusionData;
import es.gob.afirma.mreport.items.FileAttachment;
import es.gob.afirma.mreport.items.IndividualSignature;
import es.gob.afirma.mreport.items.MatrixPagesInclude;
import es.gob.afirma.mreport.items.PageDocumentImage;
import es.gob.afirma.mreport.items.PageIncludeFormat;
import es.gob.afirma.mreport.items.ValidationData;
import es.gob.afirma.mreport.utils.FOUtils;
import es.gob.afirma.mreport.utils.FileUtils;
import es.gob.afirma.mreport.utils.PDFUtils;
import es.gob.afirma.mreport.utils.UtilsTime;
import es.gob.afirma.mreport.utils.XMLUtils;

/**
 * <p>Class for managing PDF reports.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 18/04/2022.
 */
public class PdfReportManager implements IReportManager {
	
	/**
	 * Attribute that represents the processing instruction.
	 */
	private static final String PROC_INSTRUCTION = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
	
	/**
	 * Attribute that represents the namespaces used in the XML message.
	 */
	private static final String NS = "urn:es:gob:signaturereport:generation:inputparameters";

	/**
	 * Attribute that represents the local name that identifies
	 * 'GenerationReport' element.
	 */
	private static final String GENERATIONREPORT = "GenerationReport";

	/**
	 * Attribute that represents the local name that identifies
	 * 'ValidationResult' element.
	 */
	private static final String VALIDATIONRESULT = "ValidationResult";

	/**
	 * Attribute that represents the local name that identifies 'Result'
	 * element.
	 */
	private static final String RESULT = "Result";

	/**
	 * Attribute that represents the local name that identifies 'Major' element.
	 */
	private static final String MAJOR = "Major";

	/**
	 * Attribute that represents the local name that identifies 'Minor' element.
	 */
	private static final String MINOR = "Minor";

	/**
	 * Attribute that represents the local name that identifies 'Message'
	 * element.
	 */
	private static final String MESSAGE = "Message";

	/**
	 * Attribute that represents the local name that identifies
	 * 'IndividualSignature' element.
	 */
	private static final String INDIVIDUALSIGNATURE = "IndividualSignature";

	/**
	 * Attribute that represents the local name that identifies 'TimeStamp'
	 * element.
	 */
	private static final String TIMESTAMP = "TimeStamp";
	/**
	 * Attribute that represents the local name that identifies
	 * 'CertificateInfo' element.
	 */
	private static final String CERTIFICATEINFO = "CertificateInfo";

	/**
	 * Attribute that represents the local name that identifies 'Field' element.
	 */
	private static final String FIELD = "Field";

	/**
	 * Attribute that represents the local name that identifies 'FieldId'
	 * element.
	 */
	private static final String FIELDID = "FieldId";

	/**
	 * Attribute that represents the local name that identifies 'FieldValue'
	 * element.
	 */
	private static final String FIELDVALUE = "FieldValue";

	/**
	 * Attribute that represents the local name that identifies
	 * 'ExternalParameters' element.
	 */
	private static final String EXTERNALPARAMETERS = "ExternalParameters";

	/**
	 * Attribute that represents the local name that identifies 'Parameter'
	 * element.
	 */
	private static final String PARAMETER = "Parameter";

	/**
	 * Attribute that represents the local name that identifies 'ParameterId'
	 * element.
	 */
	private static final String PARAMETERID = "ParameterId";

	/**
	 * Attribute that represents the local name that identifies 'ParameterValue'
	 * element.
	 */
	private static final String PARAMETERVALUE = "ParameterValue";

	/**
	 * Attribute that represents the local name that identifies 'DocumentInfo'
	 * element.
	 */
	private static final String DOCUMENTINFO = "DocumentInfo";

	/**
	 * Attribute that represents the local name that identifies 'NumPages'
	 * element.
	 */
	private static final String NUMPAGES = "NumPages";

	/**
	 * Attribute that represents the local name that identifies
	 * 'PagesOrientation' element.
	 */
	private static final String PAGESORIENTATION = "PagesOrientation";

	/**
	 * Attribute that represents the local name that identifies 'PageInfo'
	 * element.
	 */
	private static final String PAGEINFO = "PageInfo";

	/**
	 * Attribute that represents the local name that identifies 'PagesList'
	 * element.
	 */
	private static final String PAGESLIST = "PagesList";

	/**
	 * Attribute that represents the local name that identifies 'Page' element.
	 */
	private static final String PAGE = "Page";

	/**
	 * Attribute that represents the local name that identifies 'Number'
	 * element.
	 */
	private static final String NUMBER = "Number";

	/**
	 * Attribute that represents the local name that identifies 'URL' element.
	 */
	private static final String URL = "URL";

	/**
	 * Attribute that represents the local name that identifies 'Barcodes'
	 * element.
	 */
	private static final String BARCODES = "Barcodes";

	/**
	 * Attribute that represents the local name that identifies 'Barcode'
	 * element.
	 */
	private static final String BARCODE = "Barcode";

	/**
	 * Attribute that represents the local name that identifies 'Code' element.
	 */
	private static final String CODE = "Code";

	/**
	 * Attribute that represents the local name that identifies 'Type' element.
	 */
	private static final String TYPE = "Type";
	/**
	 * Attribute that represents the local name that identifies 'IncludePage'
	 * element.
	 */
	private static final String INCLUDEPAGE = "IncludePage";

	/**
	 * Attribute that represents the local name that identifies 'Ypos'
	 * attribute.
	 */
	private static final String YPOS = "Ypos";

	/**
	 * Attribute that represents the local name that identifies ' Xpos'
	 * attribute.
	 */
	private static final String XPOS = "Xpos";

	/**
	 * Attribute that represents the local name that identifies 'Width'
	 * attribute.
	 */
	private static final String WIDTH = "Width";

	/**
	 * Attribute that represents the local name that identifies 'Height'
	 * attribute.
	 */
	private static final String HEIGHT = "Height";

	/**
	 * Attribute that represents the local name that identifies 'Layout'
	 * attribute.
	 */
	private static final String LAYOUT = "Layout";

	/**
	 * Attribute that represents the local name that identifies 'DocumentPage'
	 * element.
	 */
	private static final String DOCUMENTPAGE = "DocumentPage";

	/**
	 * Attribute that represents the local name that identifies 'ReportPage'
	 * element.
	 */
	private static final String REPORTPAGE = "ReportPage";

	/**
	 * Attribute that represents the local name that identifies
	 * 'GenerationReport' element.
	 */
	private static final String GENERATIONTIME = "GenerationTime";
	
	/**
	 * Attribute that represents the object that manages the log of the class. 
	 */
	private static final Logger LOGGER = Logger.getLogger(PdfReportManager.class);

	@Override
	public byte[] createReport(ValidationData validationData, DocInclusionData docIncData, byte[] xsltTemplate, byte[] document,
			ArrayList<Barcode> barcodes, ArrayList<FileAttachment> attachments, HashMap<String, String> additionalParameters) throws SignatureReportException {
				
		// 2. Generamos el codigo de barra en caso de haberse solicitado
		BarcodeManager barManager = new BarcodeManager();
		ArrayList<BarcodeImage> bars = null;
		if (barcodes != null && !barcodes.isEmpty()) {
			try {
				bars = barManager.generateBarcode(barcodes, true, false);
			} catch (BarcodeException e1) {
				String msg = Language.getResSigReport(ILogConstantKeys.RPT_013);
				LOGGER.error(msg, e1);
				if (e1.getCode() == BarcodeException.INVALID_INPUT_PARAMETERS) {
					throw new SignatureReportException(SignatureReportException.INVALID_INPUT_PARAMETERS, e1.getDescription(), e1);
				} else {
					throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, msg, e1);
				}
			}
		}
		
		int numPages = 0;
		List<String> pagesOrientation = null;
		String mimeType = null;
		byte[] signedPdf = null;
		if (document != null) {
			// Obtenemos el tipo del documento para comprobar que sea PDF
			try {
				mimeType = FileUtils.getMediaType(document);
				
				if (!FileUtils.PDF_MEDIA_TYPE.equals(mimeType)) {
					
					throw new SignatureReportException(SignatureReportException.INVALID_INPUT_PARAMETERS, "El documento firmado debe ser un PDF");
				}
				
			} catch (UtilsException e) {
				throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, e.getDescription(), e);
			}
			
			signedPdf = document;
			
		} else {
			
			throw new SignatureReportException(SignatureReportException.INVALID_INPUT_PARAMETERS, "El documento firmado no puede ser nulo");
		}			
		
		// Analizamos el modo de generación del documento
		ArrayList<PageDocumentImage> images = null;
		
		if (docIncData.getDocInclusionMode() == ITemplateConfiguration.INC_SIGNED_DOC_EMBED
				|| docIncData.getDocInclusionMode() == ITemplateConfiguration.INC_SIGNED_DOC_CONCAT) {
			
			try {	
				// Extreamos el número de páginas
				if (signedPdf != null) {
					numPages = PDFUtils.getNumPages(signedPdf);
					pagesOrientation = PDFUtils.getPagesOrientation(signedPdf);
				}
			} catch (UtilsException ue) {
				throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, ue.getDescription(), ue);
			}
			
		}
		
		String xmlInput = createInputXML(validationData, additionalParameters, numPages, images, bars, pagesOrientation);
		
		// Aplicamos la transformación XSLT
		byte[] foFile = null;
		try {

			foFile = XMLUtils.xslTransform(xmlInput.getBytes("UTF-8"), xsltTemplate);
			
		} catch (UnsupportedEncodingException e) {
			String msg = Language.getResSigReport(ILogConstantKeys.RPT_005);
			LOGGER.error(msg, e);
			throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, msg, e);
		} catch (UtilsException e) {
			String msg = Language.getResSigReport(ILogConstantKeys.RPT_005);
			LOGGER.error(msg, e);
			throw new SignatureReportException(SignatureReportException.INVALID_TEMPLATE, msg, e);
		}

		if (foFile == null) {
			String msg = Language.getResSigReport(ILogConstantKeys.RPT_014);
			LOGGER.error(msg);
			throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, msg);
		}
		
		// 6.Analizamos si se incrusta el documento original
		MatrixPagesInclude pagesIncl = null;
		if (docIncData.getDocInclusionMode() == ITemplateConfiguration.INC_SIGNED_DOC_EMBED) {

			try {
				Document doc = XMLUtils.getDocument(foFile);
				pagesIncl = getIncludePages(doc);
				foFile = XMLUtils.getXMLBytes(doc);
			} catch (UtilsException e) {
				String msg = Language.getResSigReport(ILogConstantKeys.RPT_015);
				LOGGER.error(msg, e);
				throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, msg, e);
			}

		}
		// 7. Realizamos el procesado XSL-FO
		byte[] pdf = null;
		try {
			pdf = FOUtils.fo2pdf(foFile);
		} catch (UtilsException e) {
			String msg = Language.getResSigReport(ILogConstantKeys.RPT_019);
			LOGGER.error(msg, e);
			if (e.getCode() == UtilsException.INVALID_FO_FILE) {
				throw new SignatureReportException(SignatureReportException.INVALID_TEMPLATE, e.getDescription(), e);
			} else {
				throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, msg, e);
			}

		}
		
		// 8. Se realiza la incrustaci�n del documento original en el informe de
		// firma
		if (pagesIncl != null && !pagesIncl.isEmpty() && signedPdf != null) {
			try {
				pdf = PDFUtils.includePages(pdf, signedPdf, pagesIncl);
			} catch (UtilsException e) {
				String msg = Language.getResSigReport(ILogConstantKeys.RPT_022);
				LOGGER.error(msg, e);
				throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, msg, e);
			}
		}
		// 9. En caso de solicitar concatenaci�n, se concatena informe y
		// documento original.
		if (docIncData.getDocInclusionMode() == ITemplateConfiguration.INC_SIGNED_DOC_CONCAT
				&& signedPdf != null) {
			if (docIncData.getDocConcatRule() == null) {
				String msg = Language.getResSigReport(ILogConstantKeys.RPT_023);
				LOGGER.error(msg);
				throw new SignatureReportException(SignatureReportException.INVALID_TEMPLATE, msg);
			}
			try {
				pdf = PDFUtils.concatPDF(pdf, signedPdf, ITemplateConfiguration.REPORT_CONTAT_ID,
						ITemplateConfiguration.DOCUMENT_CONCAT_ID, docIncData.getDocConcatRule());
			} catch (UtilsException e) {
				LOGGER.error(Language.getResSigReport(ILogConstantKeys.RPT_024), e);
				if (e.getCode() == UtilsException.INVALID_CONCATENATION_RULE) {
					throw new SignatureReportException(SignatureReportException.INVALID_TEMPLATE,
							Language.getResSigReport(ILogConstantKeys.RPT_024), e);
				} else {
					throw new SignatureReportException(SignatureReportException.INVALID_TEMPLATE,
							Language.getResSigReport(ILogConstantKeys.RPT_025), e);
				}
			}

		}
		
		// 10. Incluimos anexos en caso de ser requeridos
		try {
			
			if (!attachments.isEmpty()) {
				pdf = PDFUtils.addAttachment(pdf, attachments);
			}
		} catch (Exception e) {
			String msg = Language.getResSigReport(ILogConstantKeys.RPT_026);
			LOGGER.error(msg);
			throw new SignatureReportException(SignatureReportException.UNKNOWN_ERROR, msg, e);
		}

		return pdf;
	
	}
	
	
	/**
	 * @param validationData The {@link ValidationData} to include in the report
	 * @param additionalParameters Map of external parameters to include in the report
	 * @param numPages Number of pages of the original document
	 * @param images Images to include in the report
	 * @param barcodes Barcodes to include in the report
	 * @param pagesOrientation Page orientation of the report (vertical/landscape)
	 * @return String that represents the input XML used in the XSL-FO transformation
	 */
	private String createInputXML(ValidationData validationData,
			HashMap<String, String> additionalParameters, int numPages, ArrayList<PageDocumentImage> images,
			ArrayList<BarcodeImage> barcodes, List<String> pagesOrientation) {
		StringBuffer sb = new StringBuffer();
		// <?xml version="1.0" encoding="UTF-8"?>
		sb.append(PROC_INSTRUCTION);
		// <GenerationReport
		// xmlns="urn:es:gob:signaturereport:generation:message">
		sb.append("<" + GENERATIONREPORT + " xmlns=\"" + NS + "\">");
		if (validationData != null) {
			// <ValidationResult>
			sb.append("<" + VALIDATIONRESULT + ">");
			// <Result>
			sb.append("<" + RESULT + ">");
			if (validationData.getResultMajor() != null && !validationData.getResultMajor().trim().isEmpty()) {
				// <Major/>
				sb.append("<" + MAJOR + ">"
						+ validationData.getResultMajor() + "</"
						+ MAJOR + ">");
			}
			if (validationData.getResultMinor() != null && !validationData.getResultMinor().trim().isEmpty()) {
				// <Minor/>
				sb.append("<" + MINOR + ">"
						+ validationData.getResultMinor() + "</"
						+ MINOR + ">");
			}
			if (validationData.getResultMessage() != null && !validationData.getResultMessage().trim().isEmpty()) {
				// <Message/>
				sb.append("<" + MESSAGE + ">"
						+ validationData.getResultMessage() + "</"
						+ MESSAGE + ">");
			}
			// </Result>
			sb.append("</" + RESULT + ">");

			if (validationData.getSignatures() != null && !validationData.getSignatures().isEmpty()) {
				List<IndividualSignature> signatures = validationData.getSignatures();
				
				DateTimeFormatter formatter = DateTimeFormatter.ofPattern(validationData.getTimestampFormat());

				for (IndividualSignature indSig : signatures) {
					// <IndividualSignature>
					sb.append("<" + INDIVIDUALSIGNATURE + ">");
					// <Result>
					sb.append("<" + RESULT + ">");
					if (indSig.getResultMajor() != null && !indSig.getResultMajor().isEmpty()) {
						// <Major/>
						sb.append("<" + MAJOR + ">" + indSig.getResultMajor() + "</" + MAJOR
								+ ">");
					}
					if (indSig.getResultMinor() != null && !indSig.getResultMinor().isEmpty()) {
						// <Minor/>
						sb.append("<" + MINOR + ">" + indSig.getResultMinor() + "</" + MINOR
								+ ">");
					}
					if (indSig.getResultMessage() != null && !indSig.getResultMessage().isEmpty()) {
						// <Message/>
						sb.append("<" + MESSAGE + ">" + indSig.getResultMessage() + "</" + MESSAGE
								+ ">");
					}
					// </Result>
					sb.append("</" + RESULT + ">");
					if (indSig.getTimestamp() != null) {
						// <TimeStamp/>
						sb.append("<" + TIMESTAMP + ">" + indSig.getTimestamp().format(formatter) + "</"
								+ TIMESTAMP + ">");
					}
					if (indSig.getCertInfo() != null && !indSig.getCertInfo().isEmpty()) {
						// <CertificateInfo>
						sb.append("<" + CERTIFICATEINFO + ">");
						LinkedHashMap<String, String> certInfo = indSig.getCertInfo();
						Iterator<String> it = certInfo.keySet().iterator();
						while (it.hasNext()) {
							// <Field>
							sb.append("<" + FIELD + ">");
							String id = it.next();
							// <FieldId/>
							sb.append("<" + FIELDID + ">" + id + "</" + FIELDID + ">");
							String value = certInfo.get(id);
							// <FieldValue/>
							sb.append("<" + FIELDVALUE + ">" + StringEscapeUtils.escapeXml10(value) + "</" + FIELDVALUE
									+ ">");
							// </Field>
							sb.append("</" + FIELD + ">");
						}

						// </CertificateInfo>
						sb.append("</" + CERTIFICATEINFO + ">");
					}

					// </IndividualSignature>
					sb.append("</" + INDIVIDUALSIGNATURE + ">");
				}
			}

			// </ValidationResult>
			sb.append("</" + VALIDATIONRESULT + ">");
		}
		sb.append("<" + GENERATIONTIME + ">");
		sb.append(UtilsTime.getFechaSistema(UtilsTime.FORMATO_FECHA_ESTANDAR));
		sb.append("</" + GENERATIONTIME + ">");
		if (additionalParameters != null && !additionalParameters.isEmpty()) {
			// <ExternalParameters>
			sb.append("<" + EXTERNALPARAMETERS + ">");
			Iterator<String> it = additionalParameters.keySet().iterator();
			while (it.hasNext()) {
				// <Parameter>
				sb.append("<" + PARAMETER + ">");
				String id = it.next();
				// <ParameterId/>
				sb.append("<" + PARAMETERID + ">" + id + "</" + PARAMETERID + ">");
				String value = additionalParameters.get(id);
				// <ParameterValue/>
				sb.append("<" + PARAMETERVALUE + ">" + value + "</" + PARAMETERVALUE + ">");
				// </Parameter>
				sb.append("</" + PARAMETER + ">");
			}
			// </ExternalParameters>
			sb.append("</" + EXTERNALPARAMETERS + ">");
		}
		// <DocumentInfo>
		if (numPages > 0) {
			// <DocumentInfo>
			sb.append("<" + DOCUMENTINFO + ">");
			// <NumPages> </NumPages>
			sb.append("<" + NUMPAGES + ">" + numPages + "</" + NUMPAGES + ">");

			if (images != null && !images.isEmpty()) {
				// <PagesList>
				sb.append("<" + PAGESLIST + ">");
				for (int i = 0; i < images.size(); i++) {
					PageDocumentImage pageImage = images.get(i);
					// <Page>
					sb.append("<" + PAGE + ">");
					// <Number> </Number>
					sb.append("<" + NUMBER + ">" + pageImage.getNumPage() + "</" + NUMBER + ">");
					// <URL> </URL>
					sb.append("<" + URL + ">" + pageImage.getLocation() + "</" + URL + ">");
					// </Page>
					sb.append("</" + PAGE + ">");
				}
				// </PagesList>
				sb.append("</" + PAGESLIST + ">");
			}

			if (pagesOrientation != null) {
				// <PagesOrientation>
				sb.append("<" + PAGESORIENTATION + ">");
				// <PageInfo/>
				for (int i = 1; i <= pagesOrientation.size(); i++) {
					sb.append("<" + PAGEINFO + " orientation=\"" + pagesOrientation.get(i - 1) + "\"/>");
				}
				sb.append("</" + PAGESORIENTATION + ">");
				// </PagesOrientation>
			} else {
				// <PagesOrientation>
				sb.append("<" + PAGESORIENTATION + ">");
				// <PageInfo/>
				for (int i = 1; i <= numPages; i++) {
					sb.append("<" + PAGEINFO + " orientation=\"V\"/>");
				}
				sb.append("</" + PAGESORIENTATION + ">");
				// </PagesOrientation>
			}

			// </DocumentInfo>
			sb.append("</" + DOCUMENTINFO + ">");
		}
		if (barcodes != null && !barcodes.isEmpty()) {
			// <Barcodes>
			sb.append("<" + BARCODES + ">");
			for (int i = 0; i < barcodes.size(); i++) {
				BarcodeImage barImg = barcodes.get(i);
				// <Barcode>
				sb.append("<" + BARCODE + ">");
				if (barImg.getBarcodeType() != null) {
					// <Type> </Type>
					sb.append("<" + TYPE + ">" + barImg.getBarcodeType() + "</" + TYPE + ">");
				}
				if (barImg.getMessage() != null) {
					// <Code> </Code>
					sb.append("<" + CODE + ">" + barImg.getMessage() + "</" + CODE + ">");
				}
				if (barImg.getLocation() != null) {
					// <URL> </URL>
					sb.append("<" + URL + ">" + barImg.getLocation() + "</" + URL + ">");
				}
				// </Barcode>
				sb.append("</" + BARCODE + ">");
			}
			// </Barcodes>
			sb.append("</" + BARCODES + ">");
		}

		// </GenerationReport>
		sb.append("</" + GENERATIONREPORT + ">");
		return sb.toString();
	}
	
	/**
	 * FO file may include various  "IncludePage" components in the following format:<br/>
	 // CHECKSTYLE:OFF -- The following describes a IncludePage element.
	 * "<IncludePage Ypos="String" Width="String" Height="String" Xpos="String" Layout="front/back" xmlns="urn:es:gob:signaturereport:generation:inputparameters">"<br/>
	 *  	"<DocumentPage>X</DocumentPage>"<br/>
	 *  	"<ReportPage>Y</ReportPage>"<br/>
	 * "</IncludePage>"<br/>
	 // CHECKSTYLE:ON
	 * In this component  is reported that the X page of signed document is included in the Y page of signature report.
	 * The position of the page is specified with the attributes Ypos, Xpos, Width and Height.
	 * @param doc Fo file.
	 * @return	A {@link MatrixPagesInclude} that contains information about the pages to include in a signature report
	 * @throws ReportException	If an error occurs.
	 */
	private MatrixPagesInclude getIncludePages(Document doc) throws SignatureReportException {
		MatrixPagesInclude matrix = new MatrixPagesInclude();
		NodeList list = doc.getElementsByTagNameNS(NS, INCLUDEPAGE);
		while (list != null && list.getLength() > 0) {
			Node ipNode = list.item(0);
			String docPag = null;
			String rptPag = null;
			NodeList childPage = ipNode.getChildNodes();
			for (int i = 0; i < childPage.getLength(); i++) {
				if (childPage.item(i).getNodeType() == Node.ELEMENT_NODE && childPage.item(i).getLocalName().equals(DOCUMENTPAGE) && childPage.item(i).getFirstChild() != null) {
					docPag = childPage.item(i).getFirstChild().getNodeValue();
				}
				if (childPage.item(i).getNodeType() == Node.ELEMENT_NODE && childPage.item(i).getLocalName().equals(REPORTPAGE) && childPage.item(i).getFirstChild() != null) {
					rptPag = childPage.item(i).getFirstChild().getNodeValue();
				}
			}
			String msg = null;
			if (docPag == null) {
				msg = Language.getFormatResSigReport(ILogConstantKeys.RPT_016, new Object[ ] { INCLUDEPAGE, DOCUMENTPAGE });
			} else if (rptPag == null) {
				msg = Language.getFormatResSigReport(ILogConstantKeys.RPT_016, new Object[ ] { INCLUDEPAGE, REPORTPAGE });
			}
			try {
				PageIncludeFormat format = new PageIncludeFormat();
				if (msg != null) {
					LOGGER.error(msg);
					throw new SignatureReportException(SignatureReportException.INVALID_TEMPLATE, msg);
				}

				if (ipNode.getAttributes().getNamedItem(XPOS) != null && ipNode.getAttributes().getNamedItem(XPOS).getNodeValue() != null) {
					format.setXpos(Double.parseDouble(ipNode.getAttributes().getNamedItem(XPOS).getNodeValue()));
				}

				if (ipNode.getAttributes().getNamedItem(YPOS) != null && ipNode.getAttributes().getNamedItem(YPOS).getNodeValue() != null) {
					format.setYpos(Double.parseDouble(ipNode.getAttributes().getNamedItem(YPOS).getNodeValue()));
				}

				if (ipNode.getAttributes().getNamedItem(WIDTH) != null && ipNode.getAttributes().getNamedItem(WIDTH).getNodeValue() != null) {
					format.setWidth(Double.parseDouble(ipNode.getAttributes().getNamedItem(WIDTH).getNodeValue()));
				}

				if (ipNode.getAttributes().getNamedItem(HEIGHT) != null && ipNode.getAttributes().getNamedItem(HEIGHT).getNodeValue() != null) {
					format.setHeight(Double.parseDouble(ipNode.getAttributes().getNamedItem(HEIGHT).getNodeValue()));
				}

				if (ipNode.getAttributes().getNamedItem(LAYOUT) != null && ipNode.getAttributes().getNamedItem(LAYOUT).getNodeValue() != null) {
					format.setLayout(ipNode.getAttributes().getNamedItem(LAYOUT).getNodeValue());
				}

				matrix.addPage(Integer.parseInt(rptPag), Integer.parseInt(docPag), format);
				Node parent = ipNode.getParentNode();
				parent.removeChild(ipNode);
			} catch (NumberFormatException nfe) {
				msg = Language.getFormatResSigReport(ILogConstantKeys.RPT_017, new Object[ ] { INCLUDEPAGE });
				LOGGER.error(msg, nfe);
				throw new SignatureReportException(SignatureReportException.INVALID_TEMPLATE, msg, nfe);
			}

		}
		return matrix;
	}

}
