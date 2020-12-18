package es.gob.afirma.mreport.test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import es.gob.afirma.mreport.ITemplateConfiguration;
import es.gob.afirma.mreport.barcode.BarcodeManagerI;
import es.gob.afirma.mreport.exceptions.SignatureReportException;
import es.gob.afirma.mreport.items.Barcode;
import es.gob.afirma.mreport.items.DocInclusionData;
import es.gob.afirma.mreport.items.FileAttachment;
import es.gob.afirma.mreport.items.IndividualSignature;
import es.gob.afirma.mreport.items.ValidationData;
import es.gob.afirma.mreport.pdf.PdfReportManager;
import es.gob.afirma.mreport.utils.URLUtils;
import es.gob.afirma.mreport.utils.UtilsBase64;

public class ReportGeneration {
	
	@Test
	public void newReport() throws URISyntaxException, IOException, SignatureReportException {
		File file = getFileFromResource("documento de prueba.pdf");
		File templateFile = getFileFromResource("testing.xsl");
		File logo_afirma = getFileFromResource("logo_afirma.jpg");
		File logo_ministerio = getFileFromResource("logo_ministerio.jpg");

		byte[] fileBytes = FileUtils.readFileToByteArray(file);
		byte[] xsltTemplate = FileUtils.readFileToByteArray(templateFile);
		byte[] logoAfirmaBytes = FileUtils.readFileToByteArray(logo_afirma);

		DocInclusionData docIncData = new DocInclusionData();
		docIncData.setDocInclusionMode(ITemplateConfiguration.INC_SIGNED_DOC_EMBED);
		docIncData.setDocConcatRule(null);

		PdfReportManager manager = new PdfReportManager();
		ValidationData validation = getValidationData();
		ArrayList<Barcode> barcodes = getBarcodes();
		ArrayList<FileAttachment> attachments = getFileAttachments();
		
		HashMap<String, String> additionalParameters = new HashMap<>();
		additionalParameters.put("externalReference", "Esta es una referencia externa");
		additionalParameters.put("urlBytesLogoAfirma", getUrlBytes(logoAfirmaBytes));
		additionalParameters.put("uriLogoMinisterio", logo_ministerio.toURI().toString());

		byte[] report = manager.createReport(validation, docIncData, xsltTemplate, fileBytes, barcodes, attachments,
				additionalParameters);
		
		File parentReport = getFileFromResource("");
		FileUtils.writeByteArrayToFile(new File(parentReport, "report.pdf"),
				report);
		
	}
	
	private String getUrlBytes(byte[] byteArray) {
		UtilsBase64 base64Tool = new UtilsBase64();
		String barEncoded = base64Tool.encodeBytes(byteArray);
		String url = URLUtils.createRFC2397URL("image/png", barEncoded);
		
		return url;
	}

	private ArrayList<FileAttachment> getFileAttachments() {
		ArrayList<FileAttachment> attachments = new ArrayList<>();
		FileAttachment attachment = new FileAttachment("testAttName", "textAttachmentDescription");
		attachment.setContent("texto de prueba".getBytes());
		attachments.add(attachment);
		return attachments;
	}

	private ArrayList<Barcode> getBarcodes() {
		ArrayList<Barcode> barcodes = new ArrayList<>();
		LinkedHashMap<String, String> confParameters = new LinkedHashMap<>();
		confParameters.put("keyParam", "valueKeyParam");
		Barcode barcode = new Barcode(BarcodeManagerI.PDF417, "Mensaje del barcode");
		barcode.setConfiguration(confParameters);
		barcodes.add(barcode);
		return barcodes;
	}

	private ValidationData getValidationData() {
		String resultMajor = "urn:afirma:dss:1.0:profile:XSS:resultmajor:ValidSignature";
		String resultMinor = null;
		String resultMessage = "Proceso de generación de firma en servidor realizado correctamente.";
		LocalDateTime date = LocalDateTime.now();
		LinkedHashMap<String, String> certInfo = new LinkedHashMap<>();
		certInfo.put("nombreResponsable", "Manuel");
		certInfo.put("primerApellidoResponsable", "Español");
		certInfo.put("segundoApellidoResponsable", "Español");
		certInfo.put("NIFResponsable", "11111111T");
		certInfo.put("emisor", "FNMT");
		IndividualSignature signature = new IndividualSignature(resultMajor, resultMinor, resultMessage, date,
				certInfo);
		ValidationData validation = new ValidationData(resultMajor, resultMinor, resultMessage,
				Arrays.asList(signature));
		validation.setTimestampFormat("dd/MM/yyyy");
		return validation;
	}
	
	private File getFileFromResource(String fileName) throws URISyntaxException {

		ClassLoader classLoader = ReportGeneration.class.getClassLoader();
		URL resource = classLoader.getResource(fileName);
		if (resource == null) {
			throw new IllegalArgumentException("file not found! " + fileName);
		} else {
			return new File(resource.toURI());
		}

	}
}
