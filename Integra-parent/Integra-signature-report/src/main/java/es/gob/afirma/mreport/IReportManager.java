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
 * <b>File:</b><p>es.gob.afirma.mreport.IReportManager.java.</p>
 * <b>Description:</b><p>Interface that contains methods and constants used for the management signature reports.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>21/02/2011.</p>
 * @author Spanish Government.
 * @version 1.0, 18/08/2020.
 */
package es.gob.afirma.mreport;

import java.util.ArrayList;
import java.util.HashMap;

import es.gob.afirma.mreport.exceptions.SignatureReportException;
import es.gob.afirma.mreport.items.Barcode;
import es.gob.afirma.mreport.items.DocInclusionData;
import es.gob.afirma.mreport.items.FileAttachment;
import es.gob.afirma.mreport.items.ValidationData;
//import es.gob.signaturereport.configuration.items.TemplateData;
//import es.gob.signaturereport.modes.parameters.Barcode;


/** 
 * <p>Interface that contains methods and constants used for the management signature reports.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/08/2020.
 */
public interface IReportManager {
	
    
    /**
     * Create a signature report from the information supplied.
     * @param validationData	{@link ValidationData} that contains the validation results.
     * @param docIncData		Inclusion mode for the original document:
     * 									{@link ITemplateConfiguration#INC_SIGNED_DOC_EMBED}
     *									{@link ITemplateConfiguration#INC_SIGNED_DOC_CONCAT}
     * @param xsltTemplate		XSLT Template to apply the FO transformation.
     * @param document			Signed document.
     * @param barcodes			Bar code to include into the signature report.
     * @param attachments		Documents attached.
     * @param additionalParameters	Additional parameters included in the request.
     * @return	byte[] that represents the generated PDF Report.
     * @throws SignatureReportException		If an error occurs generating the report.
     */
   byte[ ] createReport(ValidationData validationData, DocInclusionData docIncData, byte[] xsltTemplate, byte[ ] document, ArrayList<Barcode> barcodes, ArrayList<FileAttachment> attachments, HashMap<String, String> additionalParameters) throws SignatureReportException;


}
