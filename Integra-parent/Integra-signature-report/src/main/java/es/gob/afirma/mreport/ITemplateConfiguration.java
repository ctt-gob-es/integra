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
 * <b>File:</b><p>es.gob.afirma.mreport.IDocInclusionData.java.</p>
 * <b>Description:</b><p>Interface that represents the inclusion mode and other options for the original document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 24/08/2020.
 */
package es.gob.afirma.mreport;

/** 
 * <p>Interface that represents the inclusion mode and other options for the original document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/08/2020.
 */
public interface ITemplateConfiguration {		          
            
    /**
     * Attribute that represents that the report includes the signed document embed into the report. 
     */
    int INC_SIGNED_DOC_EMBED = 0;
    
    /**
     * Attribute that represents that the report and signed document will be concatenated. 
     */
    int INC_SIGNED_DOC_CONCAT = 1;
    
    /**
     * Attribute that represents the identifier the report into the concatenation rule. 
     */
    String REPORT_CONTAT_ID = "REP";
    
    /**
     * Attribute that represents the identifier the document into the concatenation rule. 
     */
    String DOCUMENT_CONCAT_ID = "DOC";
    
    /**
     * Attribute that represents the mask of page rule. 
     */
    String RANGE_MASK = "(([1-9][0-9]*)(\\-([1-9][0-9]*))?)((\\s)*,(\\s)*([1-9][0-9]*)(\\-([1-9][0-9]*))?)*";
    
    /**
     * Attribute that represents the mask of rule that  document and report will be concatenated. 
     */
    String CONCANT_MASK = "(REP|DOC)((\\()([1-9][0-9]*)((\\s)*\\-(\\s)*[1-9][0-9]*)?(\\)))?" +
	"((\\s)*\\+(\\s)*(REP|DOC)((\\()([1-9][0-9]*)((\\s)*\\-(\\s)*[1-9][0-9]*)?(\\)))?)*";

}
