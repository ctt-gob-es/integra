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
 * <b>File:</b><p>es.gob.afirma.mreport.items.DocInclusionData.java.</p>
 * <b>Description:</b><p>Class that represents the inclusion mode and other options for the original document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>19/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 24/08/2020.
 */
package es.gob.afirma.mreport.items;

/** 
 * <p>Class that represents the inclusion mode and other options for the original document.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 24/08/2020.
 */
public class DocInclusionData {
	
	/**
	 * Attribute that represents the inclusion mode of the original document
	 * 0 - Embedded
	 * 1 - Concatenated
	 */
	private int docInclusionMode;
	
	/**
	 * Attribute that represents the concatenation rule for including the original document in the report in the mode selected was 'concatenate'.
	 */
	private String docConcatRule;

	/**
	 * Gets the value of the attribute {@link #docInclusionMode}.
	 * @return the value of the attribute {@link #docInclusionMode}.
	 */
	public int getDocInclusionMode() {
		return docInclusionMode;
	}

	/**
	 * Sets the value of the attribute {@link #docInclusionMode}.
	 * @param docInclusionModeParam the value for the attribute {@link #docInclusionMode} to set.
	 */
	public void setDocInclusionMode(int docInclusionModeParam) {
		this.docInclusionMode = docInclusionModeParam;
	}

	/**
	 * Gets the value of the attribute {@link #docConcatRule}.
	 * @return the value of the attribute {@link #docConcatRule}.
	 */
	public String getDocConcatRule() {
		return docConcatRule;
	}

	/**
	 * Sets the value of the attribute {@link #docConcatRule}.
	 * @param docConcatRuleParam the value for the attribute {@link #docConcatRule} to set.
	 */
	public void setDocConcatRule(String docConcatRuleParam) {
		this.docConcatRule = docConcatRuleParam;
	}	
	
	
	
}
