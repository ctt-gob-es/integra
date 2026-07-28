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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.elements.DetectCertInTslInfoAndValidationResponse.java.</p>
 * <b>Description:</b><p>Class that represents structure of detected certificate in TSL and validation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/10/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/10/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;


/** 
 * <p>Class that represents structure of detected certificate in TSL and validation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/10/2020.
 */
public class DetectCertInTslInfoAndValidationResponse implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = 717274246869116483L;
    /**
	 * Attribute that represents the status.
	 */
	private Integer status;

	/**
	 * Attribute that represents the description.
	 */
	private String description;

	/**
	 * Attribute that represents the result.
	 */
	private ResultTslInfVal resultTslInfVal;

	/**
	 * Gets the value of the attribute {@link #status}.
	 * @return the value of the attribute {@link #status}.
	 */
	public Integer getStatus() {
		return status;
	}

	/**
	 * Sets the value of the attribute {@link #status}.
	 * @param statusParam The value for the attribute {@link #status}.
	 */
	public void setStatus(final Integer statusParam) {
		this.status = statusParam;
	}

	/**
	 * Gets the value of the attribute {@link #description}.
	 * @return the value of the attribute {@link #description}.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Sets the value of the attribute {@link #description}.
	 * @param descriptionParam The value for the attribute {@link #description}.
	 */
	public void setDescription(final String descriptionParam) {
		this.description = descriptionParam;
	}

	/**
	 * Gets the value of the attribute {@link #resultTslInfVal}.
	 * @return the value of the attribute {@link #resultTslInfVal}.
	 */
	public ResultTslInfVal getResultTslInfVal() {
		return resultTslInfVal;
	}

	/**
	 * Sets the value of the attribute {@link #resultTslInfVal}.
	 * @param resultTslInfValP The value for the attribute {@link #resultTslInfVal}.
	 */
	public void setResultTslInfVal(final ResultTslInfVal resultTslInfValP) {
		this.resultTslInfVal = resultTslInfValP;
	}


}
