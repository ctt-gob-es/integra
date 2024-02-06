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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.ResultTslInfVal.java.</p>
 * <b>Description:</b><p>Class that represents structure of TSL information and validation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/10/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/10/2020.
 */
package es.gob.afirma.tsl.elements;

import java.io.Serializable;


/** 
 * <p>Class that represents structure of TSL information and validation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/10/2020.
 */
public class ResultTslInfVal implements Serializable {

    /**
     * Constant attribute that represents the serial version UID. 
     */
    private static final long serialVersionUID = -8791937534578121459L;
	/**
	 * Attribute that represents the TSL information data.
	 */
	private TslInformation tslInformation;

	/**
	 * Attribute that represents the certificated detected in TSL.
	 */
	private CertDetectedInTSL certDetectedInTSL;

	/**
	 * Gets the value of the attribute {@link #tslInformation}.
	 * @return the value of the attribute {@link #tslInformation}.
	 */
	public TslInformation getTslInformation() {
		return tslInformation;
	}

	/**
	 * Sets the value of the attribute {@link #tslInformation}.
	 * @param tslInformationP The value for the attribute {@link #tslInformation}.
	 */
	public void setTslInformation(final TslInformation tslInformationP) {
		this.tslInformation = tslInformationP;
	}

	/**
	 * Gets the value of the attribute {@link #certDetectedInTSL}.
	 * @return the value of the attribute {@link #certDetectedInTSL}.
	 */
	public CertDetectedInTSL getCertDetectedInTSL() {
		return certDetectedInTSL;
	}

	/**
	 * Sets the value of the attribute {@link #certDetectedInTSL}.
	 * @param certDetectInTSLP The value for the attribute {@link #certDetectedInTSL}.
	 */
	public void setCertDetectedInTSL(final CertDetectedInTSL certDetectInTSLP) {
		this.certDetectedInTSL = certDetectInTSLP;
	}

}
