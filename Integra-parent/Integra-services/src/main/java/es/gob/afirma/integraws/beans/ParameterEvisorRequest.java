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
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/** 
 * <b>File:</b><p>es.gob.afirma.integraws.beans.ParameterEvisorRequest.java.</p>
 * <b>Description:</b><p> Class that represents a parameter for evisor generate report service request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>12/5/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 12/5/2016.
 */
package es.gob.afirma.integraws.beans;

/** 
 * <p>Class that represents a parameter for evisor generate report service request.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 12/5/2016.
 */
public class ParameterEvisorRequest {

    /**
     * Attribute that represents the parameter id. 
     */
    private String parameterId;

    /**
     * Attribute that represents the parameter value. 
     */
    private String parameterValue;

    /**
     * Gets the value of the attribute {@link #parameterId}.
     * @return the value of the attribute {@link #parameterId}.
     */
    public final String getParameterId() {
	return parameterId;
    }

    /**
     * Sets the value of the attribute {@link #parameterId}.
     * @param parameterIdParam The value for the attribute {@link #parameterId}.
     */
    public final void setParameterId(String parameterIdParam) {
	this.parameterId = parameterIdParam;
    }

    /**
     * Gets the value of the attribute {@link #parameterValue}.
     * @return the value of the attribute {@link #parameterValue}.
     */
    public final String getParameterValue() {
	return parameterValue;
    }

    /**
     * Sets the value of the attribute {@link #parameterValue}.
     * @param parameterValueParam The value for the attribute {@link #parameterValue}.
     */
    public final void setParameterValue(String parameterValueParam) {
	this.parameterValue = parameterValueParam;
    }

}
