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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.Result.java.</p>
 * <b>Description:</b><p>Class that represents the result of the method called by the associated web service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>18/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 18/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the result of the method called by the associated web service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/11/2014.
 */
public class Result implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 8232396846092688632L;

    /**
     * Attribute that indicates global result of process by an URI.
     */
    private String resultMajor;

    /**
     * Attribute that indicates specified result of process by an URI.
     */
    private String resultMinor;

    /**
     * Attribute that contains a descriptive message of the result of the process.
     */
    private String resultMessage;

    /**
     * Constructor method for the class Result.java.
     */
    public Result() {
    }

    /**
     * Gets the value of the attribute {@link #resultMajor}.
     * @return the value of the attribute {@link #resultMajor}.
     */
    public final String getResultMajor() {
	return resultMajor;
    }

    /**
     * Sets the value of the attribute {@link #resultMajor}.
     * @param resultMajorParam The value for the attribute {@link #resultMajor}.
     */
    public final void setResultMajor(String resultMajorParam) {
	this.resultMajor = resultMajorParam;
    }

    /**
     * Gets the value of the attribute {@link #resultMinor}.
     * @return the value of the attribute {@link #resultMinor}.
     */
    public final String getResultMinor() {
	return resultMinor;
    }

    /**
     * Sets the value of the attribute {@link #resultMinor}.
     * @param resultMinorParam The value for the attribute {@link #resultMinor}.
     */
    public final void setResultMinor(String resultMinorParam) {
	this.resultMinor = resultMinorParam;
    }

    /**
     * Gets the value of the attribute {@link #resultMessage}.
     * @return the value of the attribute {@link #resultMessage}.
     */
    public final String getResultMessage() {
	return resultMessage;
    }

    /**
     * Sets the value of the attribute {@link #resultMessage}.
     * @param resultMessageParam The value for the attribute {@link #resultMessage}.
     */
    public final void setResultMessage(String resultMessageParam) {
	this.resultMessage = resultMessageParam;
    }

}
