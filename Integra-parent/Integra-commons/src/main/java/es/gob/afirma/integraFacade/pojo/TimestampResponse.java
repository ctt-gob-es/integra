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
 * <b>File:</b><p>es.gob.afirma.integraFacade.pojo.ServerSignerResponse.java.</p>
 * <b>Description:</b><p>Class that represents the response from the server signature service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>17/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 17/11/2014.
 */
package es.gob.afirma.integraFacade.pojo;

import java.io.Serializable;

/**
 * <p>Class that represents the response from the server signature service.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2016.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/03/2016.
 */
public class TimestampResponse implements Serializable {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 2078843229468890316L;

    /**
     * Attribute that represents the result of the process.
     */
    private Result result;

    /**
     * Attribute that represents the generated timestamp.
     */
    private byte[ ] timestamp;

    /**
     * Constructor method for the class TimestampResponse.java.
     */
    public TimestampResponse() {
    }

    /**
     * Gets the value of the attribute {@link #result}.
     * @return the value of the attribute {@link #result}.
     */
    public final Result getResult() {
	return result;
    }

    /**
     * Sets the value of the attribute {@link #result}.
     * @param resultParam The value for the attribute {@link #result}.
     */
    public final void setResult(Result resultParam) {
	this.result = resultParam;
    }

    /**
     * Gets the value of the attribute {@link #timestamp}.
     * @return the value of the attribute {@link #timestamp}.
     */
    public final byte[ ] getTimestamp() {
	return timestamp;
    }

    /**
     * Sets the value of the attribute {@link #timestamp}.
     * @param timestampParam The value for the attribute {@link #timestamp}.
     */
    public final void setTimestamp(byte[ ] timestampParam) {
	if (timestampParam != null) {
	    this.timestamp = timestampParam.clone();
	}
    }

}
