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
 * <b>File:</b><p>es.gob.afirma.signature.policy.SignaturePolicyException.java.</p>
 * <b>Description:</b><p>Class that manages the exceptions related to signature policy processes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>26/11/2014.</p>
 * @author Gobierno de España.
 * @version 1.0, 26/11/2014.
 */
package es.gob.afirma.signature.policy;

/** 
 * <p>Class that manages the exceptions related to signature policy processes.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 26/11/2014.
 */
public class SignaturePolicyException extends Exception {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 266809042867695661L;

    /**
     * Constructor method for the class SignaturePolicyException.java.
     */
    public SignaturePolicyException() {
	super();
    }

    /**
     * Constructor method for the class SignaturePolicyException.java.
     * @param message Error message.
     */
    public SignaturePolicyException(String message) {
	super(message);
    }

    /**
     * Constructor method for the class SignaturePolicyException.java.
     * @param cause Error cause.
     */
    public SignaturePolicyException(Throwable cause) {
	super(cause);

    }

    /**
     * Constructor method for the class SignaturePolicyException.java.
     * @param message Error message.
     * @param cause Error cause.
     */
    public SignaturePolicyException(String message, Throwable cause) {
	super(message, cause);
    }

}
