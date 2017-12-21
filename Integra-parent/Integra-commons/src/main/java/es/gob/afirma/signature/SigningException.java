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
 * <b>File:</b><p>es.gob.afirma.signature.SigningException.java.</p>
 * <b>Description:</b><p>Class that manages the exceptions related to sign, upgrade and verify signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/06/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 28/06/2011.
 */
package es.gob.afirma.signature;

/**
 * <p>Class that manages the exceptions related to sign, upgrade and verify signatures.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/06/2011.
 */
public class SigningException extends Exception {

    /**
     * Class serial version.
     */
    private static final long serialVersionUID = 7627042695332047140L;

    /**
     * Constructor method for the class SignerException.java.
     */
    public SigningException() {
	super();
    }

    /**
     * Constructor method for the class SignerException.java.
     * @param message Error message.
     * @param cause Error cause.
     */
    public SigningException(String message, Throwable cause) {
	super(message, cause);
    }

    /**
     * Constructor method for the class SignerException.java.
     * @param message Error message.
     */
    public SigningException(String message) {
	super(message);
    }

    /**
     * Constructor method for the class SignerException.java.
     * @param cause Error cause.
     */
    public SigningException(Throwable cause) {
	super(cause);
    }

}
