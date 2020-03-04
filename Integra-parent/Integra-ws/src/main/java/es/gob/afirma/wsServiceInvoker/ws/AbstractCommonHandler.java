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
 * <b>File:</b><p>es.gob.afirma.wsServiceInvoker.ws.AbstractCommonHandler.java.</p>
 * <b>Description:</b><p>Class that represents handlers used in the service invoker.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>03/10/2011.</p>
 * @author Gobierno de España.
 * @version 1.1, 04/03/2020.
 */
package es.gob.afirma.wsServiceInvoker.ws;

import java.util.Properties;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.handlers.AbstractHandler;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;

/**
 * <p>Class that represents handlers used in the service invoker.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.1, 04/03/2020.
 */
public class AbstractCommonHandler extends AbstractHandler {

    /**
     * Attribute that represents the user name to authenticate the request with UserNameToken, or the alias of the private key defined to to authenticate the
     * request with BinarySecurityToken.
     */
    private String userAlias = "";

    /**
     * Attribute that represents the user password to authenticate the request with UserNameToken, or the password of the private key defined to authenticate
     * the request with BinarySecurityToken.
     */
    private String password = "";

    /**
     * Attribute that represents type of password.
     */
    private String passwordType = WSConstants.PASSWORD_TEXT;

    /**
     * Attribute that represents user Keystore.
     */
    private String userKeystore;

    /**
     * Attribute that represents user Keystore Pass.
     */
    private String userKeystorePass;

    /**
     * Attribute that represents user Keystore Type.
     */
    private String userKeystoreType;

    /**
     * {@inheritDoc}
     * @see org.apache.axis2.engine.Handler#invoke(org.apache.axis2.context.MessageContext)
     */
    @Override
    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {
	return InvocationResponse.CONTINUE;
    }

    /**
     * Method that configures the properties related to WSS4J cryptographic manager.
     * @return the configured properties related to WSS4J cryptographic manager.
     * @throws WSSecurityException If there is an error in loading the cryptographic properties.
     */
    final Crypto getCryptoInstance() throws WSSecurityException {

	Properties properties = new Properties();
	properties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
	properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.type", this.userKeystoreType);
	properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", this.userKeystorePass);
	properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", this.userAlias);
	properties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", this.password);
	properties.setProperty("org.apache.ws.security.crypto.merlin.file", this.userKeystore);
	return CryptoFactory.getInstance(properties);
    }

    /**
     * Gets the value of the attribute {@link #password}.
     * @return the value of the attribute {@link #password}.
     */
    public final String getPassword() {
	return password;
    }

    /**
     * Sets the value of the attribute {@link #password}.
     * @param passParam The value for the attribute {@link #password}.
     */
    public final void setPassword(String passParam) {
	this.password = passParam;
    }

    /**
     * Gets the value of the attribute {@link #passwordType}.
     * @return the value of the attribute {@link #passwordType}.
     */
    public final String getPasswordType() {
	return passwordType;
    }

    /**
     * Sets the value of the attribute {@link #passwordType}.
     * @param passTypeParam The value for the attribute {@link #passwordType}.
     */
    public final void setPasswordType(String passTypeParam) {
	if ("digest".equalsIgnoreCase(passTypeParam)) {
	    this.passwordType = WSConstants.PASSWORD_DIGEST;
	} else if ("clear".equalsIgnoreCase(passTypeParam)) {
	    this.passwordType = WSConstants.PASSWORD_TEXT;
	}
    }

    /**
     * Gets the value of the attribute {@link #userKeystore}.
     * @return the value of the attribute {@link #userKeystore}.
     */
    public final String getUserKeystore() {
	return userKeystore;
    }

    /**
     * Sets the value of the attribute {@link #userKeystore}.
     * @param userKeystoreParam The value for the attribute {@link #userKeystore}.
     */
    public final void setUserKeystore(String userKeystoreParam) {
	this.userKeystore = userKeystoreParam;
    }

    /**
     * Gets the value of the attribute {@link #userKeystorePass}.
     * @return the value of the attribute {@link #userKeystorePass}.
     */
    public final String getUserKeystorePass() {
	return userKeystorePass;
    }

    /**
     * Sets the value of the attribute {@link #userKeystorePass}.
     * @param userKeyPassParam The value for the attribute {@link #userKeystorePass}.
     */
    final void setUserKeystorePass(String userKeyPassParam) {
	this.userKeystorePass = userKeyPassParam;
    }

    /**
     * Gets the value of the attribute {@link #userKeystoreType}.
     * @return the value of the attribute {@link #userKeystoreType}.
     */
    final String getUserKeystoreType() {
	return userKeystoreType;
    }

    /**
     * Sets the value of the attribute {@link #userKeystoreType}.
     * @param userKeyType The value for the attribute {@link #userKeystoreType}.
     */
    public final void setUserKeystoreType(String userKeyType) {
	this.userKeystoreType = userKeyType;
    }

    /**
     * Gets the value of the attribute {@link #userAlias}.
     * @return the value of the attribute {@link #userAlias}.
     */
    public final String getUserAlias() {
	return userAlias;
    }

    /**
     * Sets the value of the attribute {@link #userAlias}.
     * @param userAliasParam The value for the attribute {@link #userAlias}.
     */
    public final void setUserAlias(String userAliasParam) {
	this.userAlias = userAliasParam;
    }

}
