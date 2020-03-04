// Copyright (C) 2020 MINHAP, Gobierno de España
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
 * <b>File:</b><p>es.gob.afirma.tsaServiceInvoker.ws.AbstractTSAHandler.java.</p>
 * <b>Description:</b><p>Class that represents handlers used in the TS@ service invoker.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/03/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/03/2020.
 */
package es.gob.afirma.tsaServiceInvoker.ws;

import java.util.Properties;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.handlers.AbstractHandler;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;

/**
 * <p>Class that represents handlers used in the TS@ service invoker.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 04/03/2020.
 */
public class AbstractTSAHandler extends AbstractHandler {

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
     * Attribute that represents the SAML method type used in SAML authentication.
     */
    private String samlMethod;
    
    /**
     * Attribute that represents the keystore used to validate the TS@ response.
     */
    private String responseKeystore;
    
    /**
     * Attribute that represents the keystore password used to validate the TS@ response.
     */
    private String responseKeystorePass;
    
    /**
     * Attribute that represents the keystore type used to validate the TS@ response.
     */
    private String responseKeystoreType;
    
    /**
     * Attribute that represents the certificate alias used to validate the TS@ response.
     */
    private String responseCertificateAlias;
    
    /**
     * Attribute that represents the SAML keystore used to validate the TS@ response.
     */
    private String responseSAMLKeystore;
    
    /**
     * Attribute that represents the SAML keystore password used to validate the TS@ response.
     */
    private String responseSAMLKeystorePass;
    
    /**
     * Attribute that represents the SAML keystore type used to validate the TS@ response.
     */
    private String responseSAMLKeystoreType;
    
    /**
     * Attribute that represents the SAML certificate alias used to validate the TS@ response.
     */
    private String responseSAMLCertificateAlias;

    /**
     * Attribute that represents if the TS@ connection is going to be encrypted (true) or not (false).
     */
    private boolean encryptMessage;

    /**
     * Attribute that represents the symmetric key alias used in the TS@ request message.
     */
    private String requestSymmetricKeyAlias;

    /**
     * Attribute that represents the symmetric key used in the TS@ request message.
     */
    private String requestSymmetricKeyValue;

    /**
     * Attribute that represents the symmetric algorithm used in the TS@ request message.
     */
    private String requestSymmetricAlgorithm;
    
    /**
     * Attribute that represents the symmetric key alias used in the TS@ response message.
     */
    private String responseSymmetricKeyAlias;
    
    /**
     * Attribute that represents the symmetric key used in the TS@ response message.
     */
    private String responseSymmetricKeyValue;    

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
     * Method that configures the properties related to WSS4J cryptographic manager.
     * @return the configured properties related to WSS4J cryptographic manager.
     * @throws WSSecurityException If there is an error in loading the cryptographic properties.
     */
    final Crypto getResponseCryptoInstance() throws WSSecurityException {
	Properties properties = new Properties();
	properties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
	properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.type", this.responseKeystoreType);
	properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", this.responseKeystorePass);
	properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", this.responseCertificateAlias);
	properties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", this.password);
	properties.setProperty("org.apache.ws.security.crypto.merlin.file", this.responseKeystore);
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

    /**
     * Gets the value of the attribute {@link #samlMethod}.
     * @return the value of the attribute {@link #samlMethod}.
     */
    public String getSamlMethod() {
        return samlMethod;
    }
    
    /**
     * Sets the value of the attribute {@link #samlMethod}.
     * @param samlMethodParam The value for the attribute {@link #samlMethod}.
     */
    public void setSamlMethod(String samlMethodParam) {
        this.samlMethod = samlMethodParam;
    }

    /**
     * Gets the value of the attribute {@link #responseKeystore}.
     * @return the value of the attribute {@link #responseKeystore}.
     */
    public String getResponseKeystore() {
        return responseKeystore;
    }

    /**
     * Sets the value of the attribute {@link #responseKeystore}.
     * @param responseKeystoreParam The value for the attribute {@link #responseKeystore}.
     */
    public void setResponseKeystore(String responseKeystoreParam) {
        this.responseKeystore = responseKeystoreParam;
    }

    /**
     * Gets the value of the attribute {@link #responseKeystorePass}.
     * @return the value of the attribute {@link #responseKeystorePass}.
     */
    public String getResponseKeystorePass() {
        return responseKeystorePass;
    }

    /**
     * Sets the value of the attribute {@link #responseKeystorePass}.
     * @param responseKeystorePassParam The value for the attribute {@link #responseKeystorePass}.
     */
    public void setResponseKeystorePass(String responseKeystorePassParam) {
        this.responseKeystorePass = responseKeystorePassParam;
    }

    
    /**
     * Gets the value of the attribute {@link #responseKeystoreType}.
     * @return the value of the attribute {@link #responseKeystoreType}.
     */
    public String getResponseKeystoreType() {
        return responseKeystoreType;
    }

    /**
     * Sets the value of the attribute {@link #responseKeystoreType}.
     * @param responseKeystoreTypeParam The value for the attribute {@link #responseKeystoreType}.
     */
    public void setResponseKeystoreType(String responseKeystoreTypeParam) {
        this.responseKeystoreType = responseKeystoreTypeParam;
    }

    /**
     * Gets the value of the attribute {@link #responseCertificateAlias}.
     * @return the value of the attribute {@link #responseCertificateAlias}.
     */
    public String getResponseCertificateAlias() {
        return responseCertificateAlias;
    }

    /**
     * Sets the value of the attribute {@link #responseCertificateAlias}.
     * @param responseCertificateAliasParam The value for the attribute {@link #responseCertificateAlias}.
     */
    public void setResponseCertificateAlias(String responseCertificateAliasParam) {
        this.responseCertificateAlias = responseCertificateAliasParam;
    }

    /**
     * Gets the value of the attribute {@link #responseSAMLKeystore}.
     * @return the value of the attribute {@link #responseSAMLKeystore}.
     */
    public String getResponseSAMLKeystore() {
        return responseSAMLKeystore;
    }

    /**
     * Sets the value of the attribute {@link #responseSAMLKeystore}.
     * @param responseSAMLKeystoreParam The value for the attribute {@link #responseSAMLKeystore}.
     */
    public void setResponseSAMLKeystore(String responseSAMLKeystoreParam) {
        this.responseSAMLKeystore = responseSAMLKeystoreParam;
    }

    /**
     * Gets the value of the attribute {@link #responseSAMLKeystorePass}.
     * @return the value of the attribute {@link #responseSAMLKeystorePass}.
     */
    public String getResponseSAMLKeystorePass() {
        return responseSAMLKeystorePass;
    }

    /**
     * Sets the value of the attribute {@link #responseSAMLKeystorePass}.
     * @param responseSAMLKeystorePassParam The value for the attribute {@link #responseSAMLKeystorePass}.
     */
    public void setResponseSAMLKeystorePass(String responseSAMLKeystorePassParam) {
        this.responseSAMLKeystorePass = responseSAMLKeystorePassParam;
    }

    /**
     * Gets the value of the attribute {@link #responseSAMLKeystoreType}.
     * @return the value of the attribute {@link #responseSAMLKeystoreType}.
     */
    public String getResponseSAMLKeystoreType() {
        return responseSAMLKeystoreType;
    }

    /**
     * Sets the value of the attribute {@link #responseSAMLKeystoreType}.
     * @param responseSAMLKeystoreTypeParam The value for the attribute {@link #responseSAMLKeystoreType}.
     */
    public void setResponseSAMLKeystoreType(String responseSAMLKeystoreTypeParam) {
        this.responseSAMLKeystoreType = responseSAMLKeystoreTypeParam;
    }

    /**
     * Gets the value of the attribute {@link #responseSAMLCertificateAlias}.
     * @return the value of the attribute {@link #responseSAMLCertificateAlias}.
     */
    public String getResponseSAMLCertificateAlias() {
        return responseSAMLCertificateAlias;
    }

    /**
     * Sets the value of the attribute {@link #responseSAMLCertificateAlias}.
     * @param responseSAMLCertificateAliasParam The value for the attribute {@link #responseSAMLCertificateAlias}.
     */
    public void setResponseSAMLCertificateAlias(String responseSAMLCertificateAliasParam) {
        this.responseSAMLCertificateAlias = responseSAMLCertificateAliasParam;
    }

    /**
     * Gets the value of the attribute {@link #encryptMessage}.
     * @return the value of the attribute {@link #encryptMessage}.
     */
    public boolean isEncryptMessage() {
        return encryptMessage;
    }

    /**
     * Sets the value of the attribute {@link #encryptMessage}.
     * @param encryptMessageParam The value for the attribute {@link #encryptMessage}.
     */
    public void setEncryptMessage(boolean encryptMessageParam) {
        this.encryptMessage = encryptMessageParam;
    }

    /**
     * Gets the value of the attribute {@link #requestSymmetricKeyAlias}.
     * @return the value of the attribute {@link #requestSymmetricKeyAlias}.
     */
    public String getRequestSymmetricKeyAlias() {
        return requestSymmetricKeyAlias;
    }

    /**
     * Sets the value of the attribute {@link #requestSymmetricKeyAlias}.
     * @param requestSymmetricKeyAliasParam The value for the attribute {@link #requestSymmetricKeyAlias}.
     */
    public void setRequestSymmetricKeyAlias(String requestSymmetricKeyAliasParam) {
        this.requestSymmetricKeyAlias = requestSymmetricKeyAliasParam;
    }

    /**
     * Gets the value of the attribute {@link #requestSymmetricKeyValue}.
     * @return the value of the attribute {@link #requestSymmetricKeyValue}.
     */
    public String getRequestSymmetricKeyValue() {
        return requestSymmetricKeyValue;
    }

    /**
     * Sets the value of the attribute {@link #requestSymmetricKeyValue}.
     * @param requestSymmetricKeyValueParam The value for the attribute {@link #requestSymmetricKeyValue}.
     */
    public void setRequestSymmetricKeyValue(String requestSymmetricKeyValueParam) {
        this.requestSymmetricKeyValue = requestSymmetricKeyValueParam;
    }
    
    /**
     * Gets the value of the attribute {@link #requestSymmetricAlgorithm}.
     * @return the value of the attribute {@link #requestSymmetricAlgorithm}.
     */
    public String getRequestSymmetricAlgorithm() {
        return requestSymmetricAlgorithm;
    }

    /**
     * Sets the value of the attribute {@link #requestSymmetricAlgorithm}.
     * @param requestSymmetricAlgorithmParam The value for the attribute {@link #requestSymmetricAlgorithm}.
     */
    public void setRequestSymmetricAlgorithm(String requestSymmetricAlgorithmParam) {
        this.requestSymmetricAlgorithm = requestSymmetricAlgorithmParam;
    }

    /**
     * Gets the value of the attribute {@link #responseSymmetricKeyAlias}.
     * @return the value of the attribute {@link #responseSymmetricKeyAlias}.
     */
    public String getResponseSymmetricKeyAlias() {
        return responseSymmetricKeyAlias;
    }

    /**
     * Sets the value of the attribute {@link #responseSymmetricKeyAlias}.
     * @param responseSymmetricKeyAliasParam The value for the attribute {@link #responseSymmetricKeyAlias}.
     */
    public void setResponseSymmetricKeyAlias(String responseSymmetricKeyAliasParam) {
        this.responseSymmetricKeyAlias = responseSymmetricKeyAliasParam;
    }

    /**
     * Gets the value of the attribute {@link #responseSymmetricKeyValue}.
     * @return the value of the attribute {@link #responseSymmetricKeyValue}.
     */
    public String getResponseSymmetricKeyValue() {
        return responseSymmetricKeyValue;
    }

    /**
     * Sets the value of the attribute {@link #responseSymmetricKeyValue}.
     * @param responseSymmetricKeyValueParam The value for the attribute {@link #responseSymmetricKeyValue}.
     */
    public void setResponseSymmetricKeyValue(String responseSymmetricKeyValueParam) {
        this.responseSymmetricKeyValue = responseSymmetricKeyValueParam;
    }
    
}
