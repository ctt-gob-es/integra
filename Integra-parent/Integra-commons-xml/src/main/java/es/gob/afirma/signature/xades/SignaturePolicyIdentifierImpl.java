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
 * <b>File:</b><p>es.gob.afirma.signature.xades.SignaturePolicyIdentifier.java.</p>
 * <b>Description:</b><p>Class that represents a <code>xades:SignaturePolicyIdentifier</code> element of a XAdES signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>04/08/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 04/08/2011.
 */
package es.gob.afirma.signature.xades;

import net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier;

/**
 * <p>Class that represents a <code>xades:SignaturePolicyIdentifier</code> element of a XAdES signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 21/09/2011.
 */
public class SignaturePolicyIdentifierImpl implements SignaturePolicyIdentifier {

    /**
     * Attribute that indicates whether the data object(s) being signed and other external data imply the signature policy.
     */
    private boolean implied;

    /**
     * Attribute that represents the identifier of the signature policy.
     */
    private String identifier;

    /**
     * Attribute that represents the description.
     */
    private String description;

    /**
     * Attribute that represents the qualifier.
     */
    private String qualifier;

    /**
     * Attribute that represents the hash encoded on Base 64.
     */
    private String hashBase64;

    /**
     * Constructor method for the class SignaturePolicyIdentifierImpl.java.
     * @param impliedParam Parameter that indicates whether the data object(s) being signed and other external data imply the signature policy (true)
     * or not (false).
     */
    public SignaturePolicyIdentifierImpl(boolean impliedParam) {
	implied = impliedParam;
    }

    /**
     * Constructor method for the class SignaturePolicyIdentifierImpl.java.
     * @param impliedParam Parameter that indicates whether the data object(s) being signed and other external data imply the signature policy (true)
     * or not (false).
     * @param identifierParam Parameter that represents the identifier of the signature policy.
     * @param descriptionParam Parameter that represents the description.
     * @param qualifierParam Parameter that represents the qualifier.
     * @param digestValue Parameter that represents the hash encoded on Base 64.
     */
    public SignaturePolicyIdentifierImpl(boolean impliedParam, String identifierParam, String descriptionParam, String qualifierParam, String digestValue) {
	super();
	implied = impliedParam;
	identifier = identifierParam;
	description = descriptionParam;
	qualifier = qualifierParam;
	hashBase64 = digestValue;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#setIdentifier(java.lang.String)
     */
    public final void setIdentifier(String identifierParam) {
	identifier = identifierParam;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#isImplied()
     */
    public final boolean isImplied() {
	return implied;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#setImplied(boolean)
     */
    public final void setImplied(boolean impliedParam) {
	implied = impliedParam;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#getIdentifier()
     */
    public final String getIdentifier() {
	return identifier;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#getHashBase64()
     */
    public final String getHashBase64() {
	return hashBase64;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#setHashBase64(java.lang.String)
     */
    public final void setHashBase64(String hashBase64Param) {
	hashBase64 = hashBase64Param;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#getDescription()
     */
    public final String getDescription() {
	return description;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#setDescription(java.lang.String)
     */
    public final void setDescription(String descrParam) {
	description = descrParam;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#getQualifier()
     */
    public final String getQualifier() {
	return qualifier;
    }

    /**
     * {@inheritDoc}
     * @see net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier#setQualifier(java.lang.String)
     */
    public final void setQualifier(String qualifierParam) {
	qualifier = qualifierParam;
    }
}
