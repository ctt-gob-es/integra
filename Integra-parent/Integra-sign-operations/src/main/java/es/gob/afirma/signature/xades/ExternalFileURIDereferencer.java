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
 * <b>File:</b><p>es.gob.afirma.signature.xades.ExternalFileURIDereferencer.java.</p>
 * <b>Description:</b><p>Class that allows to resolve the URI associated to an external file signed by a XML signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>01/02/2016.</p>
 * @author Gobierno de España.
 * @version 1.2, 04/03/2020.
 */
package es.gob.afirma.signature.xades;


import org.w3c.dom.Attr;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;

/**
 * <p>Class that allows to resolve the URI associated to an external file signed by a XML signature.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 04/03/2020.
 */
public class ExternalFileURIDereferencer extends ResourceResolverSpi {

    /**
     * Attribute that represents the external file.
     */
    private byte[ ] externalFile = null;

    /**
     * Attribute that represents the name of the external file.
     */
    private String externalFileName = null;

    /**
     * Constructor method for the class ExternalFileURIDereferencer.java.
     * @param externalFileParam Parameter that represents the external file.
     * @param externalFileNameParam Parameter that represents the name of the external file.
     */
    public ExternalFileURIDereferencer(byte[ ] externalFileParam, String externalFileNameParam) {
	if (externalFileParam != null) {
	    this.externalFile = externalFileParam.clone();
	}
	this.externalFileName = externalFileNameParam;
    }

    /**
     * {@inheritDoc}
     * @see org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineResolve(org.w3c.dom.Attr, java.lang.String)
     */
    @Override
    public final XMLSignatureInput engineResolve(Attr uriAttr, String baseURI) throws ResourceResolverException {
	String uri = uriAttr.getNodeValue();
	XMLSignatureInput sigInput = new XMLSignatureInput(externalFile);
	sigInput.setSourceURI(uri);
	return sigInput;

    }

    /**
     * {@inheritDoc}
     * @see org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineCanResolve(org.w3c.dom.Attr, java.lang.String)
     */
    @Override
    public final boolean engineCanResolve(Attr uriAttr, String baseURI) {
	if (uriAttr.getTextContent().equals(externalFileName)) {
	    return true;
	}
	return false;
    }

}
