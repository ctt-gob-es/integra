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
* <b>File:</b><p>es.gob.afirma.tsl.utils.connection.auth.JCIFSNTLMSchemeFactory.java.</p>
 * <b>Description:</b><p>Class that implements {@link AuthSchemeProvider}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 17/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 17/11/2020.
 */

package es.gob.afirma.tsl.utils.connection.auth;

import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.impl.auth.NTLMScheme;
import org.apache.http.protocol.HttpContext;

/**
 * <p>Class that implements {@link AuthSchemeProvider}.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.0, 17/11/2020.
 */
public class JCIFSNTLMSchemeFactory implements AuthSchemeProvider {

	/**
	 * {@inheritDoc}
	 * @see org.apache.http.auth.AuthSchemeProvider#create(org.apache.http.protocol.HttpContext)
	 */
	@Override
	public AuthScheme create(HttpContext context) {
		return new NTLMScheme(new JCIFSEngine());
	}

}
