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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.connection.auth.JCIFSEngine.java.</p>
 * <b>Description:</b><p>Class that implements {@link NTLMEngine}.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 19/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 19/11/2020.
 */

package es.gob.afirma.tsl.utils.connection.auth;

import java.io.IOException;

import org.apache.http.impl.auth.NTLMEngine;
import org.apache.http.impl.auth.NTLMEngineException;

import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.util.Base64;

/**
 * <p>Class that implements {@link NTLMEngine}.</p>
 * <b>Project:</b><p>Platform for detection and validation of certificates recognized in European TSL.</p>
 * @version 1.0, 17/11/2020.
 */
public class JCIFSEngine implements NTLMEngine {

	/**
	 * Attribute that represents type 1 flags.
	 */
	private static final int TYPE_1_FLAGS = NtlmFlags.NTLMSSP_NEGOTIATE_56 | NtlmFlags.NTLMSSP_NEGOTIATE_128 | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM2 | NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NtlmFlags.NTLMSSP_REQUEST_TARGET;

	/**
	 * {@inheritDoc}
	 * @see org.apache.http.impl.auth.NTLMEngine#generateType1Msg(java.lang.String, java.lang.String)
	 */
	public String generateType1Msg(final String domain, final String workstation) throws NTLMEngineException {
		final Type1Message type1Message = new Type1Message(TYPE_1_FLAGS, domain, workstation);
		return Base64.encode(type1Message.toByteArray());
	}

	/**
	 * {@inheritDoc}
	 * @see org.apache.http.impl.auth.NTLMEngine#generateType3Msg(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public String generateType3Msg(final String username, final String password, final String domain, final String workstation, final String challenge) throws NTLMEngineException {
		Type2Message type2Message;
		try {
			type2Message = new Type2Message(Base64.decode(challenge));
		} catch (final IOException exception) {
			throw new NTLMEngineException("Invalid NTLM type 2 message", exception);
		}
		final int type2Flags = type2Message.getFlags();
		final int type3Flags = type2Flags & (0xffffffff ^ (NtlmFlags.NTLMSSP_TARGET_TYPE_DOMAIN | NtlmFlags.NTLMSSP_TARGET_TYPE_SERVER));
		final Type3Message type3Message = new Type3Message(type2Message, password, domain, username, workstation, type3Flags);
		return Base64.encode(type3Message.toByteArray());
	}

}
