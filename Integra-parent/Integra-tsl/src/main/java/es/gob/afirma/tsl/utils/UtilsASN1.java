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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsASN1.java.</p>
 * <b>Description:</b><p>Class that contains all utilities methods used in ASN1 Objects.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 16/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.2, 19/09/2022.
 */
package es.gob.afirma.tsl.utils;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;

import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.i18n.ILogTslConstant;
import es.gob.afirma.tsl.i18n.Language;

/** 
 * <p>Class that contains all utilities methods used in ASN1 Objects.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.2, 19/09/2022.
 */
public final class UtilsASN1 {

    /**
	 * Constructor method for the class ASN1Utilities.java.
	 */
	private UtilsASN1() {
		super();
	}

	
	/**
	 * Method that obtains the content of a {@link X500Principal} object on string format.
	 * @param name Parameter that represents the object to be processed.
	 * @return the content of the {@link X500Principal} object on string format.
	 * @throws CommonUtilsException If the method fails.
	 */
	public static String toString(X500Principal name) throws CommonUtilsException {
	    String result = null;
	    if(name != null){

		try {
			X500Name x500Name = X500Name.getInstance(name.getEncoded());
			String rfcName = (String) x500Name.toString();
			if (rfcName != null) {
				result = rfcName;
			} else {
				result = name.getName(X500Principal.RFC2253);
			}
		} catch (Exception e) {
			throw new CommonUtilsException(Language.getResIntegraTsl(ILogTslConstant.UA_LOG002), e);
		}

	    }
		return result;
	}

}
