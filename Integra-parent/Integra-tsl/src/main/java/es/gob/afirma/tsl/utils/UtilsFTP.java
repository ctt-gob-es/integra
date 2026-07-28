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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsFTP.java.</p>
 * <b>Description:</b><p>Utilities class relating to connections and FTP/S protocol.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 18/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 18/11/2020.
 */
package es.gob.afirma.tsl.utils;

import java.net.URI;
import java.net.URISyntaxException;

/** 
 * <p>Utilities class relating to connections and FTP/S protocol.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 18/11/2020.
 */
public final class UtilsFTP {
    /**
	 * Constant attribute that represents the representation string of the scheme http.
	 */
	public static final String FTP_SCHEME = "ftp";

	/**
	 * Constructor method for the class UtilsFTP.java.
	 */
	private UtilsFTP() {
		super();
	}

	/**
	 * This method determines whether a given URI scheme is FTP.
	 * @param uriString String representation of the URI to analyze.
	 * @return <i>true</i> if the scheme of the URI is FTP, otherwise <i>false</i>.
	 */
	public static boolean isUriOfSchemeFTP(String uriString) {

		boolean result = false;

		if (!UtilsStringChar.isNullOrEmptyTrim(uriString)) {

			try {

				URI uri = new URI(uriString);
				result = isUriOfSchemeFTP(uri);

			} catch (URISyntaxException e) {
				result = false;
			}

		}

		return result;

	}

	/**
	 * This method determines whether a given URI scheme is FTP.
	 * @param uri Representation of the URI to analyze.
	 * @return <i>true</i> if the scheme of the URI is FTP, otherwise <i>false</i>.
	 */
	public static boolean isUriOfSchemeFTP(URI uri) {

		boolean result = false;

		if (uri != null) {

			String scheme = uri.getScheme();
			if (!UtilsStringChar.isNullOrEmptyTrim(scheme) && scheme.equalsIgnoreCase(FTP_SCHEME)) {
				result = true;
			}

		}

		return result;

	}

}
