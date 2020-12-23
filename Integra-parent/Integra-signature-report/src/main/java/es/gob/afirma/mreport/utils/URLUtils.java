// Copyright (C) 2018, Gobierno de España
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
 * <b>File:</b><p>es.gob.signaturereport.tools.URLUtils.java.</p>
 * <b>Description:</b><p> Utility class for URL generation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>28/08/2020.</p>
 * @author Spanish Government.
 * @version 1.0, 28/08/2020.
 */
package es.gob.afirma.mreport.utils;

/** 
 * <p>Utility class for URL generation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 28/08/2020.
 */
public final class URLUtils {

	/**
	 * Constructor method for the class URLUtils.java. 
	 */
	private URLUtils() {
	}

	/**
	 * Create a RFC2397 "data" URL.	
	 * @param format		Content type of data.
	 * @param encodedData	Base64 encoded data.
	 * @return RFC2397 "data" URL.
	 */
	public static String createRFC2397URL(String format, String encodedData) {
		return "url(&quot;data:" + format + ";base64," + encodedData.trim().replaceAll("\n", "").replaceAll("\t", "").replaceAll("\r", "") + ";&quot;)";
	}
}
