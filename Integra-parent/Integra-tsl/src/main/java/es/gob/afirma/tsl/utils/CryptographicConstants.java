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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.CryptographicConstants.java.</p>
 * <b>Description:</b><p>Class that contains references and values to differents cryptographic constants.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.utils;


/** 
 * <p>Class that contains references and values to differents cryptographic constants.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public final class CryptographicConstants {
    /**
	 * Constructor method for the class CryptographicConstants.java.
	 */
	private CryptographicConstants() {
		super();
	}

	/**
	 * Constant attribute that represents the string to identify the hash algorithm: <code>MD2</code>.
	 */
	public static final String HASH_ALGORITHM_MD2 = "MD2";

	/**
	 * Constant attribute that represents the string to identify the hash algorithm: <code>MD4</code>.
	 */
	public static final String HASH_ALGORITHM_MD4 = "MD4";

	/**
	 * Constant attribute that represents the string to identify the hash algorithm: <code>MD5</code>.
	 */
	public static final String HASH_ALGORITHM_MD5 = "MD5";

	/**
	 * Constant attribute that represents the string to identify the hash algorithm: <code>SHA</code>.
	 */
	public static final String HASH_ALGORITHM_SHA = "SHA";

	/**
	 * Constant attribute that represents the string to identify the hash algorithm: <code>SHA1</code>.
	 */
	public static final String HASH_ALGORITHM_SHA1 = "SHA1";

	/**
	 * Constant attribute that represents the string to identify the hash algorithm: <code>SHA256</code>.
	 */
	public static final String HASH_ALGORITHM_SHA256 = "SHA256";

	/**
	 * Constant attribute that represents the string to identify the hash algorithm: <code>SHA384</code>.
	 */
	public static final String HASH_ALGORITHM_SHA384 = "SHA384";

	/**
	 * Constant attribute that represents the string to identify the hash algorithm: <code>SHA512</code>.
	 */
	public static final String HASH_ALGORITHM_SHA512 = "SHA512";

	/**
	 * Constant attribute that represents the URI string to identify the hash algorithm for signatures on XML format: <code>MD5</code>.
	 */
	public static final String HASH_ALGORITHM_XML_MD5 = "http://www.w3.org/2001/04/xmldsig-more#md5";

	/**
	 * Constant attribute that represents the URI string to identify the hash algorithm for signatures on XML format: <code>SHA</code>.
	 */
	public static final String HASH_ALGORITHM_XML_SHA = "http://www.w3.org/2000/09/xmldsig#sha1";

	/**
	 * Constant attribute that represents the URI string to identify the hash algorithm for signatures on XML format: <code>SHA1</code>.
	 */
	public static final String HASH_ALGORITHM_XML_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

	/**
	 * Constant attribute that represents the URI string to identify the hash algorithm for signatures on XML format: <code>SHA256</code>.
	 */
	public static final String HASH_ALGORITHM_XML_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

	/**
	 * Constant attribute that represents the URI string to identify the hash algorithm for signatures on XML format: <code>SHA384</code>.
	 */
	public static final String HASH_ALGORITHM_XML_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";

	/**
	 * Constant attribute that represents the URI string to identify the hash algorithm for signatures on XML format: <code>SHA512</code>.
	 */
	public static final String HASH_ALGORITHM_XML_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";


}
