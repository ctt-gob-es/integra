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
 * <b>File:</b><p>es.gob.afirma.tsl.elements.json.ByteArrayB64.java.</p>
 * <b>Description:</b><p>Class that represents an element transformation between an array of bytes
 * and a base 64 string representation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/10/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/10/2020.
 */
package es.gob.afirma.tsl.elements.json;

import java.io.Serializable;

import org.apache.commons.codec.binary.Base64;

import es.gob.afirma.tsl.utils.UtilsStringChar;


/** 
 * <p>Class that represents an element transformation between an array of bytes
 * and a base 64 string representation.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/10/2020.
 */
public class ByteArrayB64 implements Serializable {

    /**
     * Attribute that represents . 
     */
    private static final long serialVersionUID = -7670654848257482164L;
    /**
	 * Attribute that represents the byte array.
	 */
	private byte[ ] byteArray = null;

	/**
	 * Constructor method for the class ByteArrayB64.java.
	 */
	private ByteArrayB64() {
		super();
	}

	/**
	 * Constructor method for the class ByteArrayB64.java.
	 * @param byteArrayParam Byte array to set.
	 */
	public ByteArrayB64(byte[ ] byteArrayParam) {
		this();
		if (byteArrayParam != null) {
			this.byteArray = byteArrayParam;
		}
	}

	/**
	 * Constructor method for the class ByteArrayB64.java.
	 * @param byteArrayB64String Byte array in B64 String representation.
	 */
	public ByteArrayB64(String byteArrayB64String) {

		this();
		if (!UtilsStringChar.isNullOrEmptyTrim(byteArrayB64String)) {
			byteArray = Base64.decodeBase64(byteArrayB64String);
		}

	}

	/**
	 * Gets the value of the attribute {@link #byteArray}.
	 * @return the value of the attribute {@link #byteArray}.
	 */
	public byte[ ] getByteArray() {
		return byteArray;
	}

	/**
	 * Sets the value of the attribute {@link #byteArray}.
	 * @param byteArrayParam The value for the attribute {@link #byteArray}.
	 */
	public void setByteArray(byte[ ] byteArrayParam) {
		this.byteArray = byteArrayParam;
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {

		String result = null;

		if (byteArray != null) {
			result = Base64.encodeBase64String(byteArray);
		}

		return result;
	}

}
