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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsBytesAndBits.java.</p>
 * <b>Description:</b><p>Class that provides methods to work and transforms bytes to bits
 * and vice versa.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.utils;

import java.util.BitSet;



/** 
 * <p>Class that provides methods to work and transforms bytes to bits
 * and vice versa.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public final class UtilsBytesAndBits {
    /**
	 * Constructor method for the class UtilsBytesAndBits.java.
	 */
	private UtilsBytesAndBits() {
		super();
	}

	/**
	 * Transforms the input bit set to a byte array.
	 * @param bits Input bit set to transform.
	 * @return a byte array with all the input bits, or <code>null</code> if the input is <code>null</code>.
	 */
	public static byte[ ] bitToByteArray(BitSet bits) {

		byte[ ] bytes = null;

		if (bits != null) {
			bytes = new byte[(bits.length() + NumberConstants.INT_7) / NumberConstants.INT_8];
			for (int i = 0; i < bits.length(); i++) {
				if (bits.get(i)) {
					bytes[bytes.length - i / NumberConstants.INT_8 - 1] |= 1 << i % NumberConstants.INT_8;
				}
			}
		}

		return bytes;

	}

	/**
	 * Transforms the input byte to a bit set.
	 * @param b Input byte to transform.
	 * @return a bit set extracted from the input byte.
	 */
	public static BitSet byteToBits(byte b) {
		byte aux = b;
		BitSet bits = new BitSet(NumberConstants.INT_8);
		for (int i = 0; i < NumberConstants.INT_8; i++) {
			bits.set(i, (aux & 1) == 1);
			aux >>= 1;
		}
		return bits;
	}

	/**
	 * Transforms the input byte array to a bit set.
	 * @param byteArray Input byte array to transform.
	 * @return a bit set with all the input bytes, or <code>null</code> if the input is <code>null</code>.
	 */
	public static BitSet byteArrayToBits(byte[ ] byteArray) {

		BitSet bits = null;
		if (byteArray != null) {
			bits = new BitSet(byteArray.length * NumberConstants.INT_8);
			for (int i = 0; i < byteArray.length; i++) {

				byte b = byteArray[i];
				int bitBasePosition = i * NumberConstants.INT_8;
				for (int j = 0; j < NumberConstants.INT_8; j++) {
					bits.set(bitBasePosition + j, (b & 1) == 1);
					b >>= 1;
				}

			}
		}

		return bits;

	}

}
