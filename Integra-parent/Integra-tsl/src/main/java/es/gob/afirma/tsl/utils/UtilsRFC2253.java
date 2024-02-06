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
 * <b>File:</b><p>es.gob.afirma.tsl.utils.UtilsRFC2253.java.</p>
 * <b>Description:</b><p>Class that provides functionality related with: <b>RFC 2253</b>: Lightweight Directory Access Protocol (v3).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 11/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 11/11/2020.
 */
package es.gob.afirma.tsl.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/** 
 * <p>Class that provides functionality related with: <b>RFC 2253</b>: Lightweight Directory Access Protocol (v3).</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 11/11/2020.
 */
public final class UtilsRFC2253 {

    /**
	 * Constant attribute that represents the string <i>"UTF-8"</i>.
	 */
	private static final String UTF_8 = "UTF-8";

	/**
	 * Constant attribute that represents the string to identify the mask for hexadecimal characters.
	 */
	public static final String HEXCHAR = "[0-9a-fA-F]";

	/**
	 * Constant attribute that represents the string to identify the mask for special characters.
	 */
	public static final String SPECIAL = "[\\,\\=\\+\\<\\>\\#\\;]";

	/**
	 * Constant attribute that represents the string to identify the mask for quotes character.
	 */
	public static final String QUOTATION = "\\'";

	/**
	 * Constant attribute that represents the string to identify the mask for slash character.
	 */
	public static final String SLASH = "\\\\";

	/**
	 * Constant attribute that represents the string to identify the regular expression for a hexadecimal pair.
	 */
	public static final String HEXPAIR_REGEXP = "(" + HEXCHAR + "{2})";

	/**
	 * Constant attribute that represents the string to identify the regular expression for a pair.
	 */
	public static final String PAIR_REGEXP = "(" + SLASH + "([" + SPECIAL + SLASH + QUOTATION + HEXPAIR_REGEXP + "]){1})";

	/**
	 * Constant attribute that represents the string to identify the regular expression for a sequence of a pair.
	 */
	public static final String PAIRSEQUENCE_REGEXP = "(" + PAIR_REGEXP + "{1,})";

	/**
	 * Constant attribute that represents the string to identify the pattern for a sequence of a pair.
	 */
	private static final Pattern PAIRSEQUENCE_PATTERN = Pattern.compile(PAIRSEQUENCE_REGEXP);

	/**
	 * Constant attribute that represents the string to identify the pattern for a pair.
	 */
	private static final Pattern PAIR_PATTERN = Pattern.compile(PAIR_REGEXP);

	/**
	 * Constant attribute that represents the string to identify the pattern for a hexadecimal pair.
	 */
	public static final Pattern HEXPAIR_PATTERN = Pattern.compile(HEXPAIR_REGEXP);

	/**
	 * Attribute that represents the unique instance of the {@link UtilsRFC2253}.
	 */
	private static UtilsRFC2253 instance = null;

	/**
	 * Constructor method for the class UtilsRFC2253.java.
	 */
	private UtilsRFC2253() {
		super();
	}

	/**
	 * Gets the unique instance of the {@link UtilsRFC2253}.
	 * @return the unique instance of the {@link UtilsRFC2253}.
	 */
	public static UtilsRFC2253 getInstance() {
		if (instance == null) {
			instance = new UtilsRFC2253();
		}
		return instance;
	}

	/**
	 * Method that translates a UTF-8 string.
	 * @param str Parameter that represents the string to process.
	 * @return the processed string.
	 * @throws IOException If the method fails.
	 */
	public String unscape(String str) throws IOException {
		byte[ ] srcByteArray = str.getBytes(UTF_8);
		ByteArrayOutputStream dstBAOS = new ByteArrayOutputStream(srcByteArray.length);
		Matcher pairSequencePattern = PAIRSEQUENCE_PATTERN.matcher(str);
		int last = 0;
		try {
			while (pairSequencePattern.find(last)) {
				int iPos = pairSequencePattern.start();
				int fPos = pairSequencePattern.end();

				dstBAOS.write(srcByteArray, last, iPos - last);

				while (pairSequencePattern.find(fPos) && pairSequencePattern.start() == fPos + 1) {
					// sequenceLen = sequenceLen + (pairSequencePattern.end() -
					// pairSequencePattern.start())+1;
					fPos = pairSequencePattern.end();
				}
				String unescapedPairSequence = unescapePairSequence(srcByteArray, iPos, fPos - iPos + 1);

				dstBAOS.write(unescapedPairSequence.getBytes(UTF_8));
				last = fPos + 1;
				if (last >= str.length()) {
					break;
				}
			}
			if (last < str.length()) {
				dstBAOS.write(srcByteArray, last, srcByteArray.length - last);
			}
		} finally {
			// Cerramos recursos
			UtilsResourcesCommons.safeCloseOutputStream(dstBAOS);
		}
		String unescaped = new String(dstBAOS.toByteArray(), UTF_8);

		return unescaped;
	}

	/**
	 * Method that translates a UTF-8 pair sequence.
	 * @param src Parameter that represents the bytes to be decoded into characters.
	 * @param pos Parameter that represents the index of the first byte to decode.
	 * @param len Parameter that represents the number of bytes to decode.
	 * @return the decoded string.
	 * @throws UnsupportedEncodingException If there is some error encoding the String.
	 */
	private String unescapePairSequence(byte[ ] src, int pos, int len) throws UnsupportedEncodingException {

		int lenParam = len;

		if (pos + lenParam >= src.length) {
			lenParam = src.length - pos;
		}
		String escapedPairSequence = new String(src, pos, lenParam, UTF_8);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Matcher pairPattern = PAIR_PATTERN.matcher(escapedPairSequence);
		int last = 0;
		try {
			while (pairPattern.find(last)) {
				int iPos = pairPattern.start();
				// int fPos = pairPattern.end();
				int fPos = pairPattern.end() >= escapedPairSequence.length() ? escapedPairSequence.length() - 1 : pairPattern.end();

				if (isHexChar((char) src[pos + iPos + 1])) {
					// \C3 \C4
					baos.write(hexToByte((char) src[pos + iPos + 1], (char) src[pos + iPos + 2]));
				} else {
					baos.write(src, pos + iPos + 1, fPos - iPos);
				}

				last = fPos + 1;
				if (last >= escapedPairSequence.length()) {
					break;
				}
			}
		} finally {
			// Cerramos recursos
			UtilsResourcesCommons.safeCloseOutputStream(baos);
		}
		return new String(baos.toByteArray(), UTF_8);
	}

	/**
	 * Method that translates two hexadecimal characters to a byte.
	 * @param b1 Parameter that represents the first character to process.
	 * @param b2 Parameter that represents the second character to process.
	 * @return a byte that represents the pair of characters.
	 * @throws UnsupportedEncodingException If the method fails.
	 */
	private byte hexToByte(char b1, char b2) throws UnsupportedEncodingException {
		return (byte) (NumberConstants.INT_16 * valueHex(b1) + valueHex(b2));
	}

	/**
	 * Method that checks whether a character is a hexadecimal character (true) or not (false).
	 * @param c Parameter that represents the character to process.
	 * @return a boolean that indicates whether a character is a hexadecimal character (true) or not (false).
	 */
	private boolean isHexChar(char c) {
		boolean result = c >= '0' && c <= '9';
		result = result || c >= 'A' && c <= 'F';
		result = result || c >= 'a' && c <= 'f';
		return result;
	}

	/**
	 * Method that obtains the hexadecimal value for certain character.
	 * @param b Parameter that represents the character to process.
	 * @return the hexadecimal value associated to the character.
	 * @throws UnsupportedEncodingException If the method fails.
	 */
	private int valueHex(char b) throws UnsupportedEncodingException {
		if (b >= '0' && b <= '9') {
			return b - '0';
		}

		if (b >= 'A' && b <= 'F') {
			return b - 'A' + NumberConstants.INT_10;
		}

		if (b >= 'a' && b <= 'f') {
			return b - 'a' + NumberConstants.INT_10;
		}

		throw new UnsupportedEncodingException("Language.getFormatResCommonsUtilGeneral(ICommonsUtilGeneralMessages.UTILS_RFC_2253_000, new Object[ ] { b })");
	}


}
