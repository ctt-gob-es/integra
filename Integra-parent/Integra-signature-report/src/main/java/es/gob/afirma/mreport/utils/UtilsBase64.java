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
// https://eupl.eu/1.1/es/

/** 
 * <b>File:</b><p>es.gob.signaturereport.tools.UtilsBase64.java.</p>
 * <b>Description:</b><p> Utility class for encoding in base 64.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/08/2020.</p>
 * @author Spanish Government.
 * @version 1.1, 18/04/2022.
 */
package es.gob.afirma.mreport.utils;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import es.gob.afirma.mreport.logger.Logger;

import es.gob.afirma.mreport.i18.ILogConstantKeys;
import es.gob.afirma.mreport.i18.Language;

/** 
 * <p>Utility class for encoding in base 64.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 25/08/2020.
 */
public class UtilsBase64 {
	/**
	 * Attribute that represents the object that manages the log of the class. 
	 */
	private static final Logger logger = Logger.getLogger(UtilsBase64.class);

	/** 
	 * <p>Class for storing the encoded bytes.</p>
	 * <b>Project:</b><p>Horizontal platform to generation signature reports in legible format.</p>
	 * @version 1.0, 21/11/2011.
	 */
	public class OutputStream extends FilterOutputStream {

		/**
		 * {@inheritDoc}
		 * @see java.io.FilterOutputStream#write(int)
		 */
		public void write(int i) throws IOException {
			buffer[position++] = (byte) i;
			if (position >= bufferLength) {
				if (encode) {
					super.out.write(encode3to4(buffer, bufferLength));
					lineLength += 4;
					if (lineLength >= 76) {
						super.out.write(10);
						lineLength = 0;
					}
				} else {
					super.out.write(decode4to3(buffer));
				}
				position = 0;
			}
		}

		/**
		 * {@inheritDoc}
		 * @see java.io.FilterOutputStream#write(byte[], int, int)
		 */
		public void write(byte abyte0[], int i, int j) throws IOException {
			for (int k = 0; k < j; k++) {
				write(abyte0[i + k]);
			}

		}

		/**
		 * {@inheritDoc}
		 * @see java.io.FilterOutputStream#flush()
		 */
		public void flush() throws IOException {
			if (position > 0) {
				if (encode) {
					super.out.write(encode3to4(buffer, position));
				} else {
					throw new IOException(Language.getResSigReport(ILogConstantKeys.UTIL_003));
				}
			}
			super.flush();
			super.out.flush();
		}

		/**
		 * {@inheritDoc}
		 * @see java.io.FilterOutputStream#close()
		 */
		public void close() throws IOException {
			flush();
			super.close();
			super.out.close();
			buffer = null;
			super.out = null;
		}

		/**
		 * Attribute that indicates if the bytes is encoded. 
		 */
		private boolean encode;
		/**
		 * Attribute that represents the position. 
		 */
		private int position;
		/**
		 * Attribute that represents the buffer. 
		 */
		private byte buffer[];
		/**
		 * Attribute that represents the buffer length. 
		 */
		private int bufferLength;
		/**
		 * Attribute that represents the line length. 
		 */
		private int lineLength;

		/**
		 * Constructor method for the class OutputStream.java.
		 * @param outputstream Output stream.
		 */
		public OutputStream(java.io.OutputStream outputstream) {
			this(outputstream, true);
		}

		/**
		 * Constructor method for the class UtilsBase64.java.
		 * @param outputstream Output stream.
		 * @param flag 	Indicates if the bytes is encoded.
		 */
		public OutputStream(java.io.OutputStream outputstream, boolean flag) {
			super(outputstream);
			encode = flag;
			bufferLength = flag ? 3 : 4;
			buffer = new byte[bufferLength];
			position = 0;
			lineLength = 0;
		}
	}

	/** 
	 * <p>Class for reading the encoded bytes..</p>
	 * <b>Project:</b><p>Horizontal platform to generation signature reports in legible format.</p>
	 * @version 1.0, 21/11/2011.
	 */
	public class InputStream extends FilterInputStream {

		/**
		 * {@inheritDoc}
		 * @see java.io.FilterInputStream#read()
		 */
		public int read() throws IOException {
			if (position < 0) {
				if (encode) {
					byte abyte0[] = new byte[3];
					numSigBytes = 0;
					for (int i = 0; i < 3; i++) {
						try {
							int k = super.in.read();
							if (k >= 0) {
								abyte0[i] = (byte) k;
								numSigBytes++;
							}
						} catch (IOException ioexception) {
							if (i == 0) {
								throw ioexception;
							}
						}
					}

					if (numSigBytes > 0) {
						encode3to4(abyte0, 0, numSigBytes, buffer, 0);
						position = 0;
					}
				} else {
					byte abyte1[] = new byte[4];
					int j = 0;
					for (j = 0; j < 4; j++) {
						int l = 0;
						do {
							l = super.in.read();
						}
						while (l >= 0 && UtilsBase64.DECODABET[l & 0x7f] < -5);
						if (l < 0) {
							break;
						}
						abyte1[j] = (byte) l;
					}

					if (j == 4) {
						numSigBytes = decode4to3(abyte1, 0, buffer, 0);
						position = 0;
					}
				}
			}
			if (position >= 0) {
				if (position >= numSigBytes) {
					return -1;
				}
				byte byte0 = buffer[position++];
				if (position >= bufferLength) {
					position = -1;
				}
				return byte0;
			} else {
				return -1;
			}
		}

		/**
		 * {@inheritDoc}
		 * @see java.io.FilterInputStream#read(byte[], int, int)
		 */
		public int read(byte abyte0[], int i, int j) throws IOException {
			int k;
			for (k = 0; k < j; k++) {
				int l = read();
				if (l < 0) {
					return -1;
				}
				abyte0[i + k] = (byte) l;
			}

			return k;
		}

		/**
		 * Attribute that indicates if the bytes is encoded. 
		 */
		private boolean encode;
		/**
		 * Attribute that represents the reading position. 
		 */
		private int position;
		/**
		 * Attribute that represents the buffer for the reading. 
		 */
		private byte buffer[];
		/**
		 * Attribute that represents the buffer length. 
		 */
		private int bufferLength;
		/**
		 * Attribute that represents the offset. 
		 */
		private int numSigBytes;

		/**
		 * Constructor method for the class InputStream.java.
		 * @param inputstream Input stream.
		 */
		public InputStream(java.io.InputStream inputstream) {
			this(inputstream, false);
		}

		/**
		 * Constructor method for the class InputStream.java.
		 * @param inputstream	Input stream
		 * @param flag Parameter that indicates if the bytes is encoded. 
		 */
		public InputStream(java.io.InputStream inputstream, boolean flag) {
			super(inputstream);
			encode = flag;
			bufferLength = flag ? 4 : 3;
			buffer = new byte[bufferLength];
			position = -1;
		}
	}

	/**
	 * Constructor method for the class UtilsBase64.java. 
	 */
	public UtilsBase64() {
	}

	

	
	private byte[ ] encode3to4(byte abyte0[], int i) {
		byte abyte1[] = new byte[4];
		encode3to4(abyte0, 0, i, abyte1, 0);
		return abyte1;
	}

	private byte[ ] encode3to4(byte abyte0[], int i, int j, byte abyte1[], int k) {
		int l = (j <= 0 ? 0 : abyte0[i] << 24 >>> 8) | (j <= 1 ? 0 : abyte0[i + 1] << 24 >>> 16) | (j <= 2 ? 0 : abyte0[i + 2] << 24 >>> 24);
		switch (j) {
			case 3: // '\003'
				abyte1[k] = ALPHABET[l >>> 18];
				abyte1[k + 1] = ALPHABET[l >>> 12 & 0x3f];
				abyte1[k + 2] = ALPHABET[l >>> 6 & 0x3f];
				abyte1[k + 3] = ALPHABET[l & 0x3f];
				return abyte1;

			case 2: // '\002'
				abyte1[k] = ALPHABET[l >>> 18];
				abyte1[k + 1] = ALPHABET[l >>> 12 & 0x3f];
				abyte1[k + 2] = ALPHABET[l >>> 6 & 0x3f];
				abyte1[k + 3] = 61;
				return abyte1;

			case 1: // '\001'
				abyte1[k] = ALPHABET[l >>> 18];
				abyte1[k + 1] = ALPHABET[l >>> 12 & 0x3f];
				abyte1[k + 2] = 61;
				abyte1[k + 3] = 61;
				return abyte1;
		}
		return abyte1;
	}

	/**
	 * Encodes the supplied object.
	 * @param serializable	Serializable object.
	 * @return	Encoded result.
	 */
	public String encodeObject(Serializable serializable) {
		ByteArrayOutputStream bytearrayoutputstream = null;
		OutputStream outputstream = null;
		ObjectOutputStream objectoutputstream = null;
		try {
			bytearrayoutputstream = new ByteArrayOutputStream();
			outputstream = new OutputStream(bytearrayoutputstream, true);
			objectoutputstream = new ObjectOutputStream(outputstream);
			objectoutputstream.writeObject(serializable);
		} catch (IOException ioexception) {
			return null;
		} finally {
			try {
				objectoutputstream.close();
			} catch (Exception exception1) {}
			try {
				outputstream.close();
			} catch (Exception exception2) {}
			try {
				bytearrayoutputstream.close();
			} catch (Exception exception3) {}
		}
		return new String(bytearrayoutputstream.toByteArray());
	}

	/**
	 *	Encodes the supplied bytes. 
	 * @param abyte0	Arrays of bytes.
	 * @return	Encoded result.
	 */
	public String encodeBytes(byte abyte0[]) {
		return encodeBytes(abyte0, 0, abyte0.length);
	}

	/**
	 * Encodes the supplied bytes in the specified range.
	 * @param abyte0	Array of bytes to encode.
	 * @param i	Started index.
	 * @param j	Finished index.
	 * @return	Encoded result.
	 */
	public String encodeBytes(byte abyte0[], int i, int j) {
		int k = j * 4 / 3;
		byte abyte1[] = new byte[k + (j % 3 <= 0 ? 0 : 4) + k / 76];
		int l = 0;
		int i1 = 0;
		int j1 = j - 2;
		int k1 = 0;
		while (l < j1) {
			encode3to4(abyte0, l, 3, abyte1, i1);
			if ((k1 += 4) == 76) {
				abyte1[i1 + 4] = 10;
				i1++;
				k1 = 0;
			}
			l += 3;
			i1 += 4;
		}
		if (l < j) {
			encode3to4(abyte0, l, j - l, abyte1, i1);
			i1 += 4;
		}
		return new String(abyte1, 0, i1);
	}

	/**
	 * Encodes the supplied string.
	 * @param s	string.
	 * @return	Encoded result.
	 */
	public String encodeString(String s) {
		return encodeBytes(s.getBytes());
	}

	private byte[ ] decode4to3(byte abyte0[]) {
		byte abyte1[] = new byte[3];
		int i = decode4to3(abyte0, 0, abyte1, 0);
		byte abyte2[] = new byte[i];
		System.arraycopy(abyte1, 0, abyte2, 0, i);
		return abyte2;
	}

	private int decode4to3(byte abyte0[], int i, byte abyte1[], int j) {
		if (abyte0[i + 2] == 61) {
			int k = DECODABET[abyte0[i]] << 24 >>> 6 | DECODABET[abyte0[i + 1]] << 24 >>> 12;
			abyte1[j] = (byte) (k >>> 16);
			return 1;
		}
		if (abyte0[i + 3] == 61) {
			int l = DECODABET[abyte0[i]] << 24 >>> 6 | DECODABET[abyte0[i + 1]] << 24 >>> 12 | DECODABET[abyte0[i + 2]] << 24 >>> 18;
			abyte1[j] = (byte) (l >>> 16);
			abyte1[j + 1] = (byte) (l >>> 8);
			return 2;
		} else {
			int i1 = DECODABET[abyte0[i]] << 24 >>> 6 | DECODABET[abyte0[i + 1]] << 24 >>> 12 | DECODABET[abyte0[i + 2]] << 24 >>> 18 | DECODABET[abyte0[i + 3]] << 24 >>> 24;
			abyte1[j] = (byte) (i1 >> 16);
			abyte1[j + 1] = (byte) (i1 >> 8);
			abyte1[j + 2] = (byte) i1;
			return 3;
		}
	}

	/**
	 * Decodes the supplied string.
	 * @param s	Encoded string. 
	 * @return	Arrays of bytes.
	 */
	public byte[ ] decode(String s) {

		byte[ ] result = null;
		s = s.replaceAll("\\r\\n", "");
		s = s.replaceAll("\\n", "");
		byte abyte0[] = s.getBytes();

		if (abyte0.length % 4 == 0) {

			result = decode(abyte0, 0, abyte0.length);

		} else {

			logger.error(Language.getResSigReport(ILogConstantKeys.UTIL_005));

		}

		return result;

	}

	

	

	/**
	 * Decodes the supplied bytes.
	 * @param abyte0	Bytes to decode.
	 * @param i	Started index.
	 * @param j	Finished index.
	 * @return	Decoded bytes.
	 */
	public byte[ ] decode(byte abyte0[], int i, int j) {
		int k = j * 3 / 4;
		byte abyte1[] = new byte[k];
		int l = 0;
		byte abyte2[] = new byte[4];
		int i1 = 0;

		for (int j1 = 0; j1 < j; j1++) {
			byte byte0 = (byte) (abyte0[j1] & 0x7f);
			byte byte1 = DECODABET[byte0];
			if (byte1 >= -5) {
				if (byte1 < -1) {
					continue;
				}
				abyte2[i1++] = byte0;
				if (i1 <= 3) {
					continue;
				}
				l += decode4to3(abyte2, 0, abyte1, l);
				i1 = 0;
				if (byte0 == 61) {
					break;
				}
			} else {
				logger.error(Language.getResSigReport(ILogConstantKeys.UTIL_005));
				return null;
			}
		}

		byte abyte3[] = new byte[l];
		System.arraycopy(abyte1, 0, abyte3, 0, l);
		return abyte3;
	}
	
	public boolean isBase64(String encodedStr){
		boolean isBase64 = true;
		int i=0;
		while(i<encodedStr.length() && isBase64){
			byte character = (byte) encodedStr.charAt(i);
			isBase64 = isBase64Character(character);
			if(!isBase64){
				isBase64 = (character == NEW_LINE || character == EQUALS_SIGN );
			}
			i++;
		}
		return isBase64;
		
	}
	
	private boolean isBase64Character(byte character){
		boolean valid = false;
		int i=0;
		while(i<ALPHABET.length && !valid){
			valid = character==ALPHABET[i];
			i++;
		}
		return valid ;
	}
	
	public static final boolean ENCODE = true;
	public static final boolean DECODE = false;
	public static final int MAX_LINE_LENGTH = 76;
	public static final byte EQUALS_SIGN = 61;
	public static final byte NEW_LINE = 10;
	private static final byte ALPHABET[] = { 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47 };
	private static final byte DECODABET[] = { -9, -9, -9, -9, -9, -9, -9, -9, -9, -5, -5, -9, -9, -5, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -5, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, 62, -9, -9, -9, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -9, -9, -9, -1, -9, -9, -9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -9, -9, -9, -9, -9, -9, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -9, -9, -9, -9 };
	public static final byte BAD_ENCODING = -9;
	public static final byte WHITE_SPACE_ENC = -5;
	public static final byte EQUALS_SIGN_ENC = -1;

}
