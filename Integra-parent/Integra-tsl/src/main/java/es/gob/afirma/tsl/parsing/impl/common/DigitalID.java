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
 * <b>File:</b><p>es.gob.afirma.tsl.parsing.impl.common.DigitalID.java.</p>
 * <b>Description:</b><p>Class that defines a Digital Identity with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p> 10/11/2020.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/11/2020.
 */
package es.gob.afirma.tsl.parsing.impl.common;

import java.io.Serializable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.w3.x2000.x09.xmldsig.KeyValueType;

import es.gob.afirma.tsl.exceptions.CommonUtilsException;
import es.gob.afirma.tsl.exceptions.TSLParsingException;
import es.gob.afirma.tsl.utils.UtilsCertificateTsl;
import es.gob.afirma.tsl.utils.UtilsStringChar;



/** 
 * <p>Class that defines a Digital Identity with all its information not dependent
 * of the specification or TSL version.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 10/11/2020.
 */
public class DigitalID implements Serializable {

    /**
     * Constant attribute that represents the serial version UID.
     */
    private static final long serialVersionUID = -3338685368351921434L;

    /**
	 * Constant attribute that represents a digital identity type: X509 Certificate.
	 */
	public static final int TYPE_X509CERTIFICATE = 0;

	/**
	 * Constant attribute that represents a digital identity type: X509 Subject Name.
	 */
	public static final int TYPE_X509SUBJECTNAME = 1;

	/**
	 * Constant attribute that represents a digital identity type: Key Value.
	 */
	public static final int TYPE_KEYVALUE = 2;

	/**
	 * Constant attribute that represents a digital identity type: X509 SKI.
	 */
	public static final int TYPE_X509SKI = 3;

	/**
	 * Constant attribute that represents a digital identity type: Other.
	 */
	public static final int TYPE_OTHER = 4;

	/**
	 * Attribute that represents the type of this digital identity.
	 */
	private int type = -1;

	/**
	 * Attribute that represents the X509 certificate: Only type {@link #TYPE_X509CERTIFICATE}.
	 */
	private transient X509Certificate x509cert = null;

	/**
	 * Attribute that represents the X509 Subject Name: Only type {@link #TYPE_X509SUBJECTNAME}.
	 */
	private String x509SubjectName = null;

	/**
	 * Attribute that represents the Key Value: Only type {@link #TYPE_KEYVALUE}.
	 */
	private transient KeyValueType keyValue = null;

	/**
	 * Attribute that represents the Subject Key Identifier: Only type {@link #TYPE_X509SKI}.
	 */
	private transient SubjectKeyIdentifier ski = null;

	/**
	 * Attribute that represents the Subject Key Identifier: Only type {@link #TYPE_OTHER}.
	 */
	private String other = null;

	/**
	 * Constructor method for the class DigitalID.java.
	 */
	private DigitalID() {
		super();
	}

	/**
	 * Constructor method for the class DigitalID.java.
	 * @param digitalIdentityType Digital identity type.
	 * It must be one of the following:
	 * - {@link #TYPE_X509CERTIFICATE}.
	 * - {@link #TYPE_X509SUBJECTNAME}.
	 * - {@link #TYPE_KEYVALUE}.
	 * - {@link #TYPE_X509SKI}.
	 * - {@link #TYPE_OTHER}.
	 */
	public DigitalID(int digitalIdentityType) {
		this();
		type = digitalIdentityType;
	}

	/**
	 * Gets the value of the attribute {@link #type}.
	 * @return the value of the attribute {@link #type}.
	 */
	public final int getType() {
		return type;
	}

	/**
	 * Gets the value of the attribute {@link #x509cert}.
	 * @return the value of the attribute {@link #x509cert}.
	 */
	public final X509Certificate getX509cert() {
		return x509cert;
	}

	/**
	 * Sets the value of the attribute {@link #x509cert}.
	 * @param x509certDI The value for the attribute {@link #x509cert}.
	 */
	public final void setX509cert(X509Certificate x509certDI) {
		this.x509cert = x509certDI;
	}

	/**
	 * Sets the value of the attribute {@link #x509cert}.
	 * @param x509certBytesDI The value (in bytes) for the attribute {@link #x509cert}.
	 * @throws TSLParsingException In case of some error parsing the X509 certificate.
	 */
	public final void setX509cert(byte[ ] x509certBytesDI) throws TSLParsingException {

		try {
			this.x509cert = UtilsCertificateTsl.getX509Certificate(x509certBytesDI);
		} catch (CommonUtilsException e) {
			throw new TSLParsingException("Error parseando un certificado X509 utilizado como identificaci\u00F3n digital.", e);
		}

	}

	/**
	 * Gets the value of the attribute {@link #x509SubjectName}.
	 * @return the value of the attribute {@link #x509SubjectName}.
	 */
	public final String getX509SubjectName() {
		return x509SubjectName;
	}

	/**
	 * Sets the value of the attribute {@link #x509SubjectName}.
	 * @param x509SubjectNameDI The value for the attribute {@link #x509SubjectName}.
	 * @throws TSLParsingException In case of the input string was <code>null</code> or empty.
	 */
	public final void setX509SubjectName(String x509SubjectNameDI) throws TSLParsingException {
		if (UtilsStringChar.isNullOrEmptyTrim(x509SubjectNameDI)) {
			throw new TSLParsingException("Error parseando el nombre alternativo X509 utilizado como identificaci\u00F3n digital. No puede ser vac\u00EDo o nulo.");
		}
		this.x509SubjectName = x509SubjectNameDI;
	}

	/**
	 * Gets the value of the attribute {@link #keyValue}.
	 * @return the value of the attribute {@link #keyValue}.
	 */
	public final KeyValueType getKeyValue() {
		return keyValue;
	}

	/**
	 * Sets the value of the attribute {@link #keyValue}.
	 * @param keyValueDI The value for the attribute {@link #keyValue}.
	 * @throws TSLParsingException In case of the input parameter was <code>null</code>, or not is defined RSA or DSA values.
	 */
	public final void setKeyValue(KeyValueType keyValueDI) throws TSLParsingException {

		if (keyValueDI == null || !keyValueDI.isSetDSAKeyValue() && !keyValueDI.isSetRSAKeyValue()) {
			throw new TSLParsingException("Error parseando el 'KeyValue' como identificaci\u00F3n digital. No puede ser nulo.");
		}
		this.keyValue = keyValueDI;
	}

	/**
	 * Gets the value of the attribute {@link #ski}.
	 * @return the value of the attribute {@link #ski}.
	 */
	public final SubjectKeyIdentifier getSki() {
		return ski;
	}

	/**
	 * Sets the value of the attribute {@link #ski}.
	 * @param skiDI The value for the attribute {@link #ski}.
	 */
	public final void setSki(SubjectKeyIdentifier skiDI) {
		this.ski = skiDI;
	}

	/**
	 * Sets the value of the attribute {@link #ski}.
	 * @param skiByteDI The value (in bytes) for the attribute {@link #ski}.
	 */
	public final void setSki(byte[ ] skiByteDI) {
		this.ski = new SubjectKeyIdentifier(skiByteDI);
	}

	/**
	 * Gets the value of the attribute {@link #other}.
	 * @return the value of the attribute {@link #other}.
	 */
	public final String getOther() {
		return other;
	}

	/**
	 * Sets the value of the attribute {@link #other}.
	 * @param otherDI The value for the attribute {@link #other}.
	 */
	public final void setOther(String otherDI) {
		this.other = otherDI;
	}

	/**
	 * The writeObject method is responsible for writing the state of the
	 * object for its particular class so that the corresponding
	 * readObject method can restore it.
	 * @param out Output stream for write the components that defines this object.
	 * @throws IOException In case of some error managing the output stream.
	 */
	private void writeObject(ObjectOutputStream out) throws IOException {

		out.defaultWriteObject();

		// En función del tipo, si es alguno con los
		// objetos no serializables...
		try {
			switch (type) {
				case DigitalID.TYPE_X509CERTIFICATE:
					byte[ ] x509certEncoded = x509cert.getEncoded();
					out.write(x509certEncoded.length);
					out.write(x509certEncoded);
					break;

				case DigitalID.TYPE_KEYVALUE:
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					keyValue.save(baos);
					byte[ ] kvByteArray = baos.toByteArray();
					out.write(kvByteArray.length);
					out.write(kvByteArray);
					break;

				case DigitalID.TYPE_X509SKI:
					byte[ ] skiByteArray = ski.getEncoded();
					out.write(skiByteArray.length);
					out.write(skiByteArray);
					break;

				default:
					break;
			}
		} catch (CertificateEncodingException e) {
			throw new IOException(e);
		}

	}

	/**
	 * The readObject method is responsible for reading from the stream and restoring the classes fields.
	 * @param in Input stream with the data to restore,
	 * @throws IOException In case of some error managing the Input Stream.
	 * @throws ClassNotFoundException In case of the class to deserialize an specific object
	 * does not exists in classpath.
	 */
	private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {

		in.defaultReadObject();

		// En función del tipo, si es alguno con los
		// objetos no serializables...
		try {
			switch (type) {
				case DigitalID.TYPE_X509CERTIFICATE:
					int lengthX509Cert = in.readInt();
					byte[ ] x509encoded = new byte[lengthX509Cert];
					in.read(x509encoded);
					x509cert = UtilsCertificateTsl.getX509Certificate(x509encoded);
					break;

				case DigitalID.TYPE_KEYVALUE:
					int lengthKeyValue = in.readInt();
					byte[ ] kvByteArray = new byte[lengthKeyValue];
					in.read(kvByteArray);
					ByteArrayInputStream bais = new ByteArrayInputStream(kvByteArray);
					keyValue = KeyValueType.Factory.parse(bais);
					break;

				case DigitalID.TYPE_X509SKI:
					int lengthX509ski = in.readInt();
					byte[ ] skiByteArray = new byte[lengthX509ski];
					in.read(skiByteArray);
					ski = new SubjectKeyIdentifier(skiByteArray);
					break;

				default:
					break;
			}
		} catch (CommonUtilsException e) {
			throw new IOException(e);
		} catch (XmlException e) {
			throw new IOException(e);
		}

	}

}
