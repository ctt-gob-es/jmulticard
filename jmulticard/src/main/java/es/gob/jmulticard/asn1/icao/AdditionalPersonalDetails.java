package es.gob.jmulticard.asn1.icao;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

/** Detalles personales adicionales de un eMRTD contenidos en el DG11.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class AdditionalPersonalDetails extends DecoderObject {

	private static final byte TAG = 0x6B;

	/** Nombre completo del titular. */
	private String subjectFullName = null;

	/** N&uacute;mero personal. */
	private String personalNumber = null;

	/** Fecha de nacimiento completa (en formato <i>aaaammdd</i>). */
	private String fullBirthDate = null;

	/** Lugar de nacimiento. */
	private String birthPlace = null;

	/** Direcci&oacute;n permanente (campos separados por '&lt;'). */
	private String permanentAddress = null;

	/** Obtiene el nombre completo del titular.
	 * @return Nombre completo del titular. */
	public String getSubjectFullName() {
		return subjectFullName;
	}

	/** Ontiene el n&uacute;mero personal.
	 * @return N&uacute;mero personal. */
	public String getPersonalNumber() {
		return personalNumber;
	}

	/** Obtiene la fecha de nacimiento completa (en formato <i>aaaammdd</i>).
	 * @return Fecha de nacimiento completa (en formato <i>aaaammdd</i>). */
	public String getFullBirthDate() {
		return fullBirthDate;
	}

	/** Obtiene el lugar de nacimiento.
	 * @return Lugar de nacimiento. */
	public String getBirthPlace() {
		return birthPlace;
	}

	/** Obtiene la direcci&oacute;n permanente (campos separados por '&lt;').
	 * @return Direcci&oacute;n permanente (campos separados por '&lt;'). */
	public String getPermanentAddress() {
		return permanentAddress;
	}

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		checkTag(getBytes()[0]);

		final DataInputStream dis = new DataInputStream(
			new ByteArrayInputStream(
				new Tlv(getBytes()).getValue()
			)
		);

		try {
			byte tag;
			byte len;

			while(dis.available() > 2) {
				tag = dis.readByte();
				if (tag == 0x5f) {
					final byte type = dis.readByte();
					len = dis.readByte();
					processField(type, readNBytes(dis, len));
				}
				else {
					// Ignoramos los rotulos que no nos interesan (rotulos mono-octeto)
					len = dis.readByte();
					readNBytes(dis, len);
				}
			}
		}
		catch (final IOException e) {
			throw new TlvException("Error procesando el contenido del DG11", e); //$NON-NLS-1$
		}
	}

	//TODO: Usar el metodo analogo de DataInputStream cuando se migre a Java 9
	private static byte[] readNBytes(final DataInputStream dis, final int nBytes) throws IOException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (int i=0;i<nBytes;i++) {
			baos.write(dis.readByte());
		}
		return baos.toByteArray();
	}

	@Override
	protected byte getDefaultTag() {
		return TAG;
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("Detalles personales adidionales:"); //$NON-NLS-1$
		if (subjectFullName != null) {
			sb.append("\n  Nombre completo del titular: "); //$NON-NLS-1$
			sb.append(subjectFullName);
		}
		if (personalNumber != null) {
			sb.append("\n  Numero personal: "); //$NON-NLS-1$
			sb.append(personalNumber);
		}
		if (fullBirthDate != null) {
			sb.append("\n  Fecha de nacimiento completa: "); //$NON-NLS-1$
			sb.append(fullBirthDate);
		}
		if (birthPlace != null) {
			sb.append("\n  Lugar de nacimiento: "); //$NON-NLS-1$
			sb.append(birthPlace);
		}
		if (permanentAddress != null) {
			sb.append("\n  Direccion permanente: "); //$NON-NLS-1$
			sb.append(permanentAddress);
		}
		return sb.toString();
	}

	private void processField(final byte type, final byte[] value) {
		switch(type) {
			case 0x0e:
				subjectFullName = new String(value);
				break;
			case 0x10:
				personalNumber = new String(value);
				break;
			case 0x2b:
				fullBirthDate = HexUtils.hexify(value, false);
				break;
			case 0x11:
				birthPlace = new String(value);
				break;
			case 0x42:
				permanentAddress = new String(value);
				break;
			default:
				JmcLogger.warning("Rotulo de DG11 no soportado: 5F" + HexUtils.hexify(new byte[] { type }, false)); //$NON-NLS-1$
		}
	}
}
