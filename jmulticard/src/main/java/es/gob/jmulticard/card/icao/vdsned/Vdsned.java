package es.gob.jmulticard.card.icao.vdsned;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Logger;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.card.icao.CountryCodes;

/** <i>Visible Digital Seal for Non-Electronic Documents</i> de ICAO.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Vdsned {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	private static final byte MAGIC = (byte) 0xdc;

	private transient final byte[] encoded;

	private final int version;

	/** Pa&iacute;s que emite el sello. */
	private final String issuingCountry;

	private final String caCr;
	private final Date documentIssueDate;
	private final Date signatureCreationDate;
	private final int documentFeatureDefinitionReference;
	private final int documentTypeCategory;

	private transient String mrzB = null;
	private transient int nEntries = 0;
	private transient int durationOfStay = 0;
	private transient String passportNumber = null;
	private transient byte[] signature = null;
	private transient byte[] dataTbs = null;

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withECDSA"; //$NON-NLS-1$

	/** Construye un <i>Visible Digital Seal for Non-Electronic Documents</i> de ICAO.
	 * @param enc Codificaci&oacute;n binaria del <i>Visible Digital Seals for Non-Electronic Documents</i>.
	 * @throws IOException Si hay problemas durante el an&aacute;lisis de la codificaci&oacute;n
	 *                     proporcionada.
	 * @throws TlvException Si hay errores el los TLV que conforman el sello. */
	public Vdsned(final byte[] enc) throws IOException, TlvException {

		if (enc == null || enc.length < 1) {
			throw new IllegalArgumentException(
				"La codificacion binaria del VDSNED no puede ser nula ni vacia" //$NON-NLS-1$
			);
		}
		encoded = enc.clone();
		int offset = 0;

		// Magic
		if (encoded[offset++] != MAGIC) {
			throw new IllegalArgumentException(
				"La codificacion binaria proporcionada no corresponde con un VDSNED" //$NON-NLS-1$
			);
		}

		// Version
		version = encoded[offset++] + 1;
		if (version != 3 && version != 4) {
			throw new IllegalArgumentException(
				"Solo se soportan VDSNED v3 o v4, y se ha proporcionado un v" + version //$NON-NLS-1$
			);
		}

		// Pais emisor
		issuingCountry = C40Decoder.decode(new byte[] { encoded[offset++], encoded[offset++] });

		// CA-CR (texto en C40)
		caCr = C40Decoder.decode(
			new byte[] {
				encoded[offset++], encoded[offset++], encoded[offset++],
				encoded[offset++], encoded[offset++], encoded[offset++]
			}
		);

		// Fecha de emision del documento
		byte[] tmpDateBytes = {
			0x00, encoded[offset++], encoded[offset++], encoded[offset++]
		};
		String tmpDate = Integer.toString(ByteBuffer.wrap(tmpDateBytes).getInt());
		try {
			documentIssueDate = new SimpleDateFormat(
				tmpDate.length() == 7 ? "Mddyyyy" : "MMddyyyy" //$NON-NLS-1$ //$NON-NLS-2$
			).parse(tmpDate);
		}
		catch (final ParseException e) {
			throw new IllegalArgumentException(
				"La fecha de emision del documento es invalida (" + HexUtils.hexify(tmpDateBytes, false) + ", " + tmpDate + ")", e //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			);
		}

		// Fecha de creacion de la firma
		tmpDateBytes = new byte[] {
			0x00, encoded[offset++], encoded[offset++], encoded[offset++]
		};
		tmpDate = Integer.toString(ByteBuffer.wrap(tmpDateBytes).getInt());
		try {
			signatureCreationDate = new SimpleDateFormat(
				tmpDate.length() == 7 ? "Mddyyyy" : "MMddyyyy" //$NON-NLS-1$ //$NON-NLS-2$
			).parse(tmpDate);
		}
		catch (final ParseException e) {
			throw new IllegalArgumentException(
				"La fecha de creacion de la firma es invalida (" + HexUtils.hexify(tmpDateBytes, false) + ", " + tmpDate + ")", e //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			);
		}

		// Referencia
		documentFeatureDefinitionReference = encoded[offset++];

		// Categoria
		documentTypeCategory = encoded[offset++];
		if ((documentTypeCategory & 1) == 0 ) {
			LOGGER.warning(
				"La categoria deberia ser un numero impar, pero se ha encontrado " +  documentTypeCategory //$NON-NLS-1$
			);
		}

		while(offset < encoded.length) {

			final byte[] data = new byte[encoded.length - offset];
			System.arraycopy(encoded, offset, data, 0, data.length);

			final Tlv tlv = new Tlv(data);

			switch(tlv.getTag()) {
				case 0x02:
					mrzB = C40Decoder.decode(tlv.getValue());
					break;
				case 0x03:
					nEntries = HexUtils.getUnsignedInt(tlv.getValue(), 0);
					break;
				case 0x04:
					final byte[] durBytes = tlv.getValue();
					// Dos o una posiciones
					if (durBytes.length < 3) {
						durationOfStay = HexUtils.getUnsignedInt(durBytes, 0);
					}
					// Tres posiciones
					else if (durBytes.length == 3) {
						durationOfStay = ByteBuffer.wrap(
							new byte[] {
								0x00, durBytes[2], durBytes[1], durBytes[0]
							}
						).getInt();
					}
					// Cuatro o mas posiciones
					else {
						durationOfStay = ByteBuffer.wrap(tmpDateBytes).getInt();
					}
					break;
				case 0x05:
					passportNumber = C40Decoder.decode(tlv.getValue());
					break;
				case (byte) 0xff:

					// Hemos llegado a la firma, con lo que todo el conjunto anterior de
					// datos es lo que se firma
					dataTbs = new byte[offset];
					System.arraycopy(encoded, 0, dataTbs, 0, offset);

					final byte[] sig = tlv.getValue();
					final byte[] r = new byte[tlv.getLength()/2];
					System.arraycopy(sig, 0, r, 0, tlv.getLength()/2);
					final byte[] s = new byte[tlv.getLength()/2];
					System.arraycopy(sig, tlv.getLength()/2, s, 0, tlv.getLength()/2);
					signature = encodeEcdsaSignature(r, s);
					break;
				default:
					LOGGER.warning("Encontrado campo de datos desconocido: " + tlv); //$NON-NLS-1$
			}

			offset = offset + tlv.getBytes().length;
		}
	}

	private static byte[] encodeEcdsaSignature(final byte[] r, final byte[] s) {

		final byte integerTag = (byte) 0x02;
		final byte sequenceTag = (byte) 0x30;

		final Tlv rTlv = new Tlv(integerTag, r);
		final Tlv sTlv = new Tlv(integerTag, s);
		final Tlv sequenceTlv = new Tlv(
			sequenceTag,
			HexUtils.concatenateByteArrays(
				rTlv.getBytes(),
				sTlv.getBytes()
			)
		);

		return sequenceTlv.getBytes();
	}

	/** Comprueba la firma electr&oacute;nica de este <i>Visible Digital Seal for Non-Electronic Documents</i>.
	 * @param publicKey Clave p&uacute;lica de firma.
	 * @throws NoSuchAlgorithmException Si no se soporta el algoritmo de firma por defecto.
	 * @throws InvalidKeyException Si la clave proporcionada no es v&aacute;lida para esta firma.
	 * @throws SignatureException Si la firma es inv&aacute;lida o no se puede verificar. */
	public void verifyEcDsaSignature(final PublicKey publicKey) throws NoSuchAlgorithmException,
	                                                                   InvalidKeyException,
	                                                                   SignatureException {
		final Signature sig = Signature.getInstance(
			DEFAULT_SIGNATURE_ALGORITHM
		);
		sig.initVerify(publicKey);
		sig.update(dataTbs);
		if (!sig.verify(signature)) {
			throw new SignatureException(
				"La firma no es valida" //$NON-NLS-1$
			);
		}
	}

	@Override
	public String toString() {
		final SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy"); //$NON-NLS-1$
		return "Visible Digital Seal for Non-Electronic Documents\n" + //$NON-NLS-1$
			" Version: " + version + '\n' + //$NON-NLS-1$
			" Pais emisor: " + CountryCodes.getCountryName(issuingCountry) + '\n' + //$NON-NLS-1$
			" Autoridad de certificacion y referencia: " + caCr + '\n' + //$NON-NLS-1$
			" Fecha de emision del documento: " + sdf.format(documentIssueDate) + '\n' + //$NON-NLS-1$
			" Fecha de creacion de la firma: " + sdf.format(signatureCreationDate) + '\n' + //$NON-NLS-1$
			" Referencia: " + documentFeatureDefinitionReference + '\n' + //$NON-NLS-1$
			" Categoria: " + documentTypeCategory + '\n' + //$NON-NLS-1$
			" MRZ-B: " + mrzB + '\n' + //$NON-NLS-1$
			" Numero de entradas: " + nEntries + '\n' + //$NON-NLS-1$
			" Duracion de la estancia: " + durationOfStay + '\n' + //$NON-NLS-1$
			" Numero de pasaporte: " + passportNumber + '\n' //$NON-NLS-1$
		;
	}

	/** Obtiene c&oacute;digo del pa&iacute;s emisor.
	 * @return C&oacute;digo del pa&iacute;s emisor. */
	public String getIssuingCountry() {
		return issuingCountry;
	}

	/** Obtiene la autoridad de certificaci&oacute;n y referencia para este documento.
	 * @return C&oacute;digo de autoridad de certificaci&oacute;n y referencia para este documento. */
	public String getCaCr() {
		return caCr;
	}

	/** Obtiene la fecha de emisi&oacute;n del documento.
	 * @return Fecha de emisi&oacute;n del documento. */
	public Date getDocumentIssueDate() {
		return documentIssueDate;
	}

	/** Obtiene la fecha de firma del documento.
	 * @return Fecha de firma del documento. */
	public Date getSignatureCreationDate() {
		return signatureCreationDate;
	}

	/** Obtiene la referencia de definici&oacute;n de caracter&iacute;sticas del documento.
	 * @return Referencia de definici&oacute;n de caracter&iacute;sticas del documento. */
	public int getDocumentFeatureDefinitionReference() {
		return documentFeatureDefinitionReference;
	}

	/** Obtiene la categor&iacute;a del tipo del documento.
	 * @return Categor&iacute;a del tipo del documento. */
	public int getDocumentTypeCategory() {
		return documentTypeCategory;
	}

	/** Obtiene la versi&oacute;n del <i>Visible Digital Seal for Non-Electronic Documents</i>.
	 * @return Versi&oacute;n del <i>Visible Digital Seal for Non-Electronic Documents</i>. */
	public int getVersion() {
		return version;
	}

}
