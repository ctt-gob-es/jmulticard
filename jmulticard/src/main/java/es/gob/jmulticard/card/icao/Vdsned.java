package es.gob.jmulticard.card.icao;

import java.io.IOException;

/** <i>Visible Digital Seals for Non-Electronic Documents</i> de ICAO.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Vdsned {

	private static final byte MAGIC = (byte) 0xdc;

	private final byte[] encoded;
	private final int version;
	private final String issuingCountry;

	/** Construye un <i>Visible Digital Seals for Non-Electronic Documents</i> de ICAO.
	 * @param enc Codificaci&oacute;n binaria del <i>Visible Digital Seals for Non-Electronic Documents</i>.
	 * @throws IOException Si hay problemas durante el an&aacute;lisis de la codificaci&oacute;n
	 *                     proporcionada. */
	public Vdsned(final byte[] enc) throws IOException {
		if (enc == null || enc.length < 1) {
			throw new IllegalArgumentException(
				"La codificacion binaria del VDSNED no puede ser nula ni vacia" //$NON-NLS-1$
			);
		}

		this.encoded = enc.clone();

		int offset = 0;
		if (this.encoded[offset++] != MAGIC) {
			throw new IllegalArgumentException(
				"La codificacion binaria proporcionada no corresponde con un VDSNED" //$NON-NLS-1$
			);
		}

		this.version = this.encoded[offset++] + 1;

		if (this.version != 3 && this.version != 4) {
			throw new IllegalArgumentException(
				"Solo se soportan VDSNED v3 o v4, y se ha proporcionado un v" + this.version //$NON-NLS-1$
			);
		}

		this.issuingCountry = C40Decoder.decode(new byte[] { this.encoded[offset++], this.encoded[offset++] });
	}

	@Override
	public String toString() {
		return "VDSNED\n" + //$NON-NLS-1$
			" Version: " + this.version + '\n' + //$NON-NLS-1$
			" Pais emisor: " + CountryCodes.getCountryName(this.issuingCountry) //$NON-NLS-1$
		;
	}

}
