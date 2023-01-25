package es.gob.jmulticard.apdu.iso7816four;

import java.io.ByteArrayOutputStream;

import es.gob.jmulticard.asn1.Tlv;

/** APDU ISO 7816-4 de gesti&oacute;n de entorno de seguridad para
 * c&oacute;mputo de firma electr&oacute;nica.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class MseSetComputationApduCommand extends MseSetApduCommand {

	/** Crea una APDU ISO 7816-4 de gesti&oacute;n de entorno de
	 * seguridad para c&oacute;mputo de firma electr&oacute;nica.
	 * @param cla Clase (CLA) de la APDU.
	 * @param privateKeyReference Referencia a la clave privada de firma.
	 * @param algorithmReference Referencia al algoritmo de firma. */
	public MseSetComputationApduCommand(final byte cla,
			                            final byte[] privateKeyReference,
			                            final byte[] algorithmReference) {
		super(
			cla,
			SET_FOR_COMPUTATION,
			DST,
			createDst(privateKeyReference, algorithmReference)
		);
	}

	private static byte[] createDst(final byte[] privateKeyReference,
			                        final byte[] algorithmReference) {

		if (privateKeyReference == null) {
			throw new IllegalArgumentException(
				"La referencia a la clave privada no puede ser nula" //$NON-NLS-1$
			);
		}

		final Tlv prkRefTlv = new Tlv(PRIVATE_KEY_REFERENCE, privateKeyReference);
		Tlv algRefTlv = null;
		if (algorithmReference != null) {
			algRefTlv = new Tlv(ALGORITHM_REFERENCE, algorithmReference);
		}

		final ByteArrayOutputStream dstData = new ByteArrayOutputStream();
		try {
			dstData.write(prkRefTlv.getBytes());
			if (algRefTlv != null) {
				dstData.write(algRefTlv.getBytes());
			}
		}
		catch(final Exception e) {
			throw new IllegalStateException(
				"Error creando el cuerpo del DST", e //$NON-NLS-1$
			);
		}
		return dstData.toByteArray();
	}
}
