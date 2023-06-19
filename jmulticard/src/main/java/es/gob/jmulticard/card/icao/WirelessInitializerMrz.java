package es.gob.jmulticard.card.icao;

import java.io.IOException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/** Valor MRZ para inicializaci&oacute;n de un canal PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Ignacio Mar&iacute;n. */
public final class WirelessInitializerMrz implements WirelessInitializer {

	private transient final byte[] k;

	/** Construye una MRZ para inicializaci&oacute;n de un canal PACE.
	 * @param mrz MRZ. */
	private WirelessInitializerMrz(final byte[] mrz) {
		if (mrz == null) {
			throw new IllegalArgumentException("La MRZ no puede ser nula"); //$NON-NLS-1$
		}
		k = mrz;
	}

	@Override
	public String toString() {
		return new String(k);
	}

	@Override
	public byte[] getBytes() {
		return k;
	}

	@Override
	public PacePasswordType getPasswordType() {
		return MseSetPaceAlgorithmApduCommand.PacePasswordType.MRZ;
	}

	/** Genera el inicializador necesario para la clave partiendo de la MRZ.
	 * @param mrz MRZ.
	 * @param cryptoHelper Clase para la realizaci&oacute;n de operaciones criptogr&aacute;ficas.
	 * @return Inicializador necesario para la clave.
	 * @throws MalformedMrzException Si la MRZ est&aacute; mal formada. */
	public static WirelessInitializerMrz deriveMrz(final String mrz,
			                                       final CryptoHelper cryptoHelper) throws MalformedMrzException {
		if (mrz == null || mrz.isEmpty()) {
			throw new IllegalArgumentException(
				"El valor no puede ser nulo ni vacio" //$NON-NLS-1$
			);
		}
		try {
			return new WirelessInitializerMrz(
				new MrzInfo(mrz).getMrzPswd(cryptoHelper)
			);
		}
		catch (final IOException | IllegalArgumentException ex) {
			throw new MalformedMrzException("La MRZ no tiene formato valido", ex); //$NON-NLS-1$
		}
	}

}
