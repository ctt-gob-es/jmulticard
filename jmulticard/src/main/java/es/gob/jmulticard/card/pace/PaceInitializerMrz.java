package es.gob.jmulticard.card.pace;

import java.io.IOException;

import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/** Valor MRZ para inicializaci&oacute;n de un canal PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Ignacio Mar&iacute;n. */
public final class PaceInitializerMrz extends PaceInitializer {

	private final byte[] k;

	/** Construye una MRZ para inicializaci&oacute;n de un canal PACE.
	 * @param mrz MRZ. */
	private PaceInitializerMrz(final byte[] mrz) {
		super();
		if (mrz == null) {
			throw new IllegalArgumentException("La MRZ no puede ser nula"); //$NON-NLS-1$
		}
		this.k = mrz;
	}

	@Override
	public String toString() {
		return new String(this.k);
	}

	@Override
	public byte[] getBytes() {
		return this.k;
	}

	@Override
	public PacePasswordType getPasswordType() {
		return MseSetPaceAlgorithmApduCommand.PacePasswordType.MRZ;
	}

	/** Genera el inicializador necesario para la clave partiendo de la MRZ.
	 * @param mrz MRZ.
	 * @return Inicializador necesario para la clave.
	 * @throws MalformedMrzException Si la MRZ est&aacute; mal formada. */
	public static PaceInitializerMrz deriveMrz(final String mrz) throws MalformedMrzException {
		if (mrz == null || mrz.isEmpty()) {
			throw new IllegalArgumentException(
				"El valor no puede ser nulo ni vacio" //$NON-NLS-1$
			);
		}
		try {
			return new PaceInitializerMrz(
				new MrzInfo(mrz).getMrzPswd()
			);
		}
		catch (final IOException ex) {
			throw new MalformedMrzException("La MRZ no tiene formato valido: " + ex, ex); //$NON-NLS-1$
		}
	}

}
