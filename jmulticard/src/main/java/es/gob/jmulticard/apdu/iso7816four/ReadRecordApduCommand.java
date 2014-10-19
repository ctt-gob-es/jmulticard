package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.StatusWord;

/** APDU ISO 7816-4 de lectura de registro.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class ReadRecordApduCommand extends CommandApdu {

	private static final byte INS_READ_RECORD = (byte) 0xB2;

	/** APDU de respuesta de registro no encontrado al comando de lectura de registro. */
	public static final StatusWord RECORD_NOT_FOUND = new StatusWord((byte)0x6A, (byte)0x83);

	/** Crea una APDU ISO 7816-4 de lectura de registro.
	 * @param cla Clase (CLA) de la APDU. */
	public ReadRecordApduCommand(final byte cla) {
		super(
			cla,
			INS_READ_RECORD,
			(byte) 0x00, // Lectura del registro actual
			(byte) 0x02, // Siguiente registro (para que avance automaticamente)
			null,        // Data
			Integer.valueOf(234) // 0xEA, tamano seguro de lectura
		);
	}

}
