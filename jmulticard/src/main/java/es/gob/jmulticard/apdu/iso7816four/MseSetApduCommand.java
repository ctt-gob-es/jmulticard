package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU ISO 7816-4 de gesti&oacute;n de entorno de seguridad.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
abstract class MseSetApduCommand extends CommandApdu {

    /** Byte de instrucci&oacute;n de la APDU. */
    protected static final byte INS_MANAGE_ENVIROMENT = (byte) 0x22;

    /** Establece el fichero identificado para autenticaci&oacute;n. */
    protected static final byte SET_FOR_AUTHENTICATION = (byte) 0xc1;

    /** Crea un objeto para la gesti&oacute;n del entorno de seguridad.
     * @param cla Clase (CLA) de la APDU. */
	protected MseSetApduCommand(final byte cla, final byte param2, final byte[] data) {
		super(
			cla,
			INS_MANAGE_ENVIROMENT,
			SET_FOR_AUTHENTICATION,
			param2,
			data,
			null
		);
	}

}
