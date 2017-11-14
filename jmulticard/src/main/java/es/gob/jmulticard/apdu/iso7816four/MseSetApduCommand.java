package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU ISO 7816-4 de gesti&oacute;n de entorno de seguridad.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
abstract class MseSetApduCommand extends CommandApdu {

    /** Byte de instrucci&oacute;n de la APDU. */
    private static final byte INS_MANAGE_ENVIROMENT = (byte) 0x22;

    /** Establece modo para autenticaci&oacute;n. */
    protected static final byte SET_FOR_AUTHENTICATION = (byte) 0xc1;

    /** Establece modo para computaci&oacute;n. */
    protected static final byte SET_FOR_COMPUTATION = (byte) 0x41;

    /** Control Reference Template for Digital Signature (DST). */
    protected static final byte DST = (byte) 0xB6;

	/** Control Reference Template for Authentication (AT). */
    protected static final byte AT = (byte) 0xa4;

    /** Referencia a una clave para uso directo en modo sim&eacute;trico o referencia a una clave
     * p&uacute;blica en modo asim&eacute;trico. */
    protected static final byte PUBLIC_KEY_REFERENCE = (byte) 0x83;

    /** Referencia a una clave para c&oacute;mputo de sesi&oacute;n en modo sim&eacute;trico o
     * referencia a una clave privada en modo asim&eacute;trico. */
    protected static final byte PRIVATE_KEY_REFERENCE = (byte) 0x84;

    /** Referencia a un algoritmo (a un mecanismo criptogr&aacute;fico). */
    protected static final byte ALGORITHM_REFERENCE = (byte) 0x80;

    /** Crea un objeto para la gesti&oacute;n del entorno de seguridad.
     * @param cla Clase (CLA) de la APDU.
     * @param param1 P1.
     * @param param2 P2.
     * @param data Datos de la APDU. */
	protected MseSetApduCommand(final byte cla,
			                    final byte param1,
			                    final byte param2,
			                    final byte[] data) {
		super(
			cla,
			INS_MANAGE_ENVIROMENT,
			param1,
			param2,
			data,
			null
		);
	}

}
