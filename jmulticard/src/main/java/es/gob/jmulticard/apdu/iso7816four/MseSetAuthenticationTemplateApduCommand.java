package es.gob.jmulticard.apdu.iso7816four;

/** APDU ISO 7816-4 de gesti&oacute;n de entorno de seguridad mediante
 * plantilla de autenticaci&oacute;n.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class MseSetAuthenticationTemplateApduCommand extends MseSetApduCommand {

    /** Construye una APDU ISO 7816-4 de gesti&oacute;n de entorno de seguridad mediante
     * plantilla de autenticaci&oacute;n.
     * @param cla Clase de la APDU.
     * @param data Datos de la APDU. */
    protected MseSetAuthenticationTemplateApduCommand(final byte cla, final byte[] data) {
		super(
			cla,                    // CLA
    		SET_FOR_AUTHENTICATION, // P1
			AT,                     // P2
			data
		);
	}
}
