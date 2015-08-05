package es.gob.jmulticard.apdu.iso7816four;

/** APDU ISO 7816-4 de gesti&oacute;n de entorno de seguridad mediante
 * plantilla de autenticaci&oacute;n.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class MseSetAuthenticationTemplateApduCommand extends MseSetApduCommand {

	/** Control Reference Template for Authentication (AT) */
    private static final byte AT = (byte) 0xa4;

    protected MseSetAuthenticationTemplateApduCommand(final byte cla, final byte[] data) {
		super(cla, AT, data);
	}
}
