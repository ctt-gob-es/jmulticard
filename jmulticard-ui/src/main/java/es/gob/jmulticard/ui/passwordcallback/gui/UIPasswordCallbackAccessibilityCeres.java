package es.gob.jmulticard.ui.passwordcallback.gui;

import java.awt.Component;

import javax.security.auth.callback.PasswordCallback;

/** <i>PasswordCallbak</i> que muestra un di&aacute;logo para solicitar una
 * contrase&ntilde;a para tarjeta CERES. */
public class UIPasswordCallbackAccessibilityCeres extends PasswordCallback {

	private static final long serialVersionUID = -6342090027227609274L;

	/** Mensaje que se va a mostrar. */
    private String message = null;

    /** Atajo para el campo de inserci&oacute;n de contrasenia. */
    private int mnemonic = 0;

    /** Componente padre sobre el que se mostrar&aacute; el di&aacute;logo para
     * la inserci&oacute;n de la contrase&ntilde;a. */
    private Component parent = null;

    /** T&iacute;tulo del di&aacute;logo. */
    private String title = null;

    /** Crea una <i>CallBack</i> para solicitar al usuario una contrase&ntilde;a
     * mediante un di&aacute;logo gr&aacute;fico. La contrase&ntilde;a no se
     * retiene ni almacena internamente en ning&uacute;n momento
     * @param prompt Texto del di&aacute;logo para solicitar la contrase&ntilde;a
     * @param parent Componente padre para la modalidad del di&aacute;logo
     * @param message Mensaje
     * @param mnemonic Mnem&oacute;nico para el propio campo de texto
     * @param title T&iacute;tulo del di&aacute;logo */
    public UIPasswordCallbackAccessibilityCeres(final String prompt,
    		                               final Component parent,
    		                               final String message,
    		                               final int mnemonic,
    		                               final String title) {
        super(prompt, false);
        this.parent = parent;
        if (prompt != null) {
            this.message = prompt;
        }
        else {
            this.message = message;
        }
        this.mnemonic = mnemonic;
        this.title = title;
    }

    @Override
    public char[] getPassword() {
    	return CustomDialogCeres.showInputPasswordDialog(
			this.parent,
			true, // Modal
			this.message,
			this.mnemonic,
			this.title
    	);
    }
}
