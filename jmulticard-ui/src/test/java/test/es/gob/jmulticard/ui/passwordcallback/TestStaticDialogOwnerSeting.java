package test.es.gob.jmulticard.ui.passwordcallback;

import javax.swing.JFrame;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.ui.passwordcallback.PasswordCallbackManager;
import es.gob.jmulticard.ui.passwordcallback.gui.InputPasswordSmartcardDialog;

/** Prueba del establecimiento del componente padre. */
public final class TestStaticDialogOwnerSeting {

    /** Prueba del establecimiento del componente padre de un di&aacute;logo. */
    @SuppressWarnings("static-method")
    @Test
    @Ignore // Necesita GUI
    public void testSetGetDialogOwner() {
        final JFrame frame = new JFrame();
        PasswordCallbackManager.setDialogOwner(frame);
        Assert.assertEquals(frame, PasswordCallbackManager.getDialogOwner());
    }

    /** Prueba del di&aacute;logo de pedir PIN.
     * @param args No se usa. */
    public static void main(final String[] args) {
    	InputPasswordSmartcardDialog.showInputPasswordDialog(
			null,  // padre
			false, // modal
			"Mensaje", //$NON-NLS-1$
			0,     // mnemonico
			"Titulo", //$NON-NLS-1$
			null,  // icono
			true,  // permitir mostrar
			false  // mostrar por defecto
		);
    }
}
