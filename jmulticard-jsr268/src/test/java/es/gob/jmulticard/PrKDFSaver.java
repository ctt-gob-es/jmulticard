package es.gob.jmulticard;

import javax.swing.JOptionPane;

import es.gob.jmulticard.card.gemalto.tuir5.TuiR5;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;


/** Clase de utilidad para guardar el PrKDF a disco.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class PrKDFSaver {

	/** Main.
	 * @param args Debe indicarse el PIN y el fichero de salida */
	public static void main(final String[] args) {
		if (args == null || args.length != 1) {
			System.out.println("Uso: PrKDFSaver pin"); //$NON-NLS-1$
			System.out.println(" pin\tPIN de la tarjeta"); //$NON-NLS-1$
			System.exit(-1);
			return;
		}
		System.out.println("Se usara el PIN '" + args[0] + "'"); //$NON-NLS-1$ //$NON-NLS-2$
		System.out.println("Desea continuar? [s/n]"); //$NON-NLS-1$
		final String conf;
		try {
			conf = System.console().readLine();
		}
		catch(final Exception e) {
			JOptionPane.showMessageDialog(
				null,
				"Debe ejecutar esta aplicacion desde linea de comandos", //$NON-NLS-1$
				"Error", //$NON-NLS-1$
				JOptionPane.ERROR_MESSAGE
			);
			System.exit(-3);
			return;
		}

		if (conf == null || !conf.trim().toLowerCase().equals("s")) { //$NON-NLS-1$
			System.exit(-3);
			return;
		}

		try {
			new TuiR5(
				new SmartcardIoConnection(),
				new CachePasswordCallback(args[0].toCharArray())
			);
		}
		catch(final Exception e) {
			System.out.println("Error accediendo a la tarjeta: " + e); //$NON-NLS-1$
		}

	}

}
