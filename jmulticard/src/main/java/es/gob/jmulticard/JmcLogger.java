package es.gob.jmulticard;

import java.util.logging.Level;
import java.util.logging.Logger;

/** <i>Logger</i> centralizado de toda la biblioteca.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class JmcLogger {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	private static final boolean DEBUG = false;

	private JmcLogger() {
		// No instanciable
	}

	/** Registra un mensaje de advertencia.
	 * @param msg Mensaje de advertencia. */
	public static void warning(final String msg) {
		LOGGER.warning(msg);
	}

	/** Registra un mensaje de error.
	 * @param msg Mensaje de error. */
	public static void severe(final String msg) {
		LOGGER.severe(msg);
	}

	/** Registra un mensaje de informaci&oacute;n.
	 * @param className Nombre de la clase desde la que se llama.
	 * @param methodName Nombre del m&eacute;todo desde el que se llama.
	 * @param msg Mensaje de informaci&oacute;n. */
	public static void info(final String className, final String methodName, final String msg) {
		LOGGER.info(className + "." + methodName + "() : " + msg); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Registra un mensaje de depuraci&oacute;n.
	 * @param className Nombre de la clase desde la que se llama.
	 * @param methodName Nombre del m&eacute;todo desde el que se llama.
	 * @param msg Mensaje de depuraci&oacute;n. */
	public static void debug(final String className, final String methodName, final String msg) {
		if (DEBUG) {
			LOGGER.info(className + "." + methodName + "() : " + msg); //$NON-NLS-1$ //$NON-NLS-2$
		}
	}

	/** Registra un mensaje.
	 * @param className Nombre de la clase desde la que se llama.
	 * @param methodName Nombre del m&eacute;todo desde el que se llama.
	 * @param level Tipo de mensaje.
	 * @param msg Mensaje.
	 * @param e Excepci&oacute;n asociada al mensaje. */
	public static void log(final String className,
			               final String methodName,
			               final Level level,
			               final String msg,
			               final Throwable e) {
		LOGGER.log(level, className + "." + methodName + "() : " + msg, e); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
