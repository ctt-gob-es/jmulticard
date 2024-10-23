package es.gob.jmulticard.jse.provider;

import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.util.logging.Logger;

import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.CardNotPresentException;
import es.gob.jmulticard.jse.provider.ceres.CeresProvider;
import es.gob.jmulticard.jse.provider.gide.SmartCafeProvider;

/** Factori&iacute;a de proveedores para todas las tarjetas soportadas.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class JMultiCardProviderFactory {

	private static final Logger LOGGER = Logger.getLogger(JMultiCardProviderFactory.class.getName());

	// **************************************************************************
	// ********* ATR DNIe Y COMPATIBLES *****************************************

	private static final byte[] DNI_NFC_ATR_MASK = {
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0x00
	};
	private static final Atr DNI_NFC_ATR = new Atr(new byte[] {
		(byte) 0x3B, (byte) 0x88, (byte) 0x80, (byte) 0x01, (byte) 0xE1, (byte) 0xF3, (byte) 0x5E, (byte) 0x11,
		(byte) 0x77, (byte) 0x81, (byte) 0xA1, (byte) 0x00, (byte) 0x03
	}, DNI_NFC_ATR_MASK);


	private static final byte[] DNI_ATR_MASK = {
		(byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF
	};
	private static final Atr DNI_ATR = new Atr(new byte[] {
		(byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44,
		(byte) 0x4E, (byte) 0x49, (byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00
	}, DNI_ATR_MASK);


	private static final byte[] TIF_ATR_MASK = DNI_ATR_MASK;
	private static final Atr TIF_ATR = new Atr(new byte[] {
		(byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x54,
		(byte) 0x49, (byte) 0x46, (byte) 0x31, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00
	}, TIF_ATR_MASK);


	private static final byte[] FNMT_TC_430_ATR_MASK = DNI_ATR_MASK;
	private static final Atr FNMT_TC_430_ATR = new Atr(new byte[] {
		(byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x46,
		(byte) 0x4E, (byte) 0x4D, (byte) 0x54, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00
	}, FNMT_TC_430_ATR_MASK);


	// ********* FIN ATR DNIe Y COMPATIBLES *************************************
	// **************************************************************************

	// **************************************************************************
	// ********************* ATR FNMT-CERES *************************************

	private static final byte[] CERES_TC_ATR_MASK = {
		(byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr CERES_TC_ATR = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x46,
        (byte) 0x4E, (byte) 0x4d, (byte) 0x54, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, CERES_TC_ATR_MASK);


	private static final byte[] CERES_ST_ATR_MASK = {
		(byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00,
		(byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr CERES_ST_ATR = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x43,
        (byte) 0x45, (byte) 0x52, (byte) 0x45, (byte) 0x53, (byte) 0x02, (byte) 0x2c, (byte) 0x34, (byte) 0x00,
        (byte) 0x00, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, CERES_ST_ATR_MASK);


	private static final byte[] CERES_SLE_FN20_ATR_MASK = {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr CERES_SLE_FN20_ATR = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0xeF, (byte) 0x00, (byte) 0x00, (byte) 0x40, (byte) 0x14, (byte) 0x80, (byte) 0x25,
        (byte) 0x43, (byte) 0x45, (byte) 0x52, (byte) 0x45, (byte) 0x53, (byte) 0x57, (byte) 0x05, (byte) 0x60,
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, CERES_SLE_FN20_ATR_MASK);


	private static final byte[] CERES_SLE_FN19_ATR_MASK = {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr CERES_SLE_FN19_ATR = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0xeF, (byte) 0x00, (byte) 0x00, (byte) 0x40, (byte) 0x14, (byte) 0x80, (byte) 0x25,
        (byte) 0x43, (byte) 0x45, (byte) 0x52, (byte) 0x45, (byte) 0x53, (byte) 0x57, (byte) 0x01, (byte) 0x16,
        (byte) 0x01, (byte) 0x01, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, CERES_SLE_FN19_ATR_MASK);

	// ********************* FIN ATR FNMT-CERES *********************************
	// **************************************************************************

	// **************************************************************************
	// ********************* ATR G&D SMARTCAFE **********************************

	private static final byte[] GIDE_SCAF_ATR_MASK = {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xf
	};

	/** ATR de tarjeta G&amp;D SmartCafe 3&#46;2. */
	private static final Atr GIDE_SCAF_ATR = new Atr(new byte[] {
		(byte) 0x3b, (byte) 0xf7, (byte) 0x18, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x31, (byte) 0xfe,
		(byte) 0x45, (byte) 0x73, (byte) 0x66, (byte) 0x74, (byte) 0x65, (byte) 0x2d, (byte) 0x6e, (byte) 0x66,
		(byte) 0xc4
	}, GIDE_SCAF_ATR_MASK);


	private static final byte[] GIDE_SCAF_MSC_ATR_MASK = {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};

	/** ATR de tarjeta MicroSD G&amp;D Mobile Security Card. */
	private static final Atr GIDE_SCAF_MSC_ATR = new Atr(new byte[] {
		(byte) 0x3b, (byte) 0x80, (byte) 0x80, (byte) 0x01, (byte) 0x01
	}, GIDE_SCAF_MSC_ATR_MASK);


	/** ATR de tarjeta G&amp;D SmartCafe 3&#46;2 con T=CL (v&iacute;a inal&aacute;mbrica). */
	private static final byte[] GIDE_SCAF_TCL_ATR_MASK = {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xf
	};

	private static final Atr GIDE_SCAF_TCL_ATR = new Atr(new byte[] {
		(byte) 0x3b, (byte) 0xf7, (byte) 0x18, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x31, (byte) 0xfe,
		(byte) 0x45, (byte) 0x73, (byte) 0x66, (byte) 0x74, (byte) 0x65, (byte) 0x2d, (byte) 0x6e, (byte) 0x66,
		(byte) 0xc4
	}, GIDE_SCAF_TCL_ATR_MASK);

	// ********************* FIN ATR G&D SMARTCAFE ******************************
	// **************************************************************************

	private JMultiCardProviderFactory() {
		// No instanciable
	}

	/** Obtiene el proveedor (con la conexi&oacute;n por defecto) correspondiente
	 * a la primera tarjeta encontrada en el sistema.
	 * @return Proveedor (con la conexi&oacute;n por defecto) correspondiente
	 *         a la primera tarjeta encontrada insertada o <code>null</code> si
	 *         no hay ninguna insertada, no ha lector de tarjetas o no se
	 *         encuentra ninguna tarjeta soportada. */
	public static Provider getProvider() {
		return getProvider((String)null);
	}

	/** Obtiene el proveedor (con la conexi&oacute;n indicada) correspondiente
	 * a la primera tarjeta encontrada en el sistema.
	 * @param connectionClassName Nombre de la clase de conexi&oacute;n a usar.
	 * @return Proveedor (con la conexi&oacute;n por defecto) correspondiente
	 *         a la primera tarjeta encontrada insertada o <code>null</code> si
	 *         no hay ninguna insertada, no ha lector de tarjetas o no se
	 *         encuentra ninguna tarjeta soportada. */
	public static Provider getProvider(final String connectionClassName) {
		final ApduConnection conn;
		try {
			conn = (ApduConnection) Class.forName(
				connectionClassName != null && !connectionClassName.isEmpty() ?
					connectionClassName :
						ProviderUtil.DEFAULT_PROVIDER_CLASSNAME
			).getConstructor().newInstance();
		}
		catch (final InstantiationException    |
			         IllegalAccessException    |
			         IllegalArgumentException  |
			         InvocationTargetException |
			         NoSuchMethodException     |
			         SecurityException         |
			         ClassNotFoundException e2) {
			throw new IllegalStateException(
				"No se ha podido instanciar la conexion " + //$NON-NLS-1$
					(connectionClassName != null && !connectionClassName.isEmpty() ?
						connectionClassName :
							ProviderUtil.DEFAULT_PROVIDER_CLASSNAME),
				e2
			);
		}
		final long[] terminals;
		try {
			terminals = conn.getTerminals(false);
		}
		catch (final ApduConnectionException e1) {
			LOGGER.warning(
				"No se ha podido obtener la lista de lectores de tarjetas del sistema: " + e1 //$NON-NLS-1$
			);
			return null;
		}

		for (final long terminal : terminals) {
			try {
				conn.setTerminal((int) terminal);
			}
			catch (final ApduConnectionException e1) {
				LOGGER.warning("Numero de terminal no valido (" + terminal + "): " + e1); //$NON-NLS-1$ //$NON-NLS-2$
				continue;
			}
			try {
				final byte[] atr = conn.reset();
				final Provider provider = getProvider(atr);
				if (provider != null) {
					return provider;
				}
			}
			catch (final CardNotPresentException e) {
				LOGGER.info("No hay tarjeta insertada en el lector " + terminal + ": " + e); //$NON-NLS-1$ //$NON-NLS-2$
			}
			catch(final Exception e) {
				LOGGER.warning("Error reiniciando el lector " + terminal + ": " + e); //$NON-NLS-1$ //$NON-NLS-2$
			}
		}
		return null;
	}

	/** Obtiene el proveedor (con la conexi&oacute;n por defecto) correspondiente
	 * a la tarjeta del ATR indicado.
	 * @param atr ATR de la tarjeta.
	 * @return Proveedor (con la conexi&oacute;n por defecto) correspondiente
	 *         a la tarjeta del ATR indicado o <code>null</code> si el ATR no
	 *         es de ninguna tarjeta soportada. */
	public static Provider getProvider(final byte[] atr) {
		if (atr == null) {
			return null;
		}
		if (isDni(atr) || isCeres430(atr)) {
			return new DnieProvider();
		}
		if (isCeres(atr)) {
			return new CeresProvider();
		}
		if (isGiDeSmartCafe(atr)) {
			return new SmartCafeProvider();
		}
		return null;
	}

	private static boolean isDni(final byte[] atr) {
		return
			DNI_ATR.equals(new Atr(atr, DNI_ATR_MASK)) ||
			TIF_ATR.equals(new Atr(atr, TIF_ATR_MASK)) ||
			DNI_NFC_ATR.equals(new Atr(atr, DNI_NFC_ATR_MASK));
	}

	private static boolean isCeres430(final byte[] atr) {
		return FNMT_TC_430_ATR.equals(new Atr(atr, FNMT_TC_430_ATR_MASK)) && atr[15] >= (byte) 0x04 && atr[16] >= (byte) 0x30;
	}

	private static boolean isCeres(final byte[] atr) {
		return
			CERES_TC_ATR.equals(new Atr(atr, CERES_TC_ATR_MASK))             ||
			CERES_ST_ATR.equals(new Atr(atr, CERES_ST_ATR_MASK))             ||
			CERES_SLE_FN20_ATR.equals(new Atr(atr, CERES_SLE_FN20_ATR_MASK)) ||
			CERES_SLE_FN19_ATR.equals(new Atr(atr, CERES_SLE_FN19_ATR_MASK));
	}

	private static boolean isGiDeSmartCafe(final byte[] atr) {
		return
			GIDE_SCAF_ATR.equals(new Atr(atr, GIDE_SCAF_ATR_MASK))         ||
			GIDE_SCAF_MSC_ATR.equals(new Atr(atr, GIDE_SCAF_MSC_ATR_MASK)) ||
			GIDE_SCAF_TCL_ATR.equals(new Atr(atr, GIDE_SCAF_TCL_ATR_MASK));
	}
}
