package com.accenture.es.hps;

import com.accenture.es.hps.IosNfcConnection.WrappedAtr;
import com.accenture.es.hps.IosNfcConnection.WrappedResponseApdu;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;

/** Clase a implementar en iOS para la comunicaci&oacute;n con una tarjeta por NFC.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class IosNfcConnectionImpl {

	/** Abre la conexi&oacute;n con la tarjeta inteligente en el rango del interfaz NFC.
     * @return C&oacute;digo de error (0 = Todo OK). */
	@SuppressWarnings("static-method")
	public int open() {
    	System.out.println("AQUI ABRIMOS CONEXION"); //$NON-NLS-1$
    	return 0;
	}

	/** Cierra la conexi&oacute;n con la tarjeta inteligente.
     * @return C&oacute;digo de error (0 = Todo OK). */
	@SuppressWarnings("static-method")
	public int close() {
    	System.out.println("AQUI CERRAMOS CONEXION"); //$NON-NLS-1$
    	return 0;
	}

	/** Indica si la conexi&oacute;n con la tarjeta est&aacute; abierta o no.
     * @return <code>true</code> si la conexi&oacute;n esta abierta, <code>false</code> si est&aacute; cerrada. */
	@SuppressWarnings("static-method")
	public boolean isOpen() {
		System.out.println("AQUI COMPROBAMOS SI LA CONEXION ESTA ABIERTA"); //$NON-NLS-1$
		return true;
	}

	/** Env&iacute;a un comando APDU a la tarjeta inteligente.
     * @param commandApdu APDU que se desea enviar a la tarjeta.
     * @return Respuesta de la tarjeta al env&iacute;o. */
	@SuppressWarnings("static-method")
	public WrappedResponseApdu transmit(final CommandApdu commandApdu) {
		System.out.println("AQUI TRANSMITIMOS APDUs"); //$NON-NLS-1$
		final ResponseApdu responseFromCard = new ResponseApdu(new byte[] { (byte) 0x90, (byte) 0x00 });
		return new WrappedResponseApdu(responseFromCard, 0);
	}

	/** Obtiene la respuesta al reset (ATR) de la tarjeta.
     * @return Respuesta al reset (ATR) de la tarjeta. */
	@SuppressWarnings("static-method")
	public WrappedAtr reset() {
		System.out.println("AQUI OBTENGO Y DEVUELVO EL ATR (HistoricalBytes) DE LA TARJETA"); //$NON-NLS-1$
		return new WrappedAtr(new byte[] { 0x00 }, 0);
	}
}
