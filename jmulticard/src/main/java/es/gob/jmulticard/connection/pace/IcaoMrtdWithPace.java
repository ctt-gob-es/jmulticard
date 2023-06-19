package es.gob.jmulticard.connection.pace;

import java.io.FileNotFoundException;
import java.io.IOException;

import javax.security.auth.callback.CallbackHandler;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.CryptoCardSecurityException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.DnieNfc;
import es.gob.jmulticard.card.icao.IcaoException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.card.iso7816four.RequiredSecurityStateNotSatisfiedException;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;

/** Pasaporte accedido de forma inal&aacute;mbrica mediante PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class IcaoMrtdWithPace extends DnieNfc {

	/** Construye una clase que representa un MRTD accedido de forma
	 * inal&aacute;mbrica mediante PACE.
	 * @param conn Conexi&oacute;n con el lector NFC.
	 * @param cryptoHlpr Clase de utilidad de funciones criptogr&aacute;ficas.
	 * @param ch <code>CallbackHandler</code> que debe proporcionar, mediante un
	 *           <code>es.gob.jmulticard.callback.CustomTextInputCallback</code> o
	 *           un <code>javax.security.auth.callback.TextInputCallback</code>, el
	 *           CAN o la MRZ del MRTD.
	 * @throws IcaoException Si no se puede establecer el canal PACE.
	 * @throws ApduConnectionException Si no se puede establecer la conexi&oacute;n NFC. */
	public IcaoMrtdWithPace(final ApduConnection conn,
			                       final CryptoHelper cryptoHlpr,
			                       final CallbackHandler ch) throws IcaoException,
	                                                                ApduConnectionException {
		super(
			conn,
			null,          // No hay PIN
			cryptoHlpr,
			ch,            // CallbackHandler, debe proporcionar la MRZ o el CAN
			false          // No se cargan claves ni certificados
		);
	}

	@Override
    public String getCardName() {
        return "MRTD accedido de forma inalambrica mediante PACE"; //$NON-NLS-1$
    }

	@Override
	public void openSecureChannelIfNotAlreadyOpened() {
		LOGGER.warning(
			"No se permite apertura de canal CWA-14890, se ignora la peticion" //$NON-NLS-1$
		);
	}

	@Override
	public void openSecureChannelIfNotAlreadyOpened(final boolean doChv) {
		LOGGER.warning(
			"No se permite apertura de canal CWA-14890, se ignora la peticion" //$NON-NLS-1$
		);
	}

    @Override
    public byte[] sign(final byte[] data,
    		           final String signAlgorithm,
    		           final PrivateKeyReference privateKeyRef) {
    	throw new UnsupportedOperationException(
			"No se permite firmar con MRTD" //$NON-NLS-1$
		);
    }

	@Override
	public String toString() {
		return getCardName();
	}

	//***************************************************************************
	//* METODOS ICAO NO PRESENTES EN DNIE PERO QUE SI PUEDEN ESTAR EN OTRO MRTD *

    @Override
	public byte[] getCardSecurity() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_CARD_SECURITY_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("CardSecurity no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el CardSecurity", e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getDg3() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG03_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG3 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG3", e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg4() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG04_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG4 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch(final RequiredSecurityStateNotSatisfiedException e) {
			throw new CryptoCardSecurityException(
				"Se necesita canal de adminstrador para leer el DG4", e //$NON-NLS-1$
			);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG4", e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg5() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG05_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG5 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG5", e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getDg6() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG06_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG6 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG6", e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getDg8() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG08_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG8 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG8", e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getDg9() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG09_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG9 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG9", e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getDg10() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG10_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG10 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG10", e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getDg15() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG15_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG15 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG15", e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getDg16() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG16_LOCATION);
		}
		catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG16 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG16", e); //$NON-NLS-1$
		}
    }

}
