/*
 * Controlador Java de la Secretaria de Estado de Administraciones Publicas
 * para el DNI electronico.
 *
 * El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
 * que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
 * para la realizacion de procesos de autenticacion, firma electronica y validacion
 * de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
 * el acceso a los certificados y claves del DNI electronico, asi como la realizacion
 * de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
 * sido disenado para su funcionamiento independiente del sistema operativo final.
 *
 * Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
 * e Impulso de la Administracion Electronica
 *
 * Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
 * o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
 * licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
 * en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
 * su compatibilidad con otros componentes.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * Lesser GNU General Public License publicada por la Free Software Foundation,
 * tanto en la version 2.1 de la Licencia, o en una version posterior.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * European Union Public License publicada por la Comision Europea,
 * tanto en la version 1.1 de la Licencia, o en una version posterior.
 *
 * Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
 *
 * Deberia recibir una copia de la European Union Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
 *
 * Este programa es distribuido con la esperanza de que sea util, pero
 * SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
 * o idoneidad para un proposito particular.
 */
package es.gob.jmulticard.card.dnie;

import java.io.IOException;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneV2Connection;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PasswordCallbackNotFoundException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.icao.Dg13Identity;
import es.gob.jmulticard.card.icao.MrtdLds1;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** DNI Electr&oacute;nico versi&oacute;n 3&#46;0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class Dnie3 extends Dnie implements MrtdLds1 {

    private String idesp = null;

    @Override
	public byte[] getCardAccess() throws IOException {
    	try {
			return selectFileByLocationAndRead(FILE_CARD_ACCESS_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el CardAccess del DNIe: " + e, e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getAtrInfo() throws IOException {
    	try {
			return selectFileByLocationAndRead(FILE_ATR_INFO_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el ATR/INFO del DNIe: " + e, e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getDg1() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG01_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG1 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg2() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG02_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG2 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg7() throws IOException {
		try {
			return selectFileByLocationAndRead(MrtdLds1.FILE_DG07_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG7 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg11() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG11_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG11 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg12() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG12_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG12 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg13() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG13_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG13 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg14() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG14_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG14 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getSOD() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_SOD_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el SOD del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getCOM() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_COM_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el 'Common Data' (COM) del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

	@Override
	public byte[] getSubjectPhotoAsJpeg2k() throws IOException {
		final byte[] photo = getDg2();
		return extractImage(photo);
	}

	@Override
	public Mrz getMrz() throws IOException {
		final byte[] mrz = getDg1();
		return new Dnie3Dg01Mrz(mrz);
	}

	@Override
	public Dg13Identity getIdentity() throws IOException {
		return new Dg13Identity(getDg13());
	}

	@Override
	public byte[] getSubjectSignatureImageAsJpeg2k() throws IOException {
		final byte[] photo = getDg7();
		return extractImage(photo);
	}

    private static final String JPEG2K_HEADER = "0000000C6A502020"; //$NON-NLS-1$

    private static final byte[] extractImage(final byte[] photo) {
    	if (photo == null) {
    		throw new IllegalArgumentException("Los datos de entrada no pueden ser nulos"); //$NON-NLS-1$
    	}
    	final int headerSize = HexUtils.hexify(photo, false).indexOf(JPEG2K_HEADER) / 2;
    	final byte[] pj2kPhoto = new byte[photo.length - headerSize];
        System.arraycopy(photo, headerSize, pj2kPhoto, 0, pj2kPhoto.length);

        // En este punto pj2kPhoto contiene la imagen en JPEG2000
        return pj2kPhoto;
    }

    /** {@inheritDoc} */
	@Override
    public String getCardName() {
        return "DNIe 3.0"; //$NON-NLS-1$
    }

    /** Construye una clase que representa un DNIe.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden
     *                     variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de las <i>Callbacks</i> (PIN, confirmaci&oacute;n, etc.).
     * @param loadCertsAndKeys Si se indica <code>true</code>, se cargan las referencias a
     *                         las claves privadas y a los certificados, mientras que si se
     *                         indica <code>false</code>, no se cargan, permitiendo la
     *                         instanciaci&oacute;n de un DNIe sin capacidades de firma o
     *                         autenticaci&oacute;n con certificados.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona
     *                                 cerrada y no es posible abrirla.*/
    protected Dnie3(final ApduConnection conn,
    	  final PasswordCallback pwc,
    	  final CryptoHelper cryptoHelper,
    	  final CallbackHandler ch,
     	  final boolean loadCertsAndKeys) throws ApduConnectionException {
        super(conn, pwc, cryptoHelper, ch, loadCertsAndKeys);
        this.rawConnection = conn;
        if (loadCertsAndKeys) {
        	try {
				loadCertificates();
			}
        	catch (final CryptoCardException e) {
				throw new ApduConnectionException(
					"Error cargando los certificados del DNIe 3.0: " + e, e //$NON-NLS-1$
				);
			}
        }

    	// Identificamos numero de soporte (IDESP)
		try {
			this.idesp = getIdesp();
		}
		catch (final Exception e1) {
			LOGGER.warning("No se ha podido leer el IDESP del DNIe: " + e1); //$NON-NLS-1$
			this.idesp = null;
		}
    }

    /** Construye una clase que representa un DNIe.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden
     *                     variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de las <i>Callbacks</i> (PIN, confirmaci&oacute;n, etc.).
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona
     *                                 cerrada y no es posible abrirla.*/
    Dnie3(final ApduConnection conn,
    	  final PasswordCallback pwc,
    	  final CryptoHelper cryptoHelper,
    	  final CallbackHandler ch) throws ApduConnectionException {
        this(conn, pwc, cryptoHelper, ch, true);
    }

    /** Abre el canal seguro de usuario.
     * @return Nueva conexi&oacute;n establecida.
     * @throws CryptoCardException Si hay problemas en la apertura de canal. */
    public ApduConnection openUserChannel() throws CryptoCardException {

    	final ApduConnection usrSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		getConnection(),
    		getCryptoHelper(),
    		DnieFactory.getDnie3UsrCwa14890Constants(this.idesp),
    		DnieFactory.getDnie3UsrCwa14890Constants(this.idesp)
		);

		try {
			selectMasterFile();
		}
		catch (final Exception e) {
			throw new CryptoCardException(
        		"Error seleccionando el MF tras el establecimiento del canal seguro de usuario: " + e, e //$NON-NLS-1$
    		);
		}

        try {
            setConnection(usrSecureConnection);
        }
        catch (final ApduConnectionException e) {
            throw new CryptoCardException(
        		"Error en el establecimiento del canal seguro de usuario: " + e, e //$NON-NLS-1$
    		);
        }
    	return getConnection();
    }

    /** Si no se hab&iacute;a hecho anteriormente, establece y abre el canal seguro de PIN CWA-14890,
     * solicita y comprueba el PIN e inmediatamente despu&eacute;s y, si la verificaci&oacute;n es correcta,
     * establece el canal de <b>usuario</b> CWA-14890.
     * Si falla alg&uacute;n punto del proceso, vuelve al modo inicial de conexi&oacute;n (sin canal seguro).
     * @throws CryptoCardException Si hay problemas en el proceso.
     * @throws PinException Si el PIN usado para la apertura de canal no es v&aacute;lido. */
	@Override
	public void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException, PinException {
		openSecureChannelIfNotAlreadyOpened(true);
	}

	@Override
	public void openSecureChannelIfNotAlreadyOpened(final boolean doChv) throws CryptoCardException, PinException {

        // Si el canal seguro esta ya abierto salimos sin hacer nada
        if (isSecurityChannelOpen()) {
        	return;
        }

        if (DEBUG) {
        	LOGGER.info("Conexion actual: " + getConnection()); //$NON-NLS-1$
        	LOGGER.info("Conexion subyacente: " + this.rawConnection); //$NON-NLS-1$
        }

        // Si la conexion esta cerrada, la reestablecemos
        if (!getConnection().isOpen()) {
	        try {
				setConnection(this.rawConnection);
			}
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException(
	        		"Error en el establecimiento del canal inicial previo al seguro de PIN: " + e, e //$NON-NLS-1$
	    		);
			}
        }

        if (doChv) {
	        // Establecemos el canal PIN y lo verificamos
	        final ApduConnection pinSecureConnection = new Cwa14890OneV2Connection(
	    		this,
	    		getConnection(),
	    		getCryptoHelper(),
	    		DnieFactory.getDnie3PinCwa14890Constants(this.idesp),
	    		DnieFactory.getDnie3PinCwa14890Constants(this.idesp)
			);

	        try {
	        	selectMasterFile();
	        }
	        catch (final Exception e) {
	        	LOGGER.warning(
	    			"Error seleccionando el MF tras el establecimiento del canal seguro de PIN: " + e //$NON-NLS-1$
				);
	        }

	        try {
	        	setConnection(pinSecureConnection);
	        }
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException(
	    			"Error en el establecimiento del canal seguro de PIN: " + e, e //$NON-NLS-1$
				);
	        }

	        LOGGER.info("Canal seguro de PIN para DNIe establecido"); //$NON-NLS-1$

	        try {
	        	verifyPin(getInternalPasswordCallback());
	        }
	        catch (final PasswordCallbackNotFoundException e) {
	        	// Si no se indico un medio para obtener el PIN, ignoramos el establecimiento del canal
	        	// de PIN, pero continuamos para establecer el canal de usuario
	        	LOGGER.info("No se proporcionaron medios para verificar el canal de PIN: " + e); //$NON-NLS-1$
			}
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException(
	    			"Error en la verificacion de PIN: " + e, e //$NON-NLS-1$
				);
	        }
        }

        // Establecemos ahora el canal de usuario
        final ApduConnection usrSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		getConnection(),
    		getCryptoHelper(),
    		DnieFactory.getDnie3UsrCwa14890Constants(this.idesp),
    		DnieFactory.getDnie3UsrCwa14890Constants(this.idesp)
		);

		try {
			selectMasterFile();
		}
		catch (final Exception e) {
			throw new CryptoCardException(
        		"Error seleccionado el MF antes del establecimiento del canal seguro de usuario: " + e, e //$NON-NLS-1$
    		);
		}

        try {
            setConnection(usrSecureConnection);
        }
        catch (final ApduConnectionException e) {
            throw new CryptoCardException(
        		"Error en el establecimiento del canal seguro de usuario: " + e, e //$NON-NLS-1$
    		);
        }

        LOGGER.info("Canal seguro de Usuario para DNIe establecido"); //$NON-NLS-1$
    }

	/** {@inheritDoc} */
	@Override
	protected byte[] signInternal(final byte[] data,
                                  final String signAlgorithm,
                                  final PrivateKeyReference privateKeyReference) throws CryptoCardException,
                                                                                        PinException {
		if (!(privateKeyReference instanceof DniePrivateKeyReference)) {
            throw new IllegalArgumentException(
        		"La referencia a la clave privada tiene que ser de tipo DniePrivateKeyReference" //$NON-NLS-1$
    		);
        }
        return signOperation(data, signAlgorithm, privateKeyReference);
	}

	//*************************************************************************
	//********** METODOS DE ICAO MRTD LDS1 NO SOPORTADOS **********************

    @Override
	public byte[] getCardSecurity() throws IOException {
    	throw new UnsupportedOperationException(
			"El DNIe 3.0 no tiene CardSecurity" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg3() throws IOException {
    	throw new UnsupportedOperationException(
			"Hace falta canal de administrador para leer el DG3" //$NON-NLS-1$
		);
	}

    @Override
	public byte[] getDg4() throws IOException {
    	throw new UnsupportedOperationException(
			"Hace falta canal de administrador para leer el DG4" //$NON-NLS-1$
		);
	}

    @Override
	public byte[] getDg5() throws IOException {
    	throw new UnsupportedOperationException(
			"El DNIe 3.0 no tiene DG5" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg6() throws IOException {
    	throw new UnsupportedOperationException(
			"El DNIe 3.0 no tiene DG6" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg8() throws IOException {
    	throw new UnsupportedOperationException(
			"El DNIe 3.0 no tiene DG8" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg9() throws IOException {
    	throw new UnsupportedOperationException(
			"El DNIe 3.0 no tiene DG9" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg10() throws IOException {
    	throw new UnsupportedOperationException(
			"El DNIe 3.0 no tiene DG10" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg15() throws IOException {
    	throw new UnsupportedOperationException(
			"El DNIe 3.0 no tiene DG15" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg16() throws IOException {
    	throw new UnsupportedOperationException(
			"El DNIe 3.0 no tiene DG16" //$NON-NLS-1$
		);
    }

}