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

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneV2Connection;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;

/** DNI Electr&oacute;nico versi&oacute;n 3.0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class Dnie3 extends Dnie {

    protected static final Location FILE_DG01_LOCATION_MRZ   = new Location("3F010101"); //$NON-NLS-1$
    protected static final Location FILE_DG02_LOCATION_PHOTO = new Location("3F010102"); //$NON-NLS-1$
    protected static final Location FILE_DG07_LOCATION_SIGN  = new Location("3F010107"); //$NON-NLS-1$

    /** Obtiene la foto del titular en formato JPEG2000.
     * @return Foto del titular en formato JPEG2000. */
	@SuppressWarnings("static-method")
	public byte[] getSubjectPhotoAsJpeg2k() {
		throw new UnsupportedOperationException();
	}

	/** Obtiene la MRZ del DNIe 3.0.
	 * @return MRZ del DNIe 3.0. */
	@SuppressWarnings("static-method")
	public Dnie3Dg01Mrz getMrz() {
		throw new UnsupportedOperationException();
	}

	/** Obtiene la imagen de la firma del titular en formato JPEG2000.
     * @return Imagen de la firma del titular en formato JPEG2000. */
	@SuppressWarnings("static-method")
	public byte[] getSubjectSignatureImageAsJpen2k() {
		throw new UnsupportedOperationException();
	}

    /** Conexi&oacute;n inicial con la tarjeta, sin ning&uacute;n canal seguro. */
    protected ApduConnection rawConnection;

    /** Construye una clase que representa un DNIe.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre m&aacute;quinas virtuales.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla.*/
    Dnie3(final ApduConnection conn,
    	  final PasswordCallback pwc,
    	  final CryptoHelper cryptoHelper,
    	  final CallbackHandler ch) throws ApduConnectionException {
        super(conn, pwc, cryptoHelper, ch);
        this.rawConnection = conn;
    }

    /** Abre el canal seguro de usuario.
     * @return Nueva conexi&oacute;n establecida.
     * @throws CryptoCardException Si hay problemas en la apertura de canal. */
    public ApduConnection openUserChannel() throws CryptoCardException {
    	final ApduConnection usrSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		this.getConnection(),
    		getCryptoHelper(),
    		new Dnie3UsrCwa14890Constants()
		);

		try {
			selectMasterFile();
		}
		catch (final Exception e) {
			throw new CryptoCardException(
        		"Error seleccionado el MF tras el establecimiento del canal seguro de usuario: " + e, e //$NON-NLS-1$
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
    	return this.getConnection();
    }

    /** Si no se hab&iacute;a hecho anteriormente, establece y abre el canal seguro de PIN CWA-14890,
     * solicita y comprueba el PIN e inmediatamente despu&eacute;s y, si la verificaci&oacute;n es correcta,
     * establece el canal de USUARIO CWA-14890.
     * Si falla alg&uacute;n punto del proceso, vuelve al modo inicial de conexi&oacute;n (sin canal seguro).
     * @throws CryptoCardException Si hay problemas en el proceso.
     * @throws BadPinException Si el PIN usado para la apertura de canal no es v&aacute;lido. */
	@Override
	protected void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException, PinException {

        // Si el canal seguro esta ya abierto salimos sin hacer nada
        if (this.isSecurityChannelOpen()) {
        	return;
        }

        // Reestablecemos el canal inicial, para estar seguros de que no tenemos un canal CWA
        // establecido pero cerrado
        try {
			setConnection(this.rawConnection);
		}
        catch (final ApduConnectionException e) {
        	throw new CryptoCardException(
        		"Error en el establecimiento del canal inicial previo al seguro de PIN: " + e, e //$NON-NLS-1$
    		);
		}

        // Establecemos el canal PIN y lo verificamos
    	final ApduConnection pinSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		this.getConnection(),
    		getCryptoHelper(),
    		new Dnie3PinCwa14890Constants()
		);

		try {
			selectMasterFile();
		}
		catch (final Exception e) {
			throw new CryptoCardException(
        		"Error seleccionado el MF tras el establecimiento del canal seguro de PIN: " + e, e //$NON-NLS-1$
    		);
		}

        try {
            this.setConnection(pinSecureConnection);
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
        catch (final ApduConnectionException e) {
            throw new CryptoCardException(
        		"Error en la verificacion de PIN: " + e, e //$NON-NLS-1$
    		);
        }

        // Y establecemos ahora el canal de usuario
        final ApduConnection usrSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		this.getConnection(),
    		getCryptoHelper(),
    		new Dnie3UsrCwa14890Constants()
		);

		try {
			selectMasterFile();
		}
		catch (final Exception e) {
			throw new CryptoCardException(
        		"Error seleccionado el MF tras el establecimiento del canal seguro de usuario: " + e, e //$NON-NLS-1$
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

    /** Carga los certificados del usuario para utilizarlos cuando se desee (si no estaban ya cargados).
     * @throws CryptoCardException Cuando se produce un error en la operaci&oacute;n con la tarjeta.
     * @throws BadPinException */
    @Override
	protected void loadCertificates() throws CryptoCardException, PinException {
    	// Abrimos el canal si es necesario
    	openSecureChannelIfNotAlreadyOpened();
    	loadCertificatesInternal();
    }

    /** {@inheritDoc} */
    @Override
    public byte[] sign(final byte[] data,
    		           final String signAlgorithm,
    		           final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                 PinException {
    	final byte[] ret = signInternal(data, signAlgorithm, privateKeyReference);

        // Reestablecemos el canal inicial, para que en una segunda firma se tenga que volver a pedir
    	// el PIN y rehacer los canales CWA
        try {
        	this.rawConnection.reset();
    		setConnection(this.rawConnection);
		}
        catch (final ApduConnectionException e) {
        	throw new CryptoCardException(
        		"Error en el establecimiento del canal inicial previo al seguro de PIN: " + e, e //$NON-NLS-1$
    		);
		}

    	return ret;
    }
}