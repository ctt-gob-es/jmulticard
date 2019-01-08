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
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** DNI Electr&oacute;nico versi&oacute;n 3&#46;0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class Dnie3 extends Dnie {

    private static final Location FILE_DG01_LOCATION_MRZ   = new Location("3F010101"); //$NON-NLS-1$
    private static final Location FILE_DG02_LOCATION_PHOTO = new Location("3F010102"); //$NON-NLS-1$
    private static final Location FILE_DG07_LOCATION_SIGN  = new Location("3F010107"); //$NON-NLS-1$
    private static final Location FILE_DG11_LOCATION       = new Location("3F01010B"); //$NON-NLS-1$
    private static final Location FILE_DG12_LOCATION       = new Location("3F01010C"); //$NON-NLS-1$
    private static final Location FILE_DG13_LOCATION       = new Location("3F01010D"); //$NON-NLS-1$
    private static final Location FILE_DG14_LOCATION       = new Location("3F01010E"); //$NON-NLS-1$
    private static final Location FILE_SOD_LOCATION        = new Location("3F01011D"); //$NON-NLS-1$
    private static final Location FILE_COM_LOCATION        = new Location("3F01011E"); //$NON-NLS-1$

    /** Obtiene el DG1. Devuelve el objeto binario sin tratar.
     * El DG1 contiene el campo MRZ. Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG1 (con el MRZ).
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getDg1() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG01_LOCATION_MRZ);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG1 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    /** Obtiene el DG2. Devuelve el objeto binario sin tratar.
     * El DG2 contiene la fotograf&iacute;a  del documento.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG2.
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getDg2() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG02_LOCATION_PHOTO);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG2 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    /** Obtiene el DG7. Devuelve el objeto binario sin tratar.
     * El DG7 contiene la imagen de la firma del poseedor del documento.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG7.
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getDg7() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG07_LOCATION_SIGN);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG7 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

	/** Obtiene el DG11. Devuelve el objeto binario sin tratar.
     * El DG11 contiene detalles adicionales sobre el poseedor del documento.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG11.
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getDg11() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG11_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG11 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    /** Obtiene el DG12. Devuelve el objeto binario sin tratar.
     * El DG12 contiene datos adicionales del documento.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG12.
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getDg12() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG12_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG12 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    /** Obtiene el DG13. Devuelve el objeto binario sin tratar.
     * El DG12 contiene detalles opcionales.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG13.
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getDg13() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG13_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG13 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    /** Obtiene el DG14. Devuelve el objeto binario sin tratar.
     * El DG12 contiene opciones de seguridad.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG14.
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getDg14() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG14_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG14 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    /** Obtiene el SOD. Devuelve el objeto binario sin tratar.
     * El SOD contiene las huellas digitales de los DG.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return SOD.
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getSOD() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_SOD_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG11 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    /** Obtiene el COM. Devuelve el objeto binario sin tratar.
     * El COM contiene los "datos comunes" (<i>Common Data</i>).
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return COM.
     * @throws IOException Si hay problemas leyendo el fichero. */
    public byte[] getCOM() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_COM_LOCATION);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG11 del DNIe: " + e, e); //$NON-NLS-1$
		}
	}

    /** Obtiene la foto del titular en formato JPEG2000.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @return Foto del titular en formato JPEG2000.
     * @throws IOException Si no se puede leer la foto del titular. */
	public byte[] getSubjectPhotoAsJpeg2k() throws IOException {
		final byte[] photo = getDg2();
		return extractImage(photo);
	}

	/** Obtiene la MRZ del DNIe 3&#46;0.
	 * Necesita que el canal de usuario est&eacute; previamente establecido.
	 * @return MRZ del DNIe 3&#46;0.
	 * @throws IOException Si no se puede leer el fichero con el MRZ del DNIe. */
	public Dnie3Dg01Mrz getMrz() throws IOException {
		final byte[] mrz = getDg1();
		return new Dnie3Dg01Mrz(mrz);
	}

	/** Obtiene la imagen de la firma del titular en formato JPEG2000.
	 * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @return Imagen de la firma del titular en formato JPEG2000.
	 * @throws IOException Si no se puede leer la imagen con la firma del titular. */
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
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de las <i>Callbacks</i> (PIN, confirmaci&oacute;n, etc.).
     * @param loadCertsAndKeys Si se indica <code>true</code>, se cargan las referencias a
     *                         las claves privadas y a los certificados, mientras que si se
     *                         indica <code>false</code>, no se cargan, permitiendo la
     *                         instanciaci&oacute;n de un DNIe sin capacidades de firma o
     *                         autenticaci&oacute;n con certificados.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla.*/
    Dnie3(final ApduConnection conn,
    	  final PasswordCallback pwc,
    	  final CryptoHelper cryptoHelper,
    	  final CallbackHandler ch,
     	 final boolean loadCertsAndKeys) throws ApduConnectionException {
        super(conn, pwc, cryptoHelper, ch, loadCertsAndKeys);
        this.rawConnection = conn;
    }

    /** Construye una clase que representa un DNIe.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de las <i>Callbacks</i> (PIN, confirmaci&oacute;n, etc.).
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla.*/
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
    		new Dnie3UsrCwa14890Constants(),
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

        // Si el canal seguro esta ya abierto salimos sin hacer nada
        if (isSecurityChannelOpen()) {
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

        PasswordCallback pwc;
        try {
        	pwc = getInternalPasswordCallback();
        }
        catch(final PinException e) {
        	pwc = null;
        }

        if (pwc != null) {
	        // Establecemos el canal PIN y lo verificamos
	    	final ApduConnection pinSecureConnection = new Cwa14890OneV2Connection(
	    		this,
	    		getConnection(),
	    		getCryptoHelper(),
	    		new Dnie3PinCwa14890Constants(),
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
    		new Dnie3UsrCwa14890Constants(),
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
     * @throws PinException Si el PIN usado para la apertura de canal no es v&aacute;lido. */
    @Override
	protected void loadCertificates() throws CryptoCardException, PinException {
    	// Abrimos el canal si es necesario
    	openSecureChannelIfNotAlreadyOpened();
    	loadCertificatesInternal();
    }
}