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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneV2Connection;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.icao.Com;
import es.gob.jmulticard.asn1.icao.DataGroupHash;
import es.gob.jmulticard.asn1.icao.LdsSecurityObject;
import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.asn1.icao.Sod;
import es.gob.jmulticard.asn1.icao.SubjectFacePhoto;
import es.gob.jmulticard.asn1.icao.SubjectSignaturePhoto;
import es.gob.jmulticard.card.CardSecurityException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.CryptoCardSecurityException;
import es.gob.jmulticard.card.PasswordCallbackNotFoundException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.icao.InvalidSecurityObjectException;
import es.gob.jmulticard.card.icao.MrtdLds1;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.card.iso7816four.RequiredSecurityStateNotSatisfiedException;

/** DNI Electr&oacute;nico versi&oacute;n 3&#46;0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class Dnie3 extends Dnie implements MrtdLds1 {

    private String idesp = null;

	@Override
	public X509Certificate[] checkSecurityObjects() throws IOException,
	                                                       InvalidSecurityObjectException,
	                                                       TlvException,
	                                                       Asn1Exception,
	                                                       SignatureException,
	                                                       CertificateException {
		openSecureChannelIfNotAlreadyOpened(false);
		final Sod sod = getSod();
		sod.validateSignature();
		final LdsSecurityObject ldsSecurityObject = sod.getLdsSecurityObject();

		final MessageDigest md;
		try {
			md = MessageDigest.getInstance(
				ldsSecurityObject.getDigestAlgorithm()
			);
		}
		catch (final NoSuchAlgorithmException e) {
			throw new IOException(
				"No se soporta el algoritmo de huella indicado en el SOD (" + //$NON-NLS-1$
					ldsSecurityObject.getDigestAlgorithm() +
						"): " + e, e //$NON-NLS-1$
			);
		}

		openSecureChannelIfNotAlreadyOpened(false);

		for (final DataGroupHash dgh : ldsSecurityObject.getDataGroupHashes()) {

			final byte[] dgBytes;
			switch(dgh.getDataGroupNumber()) {
				case 1:
					dgBytes = getDg1().getBytes();
					break;
				case 2:
					dgBytes = getDg2().getBytes();
					break;
				case 3:
					// El DG3 necesita canal administrativo, le damos un tratamiento especial
					// para permitir verificar solo con canal de usuario
					try {
						dgBytes = getDg3();
					}
					catch(final CardSecurityException e) {
						LOGGER.warning(
							"Se omite la comprobacion del DG3 con el SOD por no poder leerse: " + e //$NON-NLS-1$
						);
						continue;
					}
					break;
				case 4:
					dgBytes = getDg4();
					break;
				case 5:
					dgBytes = getDg5();
					break;
				case 6:
					dgBytes = getDg6();
					break;
				case 7:
					dgBytes = getDg7().getBytes();
					break;
				case 8:
					dgBytes = getDg8();
					break;
				case 9:
					dgBytes = getDg9();
					break;
				case 10:
					dgBytes = getDg10();
					break;
				case 11:
					dgBytes = getDg11();
					break;
				case 12:
					dgBytes = getDg12();
					break;
				case 13:
					dgBytes = getDg13().getBytes();
					break;
				case 14:
					dgBytes = getDg14();
					break;
				case 15:
					dgBytes = getDg15();
					break;
				case 16:
					dgBytes = getDg16();
					break;
				default:
					throw new InvalidSecurityObjectException(
						"El SOD define huella para un DG inexistente: " + dgh.getDataGroupNumber() //$NON-NLS-1$
					);
			}
			final byte[] actualHash = md.digest(dgBytes);
			md.reset();
			if (!Arrays.equals(actualHash, dgh.getDataGroupHashValue())) {
				throw new InvalidSecurityObjectException(
					"El DG" + dgh.getDataGroupNumber() + " no concuerda con la huella del SOD, " + //$NON-NLS-1$ //$NON-NLS-2$
						"se esperaba " + HexUtils.hexify(actualHash, false) + //$NON-NLS-1$
							" y se ha encontrado " + HexUtils.hexify(dgh.getDataGroupHashValue(), false) //$NON-NLS-1$
				);
			}
		}

		// Llegados aqui, todas las huellas coinciden
		return sod.getCertificateChain();
	}

    @Override
	public byte[] getCardAccess() throws IOException {
    	try {
			return selectFileByLocationAndRead(FILE_CARD_ACCESS_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("CardAcess no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el CardAccess: " + e, e); //$NON-NLS-1$
		}
    }

    @Override
	public byte[] getAtrInfo() throws IOException {
    	try {
			return selectFileByLocationAndRead(FILE_ATR_INFO_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("ATR/INFO no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el ATR/INFO: " + e, e); //$NON-NLS-1$
		}
    }

    @Override
	public Mrz getDg1() throws IOException {
		try {
			return new Dnie3Dg01Mrz(
				selectFileByLocationAndRead(FILE_DG01_LOCATION)
			);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG1 no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG1: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public SubjectFacePhoto getDg2() throws IOException {
    	final SubjectFacePhoto ret = new SubjectFacePhoto();
		try {
			ret.setDerValue(selectFileByLocationAndRead(FILE_DG02_LOCATION));
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG2 no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG2: " + e, e); //$NON-NLS-1$
		}
		return ret;
	}

    @Override
	public byte[] getDg3() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG03_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG3 no encontrado: " + e); //$NON-NLS-1$
    	}
		// El DG3 necesita canal administrativo, le damos un tratamiento especial
		catch(final RequiredSecurityStateNotSatisfiedException e) {
			throw new CardSecurityException(
				"No se tienen permisos para leer el DG3: " + e, e //$NON-NLS-1$
			);
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG3: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public SubjectSignaturePhoto getDg7() throws IOException {
    	final SubjectSignaturePhoto ret = new SubjectSignaturePhoto();
		try {
			ret.setDerValue(selectFileByLocationAndRead(FILE_DG07_LOCATION));
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG7 no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG7: " + e, e); //$NON-NLS-1$
		}
		return ret;
	}

    @Override
	public byte[] getDg11() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG11_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG11 no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG11: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg12() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG12_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG12 no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG12: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public OptionalDetails getDg13() throws IOException {
		try {
			final OptionalDetails ret = new OptionalDetailsDnie3();
			ret.setDerValue(
				selectFileByLocationAndRead(FILE_DG13_LOCATION)
			);
			return ret;
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG13 no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG13: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public byte[] getDg14() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG14_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("DG14 no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG14: " + e, e); //$NON-NLS-1$
		}
	}

    @Override
	public Sod getSod() throws IOException {
    	final Sod sod = new Sod(this.cryptoHelper);
    	try {
			sod.setDerValue(
				selectFileByLocationAndRead(FILE_SOD_LOCATION)
			);
		}
    	catch (final Asn1Exception | TlvException | Iso7816FourCardException e) {
			throw new IOException(
				"No se puede crear un SOD a partir del contenido del fichero: " + e, e //$NON-NLS-1$
			);
		}
    	return sod;
    }

    @Override
	public Com getCom() throws IOException {
		try {
			final Com com = new Com();
			com.setDerValue(
				selectFileByLocationAndRead(FILE_COM_LOCATION)
			);
			return com;
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw new FileNotFoundException("COM no encontrado: " + e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el 'Common Data' (COM): " + e, e); //$NON-NLS-1$
		}
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
     *                         las claves privadas y a los certificados mientras que, si se
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
	public void openSecureChannelIfNotAlreadyOpened(final boolean doChv) throws CryptoCardException,
	                                                                            PinException {

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
			"Este MRTD no tiene CardSecurity" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg4() throws IOException {
    	throw new CryptoCardSecurityException(
			"Hace falta canal de administrador para leer el DG4" //$NON-NLS-1$
		);
	}

    @Override
	public byte[] getDg5() throws IOException {
    	throw new UnsupportedOperationException(
			"Este MRTD no tiene DG5" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg6() throws IOException {
    	throw new UnsupportedOperationException(
			"Este MRTD no tiene DG6" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg8() throws IOException {
    	throw new UnsupportedOperationException(
			"Este MRTD no tiene DG8" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg9() throws IOException {
    	throw new UnsupportedOperationException(
			"Este MRTD no tiene DG9" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg10() throws IOException {
    	throw new UnsupportedOperationException(
			"Este MRTD no tiene DG10" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg15() throws IOException {
    	throw new UnsupportedOperationException(
			"Este MRTD no tiene DG15" //$NON-NLS-1$
		);
    }

    @Override
	public byte[] getDg16() throws IOException {
    	throw new UnsupportedOperationException(
			"Este MRTD no tiene DG16" //$NON-NLS-1$
		);
    }

}