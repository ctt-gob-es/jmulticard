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
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.DigestAlgorithm;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.icao.AdditionalPersonalDetails;
import es.gob.jmulticard.asn1.icao.Com;
import es.gob.jmulticard.asn1.icao.DataGroupHash;
import es.gob.jmulticard.asn1.icao.LdsSecurityObject;
import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.asn1.icao.SecurityOptions;
import es.gob.jmulticard.asn1.icao.Sod;
import es.gob.jmulticard.asn1.icao.SubjectFacePhoto;
import es.gob.jmulticard.asn1.icao.SubjectSignaturePhoto;
import es.gob.jmulticard.card.CardSecurityException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.CryptoCardSecurityException;
import es.gob.jmulticard.card.PasswordCallbackNotFoundException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.icao.InvalidSecurityObjectException;
import es.gob.jmulticard.card.icao.MrtdLds1;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.card.iso7816four.RequiredSecurityStateNotSatisfiedException;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.cwa14890.ChannelType;
import es.gob.jmulticard.connection.cwa14890.Cwa14890OneV2Connection;

/** DNI Electr&oacute;nico versi&oacute;n 3&#46;0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class Dnie3 extends Dnie implements MrtdLds1 {

    private String idesp = null;

	//*************************************************************************
	//************************ CONSTRUCTORES **********************************

    /** Construye una clase que representa un DNIe 3&#46;0.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHlpr Funcionalidades criptogr&aacute;ficas de utilidad que pueden
     *                   variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de las <i>Callbacks</i> (PIN, confirmaci&oacute;n, etc.).
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona
     *                                 cerrada y no es posible abrirla.*/
    protected Dnie3(final ApduConnection conn,
    	            final PasswordCallback pwc,
    	            final CryptoHelper cryptoHlpr,
    	            final CallbackHandler ch) throws ApduConnectionException {

        super(conn, pwc, cryptoHlpr, ch);
        rawConnection = conn;

    	// Identificamos numero de soporte (IDESP)
		try {
			idesp = getIdesp();
		}
		catch (final Exception e1) {
			JmcLogger.warning("No se ha podido leer el IDESP del DNIe: " + e1); //$NON-NLS-1$
			idesp = null;
		}
    }

	//*************************************************************************
	//******************* METODOS SOBRECARGADOS DE CLASES PADRE ***************

	@Override
    public String getCardName() {
        return "DNIe 3.0"; //$NON-NLS-1$
    }

    @Override
	public int getPinRetriesLeft() throws ApduConnectionException {
    	if (!(getConnection() instanceof Cwa14890OneV2Connection)) {
			throw new ApduConnectionException("Es necesario abrir canal CWA para obtener los intentos de PIN restantes"); //$NON-NLS-1$
    	}
		final ChannelType channelType = ((Cwa14890OneV2Connection)getConnection()).getChannelType();
		final int retriesLeft;
		switch(channelType) {
    		case CWA_USER:
				try {
					openPinChannel();
				}
				catch (final CryptoCardException e) {
					throw new ApduConnectionException("Error estableciendo el canal de PIN para obtener los intentos restantes", e); //$NON-NLS-1$
				}
    			retriesLeft = super.getPinRetriesLeft();
//    			openUserChannel(); // Lo dejamos como estaba
    			break;
    		case CWA_PIN:
    			retriesLeft = super.getPinRetriesLeft();
    			break;
    		default:
    			throw new ApduConnectionException("Es necesario abrir canal CWA para obtener los intentos de PIN restantes"); //$NON-NLS-1$
		}
    	return retriesLeft;
    }

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

    	JmcLogger.info(Dnie3.class.getName(), "openSecureChannelIfNotAlreadyOpened", "Conexion actual: " + getConnection()); //$NON-NLS-1$ //$NON-NLS-2$
    	JmcLogger.info(
			Dnie3.class.getName(),
			"openSecureChannelIfNotAlreadyOpened", //$NON-NLS-1$
			"Conexion subyacente: " + (rawConnection != null ? rawConnection : "ninguna") //$NON-NLS-1$ //$NON-NLS-2$
		);

        // Si la conexion esta cerrada, la reestablecemos
        if (!getConnection().isOpen()) {
	        try {
				setConnection(rawConnection);
			}
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException("Error en el establecimiento del canal inicial previo al seguro de PIN", e); //$NON-NLS-1$
			}
        }

        if (doChv) {
	        // Establecemos el canal PIN y lo verificamos
        	openPinChannel();
	        try {
	        	verifyPin(getInternalPasswordCallback());
	        }
	        catch (final PasswordCallbackNotFoundException e) {
	        	// Si no se indico un medio para obtener el PIN, ignoramos el establecimiento
	        	// del canal de PIN, pero continuamos para establecer el canal de usuario
	        	JmcLogger.info(
        			Dnie3.class.getName(),
        			"openSecureChannelIfNotAlreadyOpened", //$NON-NLS-1$
        			"No se proporcionaron medios para verificar el PIN: " + e //$NON-NLS-1$
    			);
			}
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException("Error en la verificacion de PIN", e); //$NON-NLS-1$
	        }

	        JmcLogger.info(Dnie3.class.getName(), "openSecureChannelIfNotAlreadyOpened", "PIN verificado correctamente"); //$NON-NLS-1$ //$NON-NLS-2$
        }

        openUserChannel();
    }

	//*************************************************************************
	//******************* METODOS DE EXCLUSIVOS DE ESTA CLASE *****************

    /** Abre y establece el canal seguro de PIN.
     * @return Nueva conexi&oacute;n establecida.
     * @throws CryptoCardException Si hay problemas en la apertura de canal. */
    public final ApduConnection openPinChannel() throws CryptoCardException {
        final ApduConnection pinSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		getConnection(),
    		getCryptoHelper(),
    		DnieFactory.getDnie3PinCwa14890Constants(idesp),
    		DnieFactory.getDnie3PinCwa14890Constants(idesp),
			ChannelType.CWA_PIN
		);

        try {
        	selectMasterFile();
        }
        catch (final Exception e) {
        	JmcLogger.warning(
    			"Error seleccionando el MF tras el establecimiento del canal seguro de PIN: " + e //$NON-NLS-1$
			);
        }

        try {
        	setConnection(pinSecureConnection);
        }
        catch (final ApduConnectionException e) {
        	throw new CryptoCardException("Error en el establecimiento del canal seguro de PIN", e); //$NON-NLS-1$
        }

        JmcLogger.info(
			Dnie3.class.getName(), "openPinChannel", "Canal seguro de PIN para DNIe establecido" //$NON-NLS-1$ //$NON-NLS-2$
		);

        return pinSecureConnection;
    }

    /** Abre y establece el canal seguro de usuario.
     * @return Nueva conexi&oacute;n establecida.
     * @throws CryptoCardException Si hay problemas en la apertura de canal. */
    public final ApduConnection openUserChannel() throws CryptoCardException {

    	final ApduConnection usrSecureConnection = new Cwa14890OneV2Connection(
    		this,
    		getConnection(),
    		getCryptoHelper(),
    		DnieFactory.getDnie3UsrCwa14890Constants(idesp),
    		DnieFactory.getDnie3UsrCwa14890Constants(idesp),
			ChannelType.CWA_USER
		);

		try {
			selectMasterFile();
		}
		catch (final Exception e) {
			throw new CryptoCardException(
        		"Error seleccionando el MF tras el establecimiento del canal seguro de usuario", e //$NON-NLS-1$
    		);
		}

        try {
            setConnection(usrSecureConnection);
        }
        catch (final ApduConnectionException e) {
            throw new CryptoCardException("Error en el establecimiento del canal seguro de usuario", e); //$NON-NLS-1$
        }

        JmcLogger.info(
			Dnie3.class.getName(), "openUserChannel", "Canal seguro de Usuario para DNIe establecido" //$NON-NLS-1$ //$NON-NLS-2$
		);

    	return usrSecureConnection;
    }

	@Override
	protected boolean needsPinForLoadingCerts() {
		return false; // "true" en DNIe 1.0, "false" en cualquier otro.
	}

	//*************************************************************************
	//*************** METODOS HEREDADOS DE ICAO MRTD LDS1 *********************

	@Override
	public final X509Certificate[] checkSecurityObjects() throws IOException,
	                                                             TlvException,
	                                                             Asn1Exception,
	                                                             SignatureException,
	                                                             CertificateException {
		openSecureChannelIfNotAlreadyOpened(false);
		final Sod sod = getSod();
		sod.validateSignature();
		final LdsSecurityObject ldsSecurityObject = sod.getLdsSecurityObject();

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
						JmcLogger.warning(
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
					dgBytes = getDg11().getBytes();
					break;
				case 12:
					dgBytes = getDg12();
					break;
				case 13:
					dgBytes = getDg13().getBytes();
					break;
				case 14:
					dgBytes = getDg14().getBytes();
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
			final byte[] actualHash = getCryptoHelper().digest(
				DigestAlgorithm.getDigestAlgorithm(ldsSecurityObject.getDigestAlgorithm()),
				dgBytes
			);

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
	public final byte[] getCardAccess() throws IOException {
    	try {
			return selectFileByLocationAndRead(FILE_CARD_ACCESS_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("CardAcess no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el CardAccess", e); //$NON-NLS-1$
		}
    }

    @Override
	public final byte[] getAtrInfo() throws IOException {
    	try {
			return selectFileByLocationAndRead(FILE_ATR_INFO_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("ATR/INFO no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el ATR/INFO", e); //$NON-NLS-1$
		}
    }

    @Override
	public final Mrz getDg1() throws IOException {
		try {
			return new Mrz(selectFileByLocationAndRead(FILE_DG01_LOCATION));
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG1 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG1", e); //$NON-NLS-1$
		}
	}

    @Override
	public final SubjectFacePhoto getDg2() throws IOException {
    	final SubjectFacePhoto ret = new SubjectFacePhoto();
		try {
			ret.setDerValue(selectFileByLocationAndRead(FILE_DG02_LOCATION));
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG2 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG2", e); //$NON-NLS-1$
		}
		return ret;
	}

    @Override
	public byte[] getDg3() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG03_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG3 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		// El DG3 necesita canal administrativo, le damos un tratamiento especial
		catch(final RequiredSecurityStateNotSatisfiedException e) {
			throw new CardSecurityException("No se tienen permisos para leer el DG3", e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG3", e); //$NON-NLS-1$
		}
	}

    @Override
	public final SubjectSignaturePhoto getDg7() throws IOException {
    	final SubjectSignaturePhoto ret = new SubjectSignaturePhoto();
		try {
			ret.setDerValue(selectFileByLocationAndRead(FILE_DG07_LOCATION));
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG7 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG7", e); //$NON-NLS-1$
		}
		return ret;
	}

    @Override
	public final AdditionalPersonalDetails getDg11() throws IOException {
		try {
			final AdditionalPersonalDetails personalDetails = new AdditionalPersonalDetails();
			personalDetails.setDerValue(selectFileByLocationAndRead(FILE_DG11_LOCATION));
			return personalDetails;
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG11 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | Asn1Exception | TlvException e) {
			throw new CryptoCardException("Error leyendo el DG11", e); //$NON-NLS-1$
		}
	}

    @Override
	public final byte[] getDg12() throws IOException {
		try {
			return selectFileByLocationAndRead(FILE_DG12_LOCATION);
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG12 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException e) {
			throw new CryptoCardException("Error leyendo el DG12", e); //$NON-NLS-1$
		}
	}

    @Override
	public OptionalDetails getDg13() throws IOException {
		try {
			final OptionalDetails ret = new OptionalDetails();
			ret.setDerValue(selectFileByLocationAndRead(FILE_DG13_LOCATION));
			return ret;
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG13 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG13", e); //$NON-NLS-1$
		}
	}

    @Override
	public final SecurityOptions getDg14() throws IOException {
		try {
			final SecurityOptions securityOptions = new SecurityOptions();
			securityOptions.setDerValue(selectFileByLocationAndRead(FILE_DG14_LOCATION));
			return securityOptions;
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("DG14 no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el DG14", e); //$NON-NLS-1$
		}
	}

    @Override
	public final Sod getSod() throws IOException {
    	final Sod sod = new Sod(getCryptoHelper());
    	try {
			sod.setDerValue(selectFileByLocationAndRead(FILE_SOD_LOCATION));
		}
    	catch (final Asn1Exception | TlvException | Iso7816FourCardException e) {
			throw new IOException("No se puede crear un SOD a partir del contenido del fichero", e); //$NON-NLS-1$
		}
    	return sod;
    }

    @Override
	public final Com getCom() throws IOException {
		try {
			final Com com = new Com();
			com.setDerValue(selectFileByLocationAndRead(FILE_COM_LOCATION));
			return com;
		}
    	catch(final es.gob.jmulticard.card.iso7816four.FileNotFoundException e) {
    		throw (IOException) new FileNotFoundException("COM no encontrado").initCause(e); //$NON-NLS-1$
    	}
		catch (final Iso7816FourCardException | TlvException | Asn1Exception e) {
			throw new CryptoCardException("Error leyendo el 'Common Data' (COM)", e); //$NON-NLS-1$
		}
	}

	//*************************************************************************
	//********** METODOS DE ICAO MRTD LDS1 NO SOPORTADOS **********************

    @Override
	public byte[] getCardSecurity() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene CardSecurity"); //$NON-NLS-1$
    }

    @Override
	public byte[] getDg4() throws IOException {
    	throw new CryptoCardSecurityException("Hace falta canal de administrador para leer el DG4"); //$NON-NLS-1$
	}

    @Override
	public byte[] getDg5() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene DG5"); //$NON-NLS-1$
    }

    @Override
	public byte[] getDg6() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene DG6"); //$NON-NLS-1$
    }

    @Override
	public byte[] getDg8() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene DG8"); //$NON-NLS-1$
    }

    @Override
	public byte[] getDg9() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene DG9"); //$NON-NLS-1$
    }

    @Override
	public byte[] getDg10() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene DG10"); //$NON-NLS-1$
    }

    @Override
	public byte[] getDg15() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene DG15"); //$NON-NLS-1$
    }

    @Override
	public byte[] getDg16() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene DG16"); //$NON-NLS-1$
    }

	@Override
	public final byte[] getDir() throws IOException {
    	throw new UnsupportedOperationException("Este MRTD no tiene DIR"); //$NON-NLS-1$
	}
}