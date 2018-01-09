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

package es.gob.jmulticard.card.fnmt.ceres;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.ceres.CeresVerifyApduCommand;
import es.gob.jmulticard.apdu.ceres.LoadDataApduCommand;
import es.gob.jmulticard.apdu.ceres.SignDataApduCommand;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.dnie.RetriesLeftApduCommand;
import es.gob.jmulticard.apdu.iso7816eight.EnvelopeDataApduCommand;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.Pkcs15Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.Pkcs15PrKdf;
import es.gob.jmulticard.asn1.der.pkcs15.PrKdf;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.CompressionUtils;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.fnmt.ceres.asn1.CeresCdf;
import es.gob.jmulticard.card.fnmt.ceres.asn1.CeresPrKdf;
import es.gob.jmulticard.card.iso7816eight.Iso7816EightCard;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Tarjeta FNMT-RCM CERES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Ceres extends Iso7816EightCard implements CryptoCard {

	private static final byte[] ATR_MASK_TC = new byte[] {
		(byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr ATR_TC = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x46, (byte) 0x4E, (byte) 0x4d,
        (byte) 0x54, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, ATR_MASK_TC);

	private static final byte[] ATR_MASK_ST = new byte[] {
		(byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr ATR_ST = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x43, (byte) 0x45, (byte) 0x52,
        (byte) 0x45, (byte) 0x53, (byte) 0x02, (byte) 0x2c, (byte) 0x34, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, ATR_MASK_ST);

	private static final byte[] ATR_MASK_SLE_FN20 = new byte[] {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr ATR_SLE_FN20 = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0xeF, (byte) 0x00, (byte) 0x00, (byte) 0x40, (byte) 0x14, (byte) 0x80, (byte) 0x25, (byte) 0x43, (byte) 0x45,
        (byte) 0x52, (byte) 0x45, (byte) 0x53, (byte) 0x57, (byte) 0x05, (byte) 0x60, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, ATR_MASK_SLE_FN20);

	private static final byte[] ATR_MASK_SLE_FN19 = new byte[] {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr ATR_SLE_FN19 = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0xeF, (byte) 0x00, (byte) 0x00, (byte) 0x40, (byte) 0x14, (byte) 0x80, (byte) 0x25, (byte) 0x43, (byte) 0x45,
        (byte) 0x52, (byte) 0x45, (byte) 0x53, (byte) 0x57, (byte) 0x01, (byte) 0x16, (byte) 0x01, (byte) 0x01, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, ATR_MASK_SLE_FN19);

	private static final byte CLA = (byte) 0x00;

	private final CryptoHelper cryptoHelper;

    private static final Location CDF_LOCATION = new Location("50156004"); //$NON-NLS-1$
    private static final Location PRKDF_LOCATION = new Location("50156001"); //$NON-NLS-1$

    /** Nombre del Fichero Maestro. */
    private static final String MASTER_FILE_NAME = "Master.File"; //$NON-NLS-1$

    /** Octeto que identifica una verificaci&oacute;n fallida del
     * PIN por PIN de longitud incorrecta. */
    private final static byte ERROR_PIN_SW1 = (byte) 0x67;

    /** Octeto que identifica una verificaci&oacute;n fallida del
     * PIN por PIN incorrecto. */
    private final static byte ERROR_PIN_SW2 = (byte) 0x63;

	private static final boolean AUTO_RETRY = true;

    /** Certificados de la tarjeta indexados por su alias. */
    private Map<String, X509Certificate> certs;

    /** Alias de los certificados de la tarjeta indexados por el identificador
     * interno del certificado (pasado de <code>byte[]</code> a <code>String</code>). */
    private Map<String, String> aliasByCertAndKeyId;

    /** Claves privadas de la tarjeta indexadas por el alias de su certificado
     * asociado. */
    private Map<String, Byte> keys;

    private PasswordCallback passwordCallback = null;

    private boolean authenticated = false;
	private CallbackHandler callbackHandler;

	/** Establece el <code>PasswordCallback</code> para el PIN de la tarjeta.
     * @param pwc <code>PasswordCallback</code> para el PIN de la tarjeta. */
    public void setPasswordCallback(final PasswordCallback pwc) {
    	this.passwordCallback = pwc;
    }

    private static void checkAtr(final byte[] atrBytes) throws InvalidCardException {
    	Atr tmpAtr = new Atr(atrBytes, ATR_MASK_TC);
    	if (ATR_TC.equals(tmpAtr)) {
    		if (atrBytes[15] >= (byte) 0x04 && atrBytes[16] >= (byte) 0x30) {
    			throw new InvalidCardException(
					"Encontrada CERES en version " + //$NON-NLS-1$
						HexUtils.hexify(new byte[] { atrBytes[15] }, false) + "." + HexUtils.hexify(new byte[] { atrBytes[16] }, false) + //$NON-NLS-1$
							", pero las versiones iguales o superiores a la 04.30 no estan soportadas por este controlador" //$NON-NLS-1$
				);
    		}
    		return;
    	}
    	tmpAtr = new Atr(atrBytes, ATR_MASK_ST);
    	if (ATR_ST.equals(tmpAtr)) {
    		return;
    	}
    	tmpAtr = new Atr(atrBytes, ATR_MASK_SLE_FN19);
    	if (ATR_SLE_FN19.equals(tmpAtr)) {
    		return;
    	}
    	tmpAtr = new Atr(atrBytes, ATR_MASK_SLE_FN20);
    	if (ATR_SLE_FN20.equals(tmpAtr)) {
    		return;
    	}
    	throw new InvalidCardException("CERES", ATR_TC, atrBytes); //$NON-NLS-1$
    }

    /** Inicia la conexi&oacute;n con la tarjeta CERES.
     * @param conn Conexi&oacute;n con el lector de tarjetas.
     * @throws ApduConnectionException Si ocurren errores de conexi&oacute;n.
     * @throws InvalidCardException Si la tarjeta encontrada en el lector no es una tarjeta FNMT-RCM-CERES. */
    public static void connect(final ApduConnection conn) throws ApduConnectionException, InvalidCardException {
    	conn.open();
    	checkAtr(conn.reset());
    }

	/** Construye una clase que representa una tarjeta FNMT-RCM CERES.
	 * @param conn Conexi&oacute;n con la tarjeta.
	 * @param ch Clase para la realizaci&oacute;n de las huellas digitales del <i>DigestInfo</i>.
	 * @throws ApduConnectionException Si hay problemas con la conexi&oacute;n proporcionada.
	 * @throws InvalidCardException Si la tarjeta conectada no es una FNMT-RCM CERES. */
	public Ceres(final ApduConnection conn,
			     final CryptoHelper ch) throws ApduConnectionException, InvalidCardException {
		super(CLA, conn);
		if (ch == null) {
			throw new IllegalArgumentException("El CryptoHelper no puede ser nulo"); //$NON-NLS-1$
		}

		connect(getConnection());

		try {
			preload();
		}
		catch (final Exception e) {
			throw new ApduConnectionException(
				"Error cargando las estructuras iniciales de la tarjeta: " + e, e //$NON-NLS-1$
			);
		}
		this.cryptoHelper = ch;
	}

	private void preload() throws ApduConnectionException,
	                              Iso7816FourCardException,
	                              IOException,
	                              CertificateException,
	                              Asn1Exception,
	                              TlvException {

        // Nos vamos al raiz antes de nada
        selectMasterFile();

        // Leemos el CDF
        final byte[] cdfBytes = selectFileByLocationAndRead(CDF_LOCATION);

		// Cargamos el CDF
        Pkcs15Cdf cdf = new CeresCdf();
        try {
        	cdf.setDerValue(cdfBytes);
        }
        catch(final Exception e) {
        	// Si ha fallado la inicializacion del CDF tipo CERES probamos con el CDF generico PKCS#15,
        	// presente en las nuevas tarjetas FNMT-CERES
        	cdf = new Cdf();
        	cdf.setDerValue(cdfBytes);
        }

        // Leemos los certificados segun las rutas del CDF

        final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$

        this.certs = new LinkedHashMap<>(cdf.getCertificateCount());
        this.aliasByCertAndKeyId = new LinkedHashMap<>(cdf.getCertificateCount());

        for (int i=0; i<cdf.getCertificateCount(); i++) {
        	final Location l = new Location(
    			cdf.getCertificatePath(i).replace("\\", "").trim() //$NON-NLS-1$ //$NON-NLS-2$
			);
        	final X509Certificate cert = (X509Certificate) cf.generateCertificate(
    			new ByteArrayInputStream(
					CompressionUtils.deflate(
						selectFileByLocationAndRead(l)
					)
				)
			);
        	final String alias = i + " " + cert.getSerialNumber(); //$NON-NLS-1$
        	this.aliasByCertAndKeyId.put(
    			HexUtils.hexify(cdf.getCertificateId(i), false),
    			alias
			);
        	this.certs.put(alias, cert);
        }

        // Leemos el PrKDF
        final byte[] prkdfValue =  selectFileByLocationAndRead(PRKDF_LOCATION);

        // Establecemos el valor del PrKDF
        Pkcs15PrKdf prkdf = new CeresPrKdf();
        try {
        	prkdf.setDerValue(prkdfValue);
        }
        catch(final Exception e) {
        	// Si no carga el estructura PrKDF especifica de CERES probamos con la
        	// generica PKCS#15, presente en las ultimas versiones de la tarjeta
        	prkdf = new PrKdf();
        	prkdf.setDerValue(prkdfValue);
        }

        this.keys = new LinkedHashMap<>();
        for (int i=0; i<prkdf.getKeyCount(); i++) {
        	final String alias = this.aliasByCertAndKeyId.get(
    			HexUtils.hexify(prkdf.getKeyId(i), false)
			);
        	if (alias != null) {
	        	this.keys.put(
	    			alias,
					Byte.valueOf(prkdf.getKeyReference(i))
				);
        	}
        }

        // Sincronizamos claves y certificados
        hideCertsWithoutKey();
	}

	/** Oculta los certificados que no tienen una clave privada asociada. */
	private void hideCertsWithoutKey() {
		final String[] aliases;
		try {
			aliases = getAliases();
		}
		catch (final Exception e) {
			throw new IllegalStateException(
				"No se han podido leer los alias de los certificados de la tarjeta CERES: " + e, e //$NON-NLS-1$
			);
		}
		for (final String alias : aliases) {
			if (this.keys.get(alias) == null) {
				this.certs.remove(alias);
			}
		}
	}

	@Override
	public String[] getAliases() {
		return this.certs.keySet().toArray(new String[0]);
	}

	@Override
	public X509Certificate getCertificate(final String alias) {
		return this.certs.get(alias);
	}

	@Override
	public PrivateKeyReference getPrivateKey(final String alias) {
		return new CeresPrivateKeyReference(
			this.keys.get(alias).byteValue(),
			((RSAPublicKey)this.certs.get(alias).getPublicKey()).getModulus().bitLength()
		);
	}

	@Override
	public byte[] sign(final byte[] data,
			           final String algorithm,
			           final PrivateKeyReference keyRef) throws CryptoCardException,
	                                                            PinException {
		if (data == null) {
			throw new CryptoCardException("Los datos a firmar no pueden ser nulos"); //$NON-NLS-1$
		}
		if (keyRef == null) {
			throw new IllegalArgumentException("La clave privada no puede ser nula"); //$NON-NLS-1$
		}
		if (!(keyRef instanceof CeresPrivateKeyReference)) {
			throw new IllegalArgumentException(
				"La clave proporcionada debe ser de tipo CeresPrivateKeyReference, pero se ha recibido de tipo " + keyRef.getClass().getName() //$NON-NLS-1$
			);
		}
		final CeresPrivateKeyReference ceresPrivateKey = (CeresPrivateKeyReference) keyRef;

		// Pedimos el PIN si no se ha pedido antes
		if (!this.authenticated) {
			try {
				verifyPin(getInternalPasswordCallback());
				this.authenticated = true;
			}
			catch (final ApduConnectionException e1) {
				throw new CryptoCardException("Error en la verificacion de PIN: " + e1, e1); //$NON-NLS-1$
			}
		}

		final byte[] digestInfo;
		try {
			digestInfo = DigestInfo.encode(algorithm, data, this.cryptoHelper);
		}
		catch(final Exception e) {
			throw new CryptoCardException(
				"Error creando el DigestInfo para la firma con el algoritmo " + algorithm + ": " + e, e //$NON-NLS-1$ //$NON-NLS-2$
			);
		}

		loadData(ceresPrivateKey.getKeyBitSize(), digestInfo);

		final ResponseApdu res;

		final CommandApdu cmd = new SignDataApduCommand(
			ceresPrivateKey.getKeyReference(), // Referencia
			ceresPrivateKey.getKeyBitSize()    // Tamano en bits de la clave
		);
		try {
			res = sendArbitraryApdu(cmd);
		}
		catch (final Exception e) {
			throw new CryptoCardException("Error firmando los datos: " + e, e); //$NON-NLS-1$
		}
		if (!res.isOk()) {
			throw new CryptoCardException(
				"No se han podido firmar los datos. Respuesta: " + HexUtils.hexify(res.getBytes(), true) //$NON-NLS-1$
			);
		}
		return res.getData();
	}

	private void loadData(final int keyBitSize, final byte[] digestInfo) throws CryptoCardException {
		final byte[] paddedData;
		try {
			paddedData = CryptoHelper.addPkcs1PaddingForPrivateKeyOperation(
				digestInfo,
				keyBitSize
			);
		}
		catch (final Exception e1) {
			throw new CryptoCardException(
				"Error realizando el relleno PKCS#1 de los datos a firmar: " + e1, e1 //$NON-NLS-1$
			);
		}

		ResponseApdu res;

		// Si la clave es de 1024 la carga se puede hacer en una unica APDU
		if (keyBitSize < 2048) {
			try {
				res = sendArbitraryApdu(new LoadDataApduCommand(paddedData));
			}
			catch (final Exception e) {
				throw new CryptoCardException(
					"Error enviando los datos a firmar a la tarjeta: " + e, e //$NON-NLS-1$
				);
			}
			if (!res.isOk()) {
				throw new CryptoCardException(
					"No se han podido enviar los datos a firmar a la tarjeta. Respuesta: " + HexUtils.hexify(res.getBytes(), true) //$NON-NLS-1$
				);
			}
		}
		// Pero si es de 2048 hacen falta dos APDU, envolviendo la APDU de carga de datos
		else if (keyBitSize == 2048) {

			final byte[] envelopedLoadDataApdu = new byte[] {
				(byte) 0x90, (byte) 0x58, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00
			};

			// La primera APDU carga 0xFF octetos (254)
			byte[] data = new byte[255];
			System.arraycopy(envelopedLoadDataApdu, 0, data, 0, envelopedLoadDataApdu.length);
			System.arraycopy(paddedData, 0, data, envelopedLoadDataApdu.length, 255 - envelopedLoadDataApdu.length);

			try {
				res = sendArbitraryApdu(new EnvelopeDataApduCommand(data));
			}
			catch (final Exception e) {
				throw new CryptoCardException(
					"Error en el primer envio a la tarjeta de los datos a firmar: " + e, e //$NON-NLS-1$
				);
			}
			if (!res.isOk()) {
				throw new CryptoCardException(
					"No se han podido enviar (primera tanda) los datos a firmar a la tarjeta. Respuesta: " + HexUtils.hexify(res.getBytes(), true) //$NON-NLS-1$
				);
			}

			// La segunda APDU es de 0x08 octetos (8)
			data = new byte[8];
			System.arraycopy(paddedData, 255 - envelopedLoadDataApdu.length, data, 0, 8);

			try {
				res = sendArbitraryApdu(new EnvelopeDataApduCommand(data));
			}
			catch (final Exception e) {
				throw new CryptoCardException(
					"Error en el segundo envio a la tarjeta de los datos a firmar: " + e, e //$NON-NLS-1$
				);
			}
			if (!res.isOk()) {
				throw new CryptoCardException(
					"No se han podido enviar (segunda tanda) los datos a firmar a la tarjeta. Respuesta: " + HexUtils.hexify(res.getBytes(), true) //$NON-NLS-1$
				);
			}

		}

		else {
			throw new IllegalArgumentException("Solo se soportan claves de 2048 o menos bits"); //$NON-NLS-1$
		}

	}

	@Override
	protected void selectMasterFile() throws ApduConnectionException,
	                                         FileNotFoundException,
	                                         Iso7816FourCardException {
		selectFileByName(MASTER_FILE_NAME);
	}

	@Override
	public void verifyPin(final PasswordCallback pinPc) throws ApduConnectionException, PinException {
		if (pinPc == null) {
			throw new PinException("No se ha establecido un PasswordCallback"); //$NON-NLS-1$
		}
		final CommandApdu chv = new CeresVerifyApduCommand(CLA, pinPc);
		final ResponseApdu verifyResponse = sendArbitraryApdu(chv);
        if (!verifyResponse.isOk()) {
            if (
        		verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1 ||
        		verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW2
    		) {
            	if(AUTO_RETRY) {
            		this.passwordCallback = null;
            		verifyPin(
                		getInternalPasswordCallback()
                	);
            		return;
            	}
				throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
            }
            else if (new StatusWord((byte)0x69, (byte)0x83).equals(verifyResponse.getStatusWord())) {
            	throw new AuthenticationModeLockedException();
            }
            throw new ApduConnectionException(
        		new Iso7816FourCardException(
	        		"Error en la verificacion de PIN (" + verifyResponse.getStatusWord() + ")", //$NON-NLS-1$ //$NON-NLS-2$
	        		verifyResponse.getStatusWord()
				)
    		);
        }
	}

    protected PasswordCallback getInternalPasswordCallback() throws PinException {
    	if (this.passwordCallback != null) {
    		final int retriesLeft = getPinRetriesLeft();
    		if(retriesLeft == 0) {
    			throw new AuthenticationModeLockedException();
    		}
    		return this.passwordCallback;
    	}
    	if (this.callbackHandler != null) {
        	final int retriesLeft = getPinRetriesLeft();
        	if(retriesLeft == 0) {
        		throw new AuthenticationModeLockedException();
        	}
        	final PasswordCallback pwc = new PasswordCallback(
    			CardMessages.getString("Gen.0", Integer.toString(retriesLeft)), //$NON-NLS-1$
				false
			);
			try {
				this.callbackHandler.handle(
					new Callback[] {
						pwc
					}
				);
			}
			catch (final IOException e) {
				throw new PinException(
					"Error obteniendo el PIN del CallbackHandler: " + e, e //$NON-NLS-1$
				);
			}
			catch (final UnsupportedCallbackException e) {
				throw new PinException(
					"El CallbackHandler no soporta pedir el PIN al usuario: " + e, e //$NON-NLS-1$
				);
			}
			return pwc;
    	}
    	throw new PinException("No hay ningun metodo para obtener el PIN"); //$NON-NLS-1$
    }

    private int getPinRetriesLeft() throws PinException {
    	final CommandApdu verifyCommandApdu = new RetriesLeftApduCommand();
    	final ResponseApdu verifyResponse;
		try {
			verifyResponse = getConnection().transmit(
				verifyCommandApdu
			);
		}
		catch (final ApduConnectionException e) {
			throw new PinException(
				"Error obteniendo el PIN del CallbackHandler: " + e, e  //$NON-NLS-1$
			);
		}
    	return verifyResponse.getStatusWord().getLsb() - (byte) 0xC0;
    }

	@Override
	public String getCardName() {
		return "FNMT-RCM CERES"; //$NON-NLS-1$
	}

	/** Obtiene el <code>CallbackHandler</code>.
	 * @return <code>CallbackHandler</code>. */
    public CallbackHandler getCallbackHandler() {
		return this.callbackHandler;
	}

    /** Define el <code>CallbackHandler</code>.
     * @param callh <code>CallbackHandler</code> a definir. */
	public void setCallbackHandler(final CallbackHandler callh) {
		this.callbackHandler = callh;
	}

}
