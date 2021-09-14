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
package es.gob.jmulticard.jse.smartcardio;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.ApduConnectionOpenedInExclusiveModeException;
import es.gob.jmulticard.apdu.connection.ApduConnectionProtocol;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.LostChannelException;
import es.gob.jmulticard.apdu.connection.NoReadersFoundException;
import es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand;

/** Conexi&oacute;n con lector de tarjetas inteligentes implementado sobre
 * JSR-268 SmartCard I/O.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
@SuppressWarnings("restriction")
public final class SmartcardIoConnection implements ApduConnection {

	private static final boolean DEBUG = false;

	/** Tama&ntilde;o m&aacute;ximo de las APDU.
	 * Por encima de este tama&ntilde;o, se hace autom&aacute;ticamente una envoltura en
	 * varias APDU. */
	private static final int MAX_APDU_SIZE = 0xFF;

    /** Constante para la indicaci&oacute;n de que se ha detectado un reinicio del canal
     * con la tarjeta. */
    private static final String SCARD_W_RESET_CARD = "SCARD_W_RESET_CARD"; //$NON-NLS-1$

    private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    private int terminalNumber = -1;

	private CardChannel canal = null;

    private Card card = null;

    private boolean exclusive = false;

    private ApduConnectionProtocol protocol = ApduConnectionProtocol.ANY;

    static {

		// Aplicamos un parche para el error de PCSCLite de Debian:
		// https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529339
    	try {
    		LibJ2PCSCGNULinuxFix.fixNativeLibrary();
    	}
    	catch(final Exception | Error e) {
    		LOGGER.warning(
				"No se han podido aplicar las correcciones al error 529339 de Debian: " + e //$NON-NLS-1$
			);
    	}

    	// Aplicamos un parche para el error JDK-8255877 de Java:
   	 	// https://bugs.openjdk.java.net/browse/JDK-8255877
    	final String osName = System.getProperty("os.name"); //$NON-NLS-1$
		if (osName != null && osName.startsWith("Mac OS X")) { //$NON-NLS-1$
			final String dir = "/System/Library/Frameworks/PCSC.framework/Versions/Current"; //$NON-NLS-1$
			if (new File(dir).isDirectory()) {
				System.setProperty(
					"sun.security.smartcardio.library", //$NON-NLS-1$
					"/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC" //$NON-NLS-1$
				);
			}
		}
    }

    @Override
	  public String toString() {
    	return "Conexion de bajo nivel JSR-268 " + //$NON-NLS-1$
    			(isOpen()
    					? "abierta en modo " + (this.exclusive ? "" : "no") + " exclusivo" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
    					: "cerrada"); //$NON-NLS-1$
    }

    /** JSR-268 no soporta eventos de inserci&oacute;n o extracci&oacute;n. */
    @Override
    public void addCardConnectionListener(final CardConnectionListener ccl) {
        throw new UnsupportedOperationException("JSR-268 no soporta eventos de insercion o extraccion"); //$NON-NLS-1$
    }

    /** {@inheritDoc} */
    @Override
    public void close() throws ApduConnectionException {
    	if (this.card != null) {
	        try {
	            this.card.disconnect(false);
	        }
	        catch (final Exception e) {
	            throw new ApduConnectionException(
	                "Error intentando cerrar el objeto de tarjeta inteligente, la conexion puede quedar abierta pero inutil: " + e, e //$NON-NLS-1$
	            );
	        }
	        this.card = null;
    	}
        this.canal = null;
    }

    /** {@inheritDoc} */
    @Override
    public String getTerminalInfo(final int terminal) throws ApduConnectionException {
        try {
            final List<CardTerminal> terminales = TerminalFactory.getDefault().terminals().list();
            if (terminal < terminales.size()) {
                final CardTerminal cardTerminal = terminales.get(terminal);
                if (cardTerminal != null) {
                    return cardTerminal.getName();
                }
            }

            return null;
        }
        catch (final Exception ex) {
            throw new ApduConnectionException(
        		"Error recuperando la lista de lectores de tarjetas del sistema: " + ex, ex //$NON-NLS-1$
    		);
        }
    }

    /** {@inheritDoc} */
    @Override
    public long[] getTerminals(final boolean onlyWithCardPresent) throws ApduConnectionException {
    	final List<CardTerminal> terminales;
    	try {
    		terminales = TerminalFactory.getDefault().terminals().list();
    	}
    	catch(final CardException e) {
    		LOGGER.warning("No se ha podido recuperar la lista de lectores del sistema: " + e); //$NON-NLS-1$
    		return new long[0];
    	}

        try {
        	// Listamos los indices de los lectores que correspondan segun si tienen o no tarjeta insertada
        	final ArrayList<Long> idsTerminales = new ArrayList<>(terminales.size());
        	for (int idx = 0; idx < terminales.size(); idx++) {
        		if (onlyWithCardPresent) {
        			if (terminales.get(idx).isCardPresent()) {
        				idsTerminales.add(Long.valueOf(idx));
        			}
        		}
        		else {
        			idsTerminales.add(Long.valueOf(idx));
        		}
        	}

        	final long[] ids = new long[idsTerminales.size()];
        	for (int i = 0; i < ids.length; i++) {
        		ids[i] = idsTerminales.get(i).longValue();
        	}
        	return ids;
        }
        catch (final Exception ex) {
            throw new ApduConnectionException(
        		"Error recuperando la lista de lectores de tarjetas del sistema: " + ex, ex //$NON-NLS-1$
    		);
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean isOpen() {
        return this.card != null;
    }

    /** {@inheritDoc} */
    @Override
    public void open() throws ApduConnectionException {

        // Desactivamos las respuestas automaticas para evitar los problemas con el canal seguro
        System.setProperty("sun.security.smartcardio.t0GetResponse", "false"); //$NON-NLS-1$ //$NON-NLS-2$
        System.setProperty("sun.security.smartcardio.t1GetResponse", "false"); //$NON-NLS-1$ //$NON-NLS-2$

        if (isExclusiveUse() && isOpen()) {
            throw new ApduConnectionOpenedInExclusiveModeException();
        }

        final List<CardTerminal> terminales;
        try {
            terminales = TerminalFactory.getDefault().terminals().list();
        }
        catch(final Exception e) {
        	throw new NoReadersFoundException(
    			"No se han podido listar los lectores del sistema: " + e, e //$NON-NLS-1$
			);
        }
        try {
            if (terminales.size() < 1) {
                throw new NoReadersFoundException();
            }
            if (this.terminalNumber == -1) {
            	final long[] cadsWithCard = getTerminals(true);
            	if (cadsWithCard.length <= 0) {
            		throw new ApduConnectionException(
        				"En el sistema no hay ningun terminal con tarjeta insertada" //$NON-NLS-1$
    				);
            	}
				this.terminalNumber = (int) cadsWithCard[0];
            }
            if (terminales.size() <= this.terminalNumber) {
                throw new ApduConnectionException(
            		"No se detecto el lector de tarjetas numero " + Integer.toString(this.terminalNumber) //$NON-NLS-1$
        		);
            }
            this.card = terminales.get(this.terminalNumber).connect(this.protocol.toString());
        }
        catch(final javax.smartcardio.CardNotPresentException e) {
            throw new CardNotPresentException(e);
        }
        catch (final CardException e) {
            throw new ApduConnectionException(
                "No se ha podido abrir la conexion con el lector de tarjetas numero " + Integer.toString(this.terminalNumber) + ": " + e, e  //$NON-NLS-1$ //$NON-NLS-2$
    		);
        }

        if (this.exclusive) {
            try {
                this.card.beginExclusive();
            }
            catch (final CardException e) {
                throw new ApduConnectionException(
                    "No se ha podido abrir la conexion exclusiva con el lector de tarjetas numero " + Integer.toString(this.terminalNumber) + ": " + e, e //$NON-NLS-1$ //$NON-NLS-2$
                );
            }
        }
        this.canal = this.card.getBasicChannel();
    }

    /** JSR-268 no soporta eventos de inserci&oacute;n o extracci&oacute;n. */
    @Override
    public void removeCardConnectionListener(final CardConnectionListener ccl) {
        throw new UnsupportedOperationException("JSR-268 no soporta eventos de insercion o extraccion"); //$NON-NLS-1$
    }

    /** {@inheritDoc} */
    @Override
    public byte[] reset() throws ApduConnectionException {
    	if (this.card != null) {
	    	try {
				this.card.disconnect(true);
			}
	    	catch (final CardException e) {
				LOGGER.warning("Error reiniciando la tarjeta: " + e); //$NON-NLS-1$
			}
    	}
    	this.card = null;
        open();
        if (this.card != null) {
            return this.card.getATR().getBytes();
        }
        throw new ApduConnectionException("Error indefinido reiniciando la conexion con la tarjeta"); //$NON-NLS-1$
    }

    /** Establece si la conexi&oacute;n se debe abrir en modo exclusivo.
     * Solo puede establecerse si la conexi&oacute;n aun no ha sido abierta.
     * @param ex <code>true</code> para abrir la conexi&oacute;n en modo
     *           exclusivo, <code>false</code> para abrirla en modo no
     *           exclusivo. */
    public void setExclusiveUse(final boolean ex) {
        if (this.card == null) {
            this.exclusive = ex;
        }
        else {
            SmartcardIoConnection.LOGGER.warning(
                "No se puede cambiar el modo de acceso a la tarjeta con la conexion abierta, se mantendra el modo EXCLUSIVE=" + Boolean.toString(this.exclusive) //$NON-NLS-1$
            );
        }
    }

    /** Establece el protocolo de conexi&oacute;n con la tarjeta.
     * Por defecto, si no se establece ninguno, se indica <i>*</i> para que sea el API subyancente el
     * que detecte el apropiado.
     * @param p Protocolo de conexi&oacute;n con la tarjeta. */
    @Override
	public void setProtocol(final ApduConnectionProtocol p) {
        if (p == null) {
            SmartcardIoConnection.LOGGER.warning(
                "El protocolo de conexion no puede ser nulo, se usara T=0" //$NON-NLS-1$
            );
            this.protocol = ApduConnectionProtocol.T0;
            return;
        }
        this.protocol = p;
    }

    /** {@inheritDoc} */
    @Override
    public void setTerminal(final int terminalN) {
        if (this.terminalNumber == terminalN) {
            return;
        }

        final boolean wasOpened = isOpen();

        if (wasOpened) {
            try {
                close();
            }
            catch (final Exception e) {
                SmartcardIoConnection.LOGGER.warning(
                    "Error intentando cerrar la conexion con el lector: " + e); //$NON-NLS-1$
            }
        }
        this.terminalNumber = terminalN;
        if (wasOpened) {
            try {
            	open();
            }
            catch (final Exception e) {
            	SmartcardIoConnection.LOGGER.warning("Error intentando abrir la conexion con el lector: " + e); //$NON-NLS-1$
            }
        }
    }

    /** Etiqueta que identifica que es necesario recuperar el resultado del comando anterior. */
    private static final byte TAG_RESPONSE_PENDING = 0x61;

    private static final byte TAG_RESPONSE_INVALID_LENGTH = 0x6C;

    /** {@inheritDoc} */
    @Override
    public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {

        if (this.canal == null) {
            throw new ApduConnectionException(
                "No se puede transmitir sobre una conexion cerrada" //$NON-NLS-1$
            );
        }
        if (command == null) {
            throw new IllegalArgumentException(
        		"No se puede transmitir una APDU nula" //$NON-NLS-1$
            );
        }

        if (DEBUG) {
        	Logger.getLogger("es.gob.jmulticard").info( //$NON-NLS-1$
    			"Enviada APDU:\n" + //$NON-NLS-1$
				HexUtils.hexify(command.getBytes(), true)
			);
        }

        try {
        	final byte[] sendApdu;
    		// Si la APDU es mayor que MAX_APDU_SIZE la troceamos y la envolvemos
    		if (command.getBytes().length > MAX_APDU_SIZE) {

    			int sentLength = 0;
    			final int totalLength = command.getBytes().length;
    			final int contentSizeEnvelope = MAX_APDU_SIZE-5; // La cabecera de la APDU son 5 octetos

    			while (totalLength - sentLength > contentSizeEnvelope) {
    				final byte[] apduChunk = Arrays.copyOfRange(
						command.getBytes(),
						sentLength,
						sentLength + contentSizeEnvelope
					);
    				final CommandAPDU apdu = new CommandAPDU(
						(byte) 0x90,
						(byte) 0xC2,
						(byte) 0x00,
						(byte) 0x00,
						apduChunk
					);
    				final ResponseApdu response = new ResponseApdu(
						this.canal.transmit(apdu).getBytes()
					);
    				if(!response.isOk()) {
    					return response;
    				}
    				sentLength += contentSizeEnvelope;
    			}

    			// La ultima APDU se envia fuera del bucle
    			final byte[] apduChunk = Arrays.copyOfRange(
					command.getBytes(),
					sentLength,
					totalLength
				);
    			sendApdu = new CommandAPDU(
					(byte) 0x90,
					(byte) 0xC2,
					(byte) 0x00,
					(byte) 0x00,
					apduChunk
				).getBytes();
    		}
    		// Si es pequena, se envia directamente
    		else {
    			sendApdu = command.getBytes();
    		}
        	final ResponseApdu response = new ResponseApdu(
    			this.canal.transmit(new CommandAPDU(sendApdu)).getBytes()
			);

            // Solicitamos el resultado de la operacion si es necesario
            if (response.getStatusWord().getMsb() == TAG_RESPONSE_PENDING) {
                // Si ya se ha devuelto parte de los datos, los concatenamos al resultado
                if (response.getData().length > 0) {
                    final byte[] data = response.getData();
                    final byte[] additionalData = transmit(
                        new GetResponseApduCommand(
                    		(byte) 0x00, response.getStatusWord().getLsb()
                		)
                    ).getBytes();

                    final byte[] fullResponse = new byte[data.length + additionalData.length];
                    System.arraycopy(data, 0, fullResponse, 0, data.length);
                    System.arraycopy(additionalData, 0, fullResponse, data.length, additionalData.length);

                    return new ResponseApdu(fullResponse);
                }
                return transmit(new GetResponseApduCommand((byte) 0x00, response.getStatusWord().getLsb()));
            }
            // En caso de longitud esperada incorrecta reenviamos la APDU con la longitud esperada.
            // Incluimos la condicion del CLA igual 0x00 para que no afecte a las APDUs cifradas
            // (de eso se encargara la clase de conexion con canal seguro)
			if (response.getStatusWord().getMsb() == TAG_RESPONSE_INVALID_LENGTH && command.getCla() == (byte) 0x00) {
                command.setLe(response.getStatusWord().getLsb());
                return transmit(command);
            }

            if (DEBUG) {
            	Logger.getLogger("es.gob.jmulticard").info( //$NON-NLS-1$
        			"Respuesta:\n" + //$NON-NLS-1$
						HexUtils.hexify(response.getBytes(), true)
				);
            }

            return response;
        }
        catch (final CardException e) {
            final Throwable t = e.getCause();
            if (t != null && SCARD_W_RESET_CARD.equals(t.getMessage())) {
                throw new LostChannelException(t.getMessage(), t);
            }
            throw new ApduConnectionException(
                "Error de comunicacion con la tarjeta tratando de transmitir la APDU\n" + //$NON-NLS-1$
            		HexUtils.hexify(command.getBytes(), true) +
            			"\nAl lector " + Integer.toString(this.terminalNumber) + //$NON-NLS-1$
            				" en modo EXCLUSIVE=" + //$NON-NLS-1$
            					Boolean.toString(this.exclusive) +
            						" con el protocolo " + this.protocol.toString(), e //$NON-NLS-1$
            );
        }
        catch (final Exception e) {
        	e.printStackTrace();
            throw new ApduConnectionException(
                "Error tratando de transmitir la APDU\n" + HexUtils.hexify(command.getBytes(), true) + //$NON-NLS-1$
            		"\nAl lector " + Integer.toString(this.terminalNumber) + //$NON-NLS-1$
            			" en modo EXCLUSIVE=" + //$NON-NLS-1$
            				Boolean.toString(this.exclusive) +
            					" con el protocolo " + this.protocol.toString(), e //$NON-NLS-1$
            );
        }
    }

    /** Devuelve el protocolo de conexi&oacute;n con la tarjeta usado actualmente.
     * @return Un objeto de tipo enumerado <code>ConnectionProtocol</code>. */
    public ApduConnectionProtocol getProtocol() {
        return this.protocol;
    }

    /** Indica si la conexi&oacute;n con la tarjeta se ha establecido en modo exclusivo o no.
     * @return <code>true</code> si la conexi&oacute;n est&aacute; establecida en modo exclusivo. */
    public boolean isExclusiveUse() {
        return this.exclusive;
    }

	@Override
	public ApduConnection getSubConnection() {
		// Esta conexion es siempre la de mas bajo nivel
		return null;
	}
}