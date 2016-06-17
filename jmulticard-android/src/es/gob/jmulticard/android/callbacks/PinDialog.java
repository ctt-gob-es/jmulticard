/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * Date: 11/01/11
 * You may contact the copyright holder at: soporte.afirma5@mpt.es
 */

package es.gob.jmulticard.android.callbacks;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.util.Log;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import es.gob.jmulticard.android.R;
import es.gob.jmulticard.card.dnie.TextInputCallback;

/** Di&acute;logo para introducir el PIN.
 * Se usa en almacenes distintos al del propio sistema operativo Android.
 * @author Astrid Idoate */

public class PinDialog extends DialogFragment {

	private final String title;
	private final boolean isCan;
	private String password;
	private String provider;
	static Callback callback;
	private final Activity activity;
	String getProviderName() {
		return this.provider;
	}

	void setPassword(final String pass) {
		this.password = pass;
	}
	String getPassword() {
		return this.password;
	}

	private String keyStoreName;
	DialogDoneChecker dialogDone;
	String getKeyStoreName() {
		return this.keyStoreName;
	}

	/** Construye un di&acute;logo para introducir el PIN.
	 * @param title T&iacute;tulo del di&aacute;logo.
	 * @param cb
	 * @param prompt Contenido del di&aacute;logo. */
	public PinDialog(final boolean isCan, final Activity activity, final Callback cb, final DialogDoneChecker ddc) {
        this.isCan=isCan;
        if(isCan) {
        	this.title = "Introducci\u00f3n de CAN";//getString(R.string.can_intro);
        }
        else {
        	this.title = "Introducci\u00f3n de PIN";//getString(R.string.pin_intro);
        }
        this.activity = activity;
        callback = cb;
        this.dialogDone = ddc;
	}

	@Override
	public Dialog onCreateDialog(final Bundle savedInstanceState) {
		final Builder alertDialogBuilder = new AlertDialog.Builder(this.activity);
		alertDialogBuilder.setTitle(this.title);
		final LayoutInflater layoutInflater = LayoutInflater.from(this.activity);
		final View view;
		if(this.isCan) {
			view = layoutInflater.inflate(R.layout.dialog_can, null);
		}
		else {
			view = layoutInflater.inflate(R.layout.dialog_pin, null);
		}

		final EditText editTextPin = (EditText) view.findViewById(R.id.etPin);
		alertDialogBuilder.setView(view);
		alertDialogBuilder.setNegativeButton(
				this.activity.getString(R.string.cancel),
			new DialogInterface.OnClickListener() {
				@Override
				public void onClick(final DialogInterface dialog, final int id) {
					dialog.dismiss();
				}
			}
		);
		alertDialogBuilder.setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {

			@Override
			public void onClick(final DialogInterface dialog, final int which) {
				if(editTextPin.getText() != null && !"".equals(editTextPin.getText().toString())) { //$NON-NLS-1$

					dialog.dismiss();
					setPassword(editTextPin.getText().toString());
					if (callback instanceof PasswordCallback) {
						final PasswordCallback pc = (PasswordCallback) callback;
						pc.setPassword(editTextPin.getText().toString().toCharArray());
						PinDialog.this.dialogDone.setPinReady(true);
					}
					else if (callback instanceof TextInputCallback) {
						final TextInputCallback pc = (TextInputCallback) callback;
						pc.setText(editTextPin.getText().toString());
						PinDialog.this.dialogDone.setCanReady(true);
					}
					synchronized(PinDialog.this.dialogDone) {
						PinDialog.this.dialogDone.notify();
					}

				}
				else {
					//TODO: Gestionar este caso
					Log.e("es.gob.jmulticard", "El pin no puede ser vacio o nulo"); //$NON-NLS-1$ //$NON-NLS-2$
					return;
				}
			}
		});
		alertDialogBuilder.setOnKeyListener(new DialogInterface.OnKeyListener() {
			@Override
			public boolean onKey(final DialogInterface dialog, final int keyCode, final KeyEvent event) {
				if (keyCode == KeyEvent.KEYCODE_BACK) {
					dialog.dismiss();
					return true;
				}
				return false;
			}
		});

		return alertDialogBuilder.create();
	}
}