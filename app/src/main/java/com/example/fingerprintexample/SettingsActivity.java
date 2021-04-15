package com.example.fingerprintexample;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;

import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;

import com.google.android.material.snackbar.Snackbar;

public class SettingsActivity extends AppCompatActivity {
    TextView info_about_attributes;
    Button btninitialState;
    ConstraintLayout settings_constraintLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        this.getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);
        settings_constraintLayout = findViewById(R.id.settings_constraintLayout);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);
        info_about_attributes = findViewById(R.id.info_about_attributes);
        SharedPreferences sharedPreferences = getApplicationContext().getSharedPreferences("UserData", MODE_PRIVATE);
        info_about_attributes.setText("This aplication holds "+ Integer.parseInt(sharedPreferences.getString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, "00"), 16) + " attributes");
        btninitialState = findViewById(R.id.btn_initial_state);
        btninitialState.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                setInitialState(v);
            }
        });
    }


    public void setInitialState(View view) {
        AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(
                SettingsActivity.this, R.style.AlertDialogStyle)
                .setTitle("Initial state")
                .setMessage("Do you want to set the application into initial state ?")
                .setCancelable(false).setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        SharedPreferences sharedPreferences = getApplicationContext().getSharedPreferences("UserData", MODE_PRIVATE);
                        SharedPreferences.Editor editor = sharedPreferences.edit();
                        editor.clear();
                        editor.commit();
                        editor.putString(Constants.SystemParameters.NUMBER_OF_ATTRIBUTES, "00");
                        editor.commit();
                        info_about_attributes.setText("This aplication holds 0 attributes");
                        dialogInterface.cancel();
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        dialogInterface.cancel();
                    }
                });
        AlertDialog alertDialog = alertDialogBuilder.create();
        alertDialog.show();
    }

}