package com.example.fingerprintexample;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;

public class MenuActivity extends AppCompatActivity {

    Button btn_history, btn_settings, btn_about, exit_btn, btn_qr;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        this.getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_menu);
        initializeElements();
        //History
        btn_history.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent historyIntent = new Intent(MenuActivity.this, HistoryActivity.class);
                startActivity(historyIntent);
            }
        });
        //QR Generator
        btn_qr.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent qrIntent = new Intent(MenuActivity.this, QrActivity.class);
                startActivity(qrIntent);
            }
        });
        //Settings
        btn_settings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent settingsIntent = new Intent(MenuActivity.this, SettingsActivity.class);
                startActivity(settingsIntent);
            }
        });
        //About
        btn_about.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent aboutIntent = new Intent(MenuActivity.this, AboutActivity.class);
                startActivity(aboutIntent);
            }
        });
        //Exit
        exit_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exit(v);
            }
        });
    }

    private void initializeElements() {
        btn_history = findViewById(R.id.btn_history);
        btn_settings = findViewById(R.id.btn_settings);
        btn_about = findViewById(R.id.btn_about);
        exit_btn = findViewById(R.id.exit_btn);
        btn_qr = findViewById(R.id.btn_qr);
    }


    public void exit(View view) {
        AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(
                MenuActivity.this, R.style.AlertDialogStyle)
                .setTitle("Exit")
                .setMessage("Do you want to exit ?")
                .setCancelable(false).setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        MenuActivity.this.finish();
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