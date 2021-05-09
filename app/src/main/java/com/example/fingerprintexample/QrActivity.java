package com.example.fingerprintexample;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.herumi.mcl.Fr;
import com.journeyapps.barcodescanner.BarcodeEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class QrActivity extends AppCompatActivity {

    EditText editText_shaInput;
    TextView txt_qr_generator_state;
    ImageView qr_output;
    Button btn_generate_qr;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        this.getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_qr);
        initializeElements();
        btn_generate_qr.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    //Get input from edit text
                    String input = editText_shaInput.getText().toString().trim();
                    if (input.equals("")){
                        throw new IllegalArgumentException();
                    }
                    CryptoCore cryptoCore = new CryptoCore(getApplicationContext());
                    String input_hash = cryptoCore.SHA256(input);
                    //Initialize multi format writer
                    MultiFormatWriter writer = new MultiFormatWriter();
                    //Initialize bit matrix
                    BitMatrix matrix = writer.encode(input_hash, BarcodeFormat.QR_CODE, 300, 300);
                    //Initialize barcode encoder
                    BarcodeEncoder encoder = new BarcodeEncoder();
                    //Initialize bitmap
                    Bitmap bitmap = encoder.createBitmap(matrix);
                    //Set bitmap on imageView
                    qr_output.setImageBitmap(bitmap);
                    //Initialize input manager
                    InputMethodManager manager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                    //Hide soft keyboard
                    manager.hideSoftInputFromWindow(editText_shaInput.getApplicationWindowToken(), 0);
                    txt_qr_generator_state.setText("Successfuly generated");
                    txt_qr_generator_state.setTextColor(Color.parseColor("#176F0E"));
                } catch (Exception e) {
                    if (e instanceof WriterException){
                    e.printStackTrace();}
                    if (e instanceof IllegalArgumentException){
                        txt_qr_generator_state.setText("Empty value!");
                        txt_qr_generator_state.setTextColor(Color.parseColor("#F44336"));
                    }
                }
            }
        });
    }

    private void initializeElements() {
        editText_shaInput = findViewById(R.id.editText_shaInput);
        txt_qr_generator_state = findViewById(R.id.txt_qr_generator_state);
        qr_output = findViewById(R.id.qr_output);
        btn_generate_qr = findViewById(R.id.btn_generate_qr);
    }
}