package com.example.fingerprintexample;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;

import java.util.ArrayList;

public class HistoryActivity extends AppCompatActivity {

    public ArrayList<HistoryItem> historyLogsList;
    private RecyclerView historyRecyclerView;
    //Bridge between data and RecyclerView -> Provide as many items as we need
    private HistoryAdapter historyRecyclerViewAdapter;
    //Responsible for align item layout to recyclerView
    private RecyclerView.LayoutManager historyRecyclerViewLayoutManager;
    Button btnclearAllLogs;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        this.getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_history);
        createHistoryList();
        buildRecyclerView();
    }

    public void buildRecyclerView() {
        historyRecyclerView = findViewById(R.id.recyclerView_history);
        historyRecyclerView.setHasFixedSize(true);
        historyRecyclerViewLayoutManager = new LinearLayoutManager(this);
        historyRecyclerViewAdapter = new HistoryAdapter(historyLogsList);
        historyRecyclerView.setLayoutManager(historyRecyclerViewLayoutManager);
        historyRecyclerView.setAdapter(historyRecyclerViewAdapter);
        btnclearAllLogs = findViewById(R.id.btn_clear_logs);
        btnclearAllLogs.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                SharedPreferences sharedPreferences = getApplicationContext().getSharedPreferences("UserData", MODE_PRIVATE);
                SharedPreferences.Editor editor = sharedPreferences.edit();
                int totalNumberOfLogs = sharedPreferences.getInt(Constants.SystemParameters.NUMBER_OF_LOGS, 0);
                for (int i = 1; i <= totalNumberOfLogs; i++) {
                    editor.remove(Constants.SystemParameters.LOG_STATE + i);
                    editor.remove(Constants.SystemParameters.LOG_DATE + i);
                }
                editor.putInt(Constants.SystemParameters.NUMBER_OF_LOGS, 0);
                editor.commit();
            }
        });
    }

    public void createHistoryList() {
        SharedPreferences sharedPreferences = getApplicationContext().getSharedPreferences("UserData", MODE_PRIVATE);
        historyLogsList = new ArrayList<>();
        for (int i = 1; i <= sharedPreferences.getInt(Constants.SystemParameters.NUMBER_OF_LOGS, 0); i++) {
            //Card personalization
            if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.SystemParameters.CARD_PERSONALIZATION)) {
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_person_add_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Issuance of Revocation handler
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.SystemParameters.REVOCATION_HANDLER_ISSUE)) {
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_info_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //User's attributes issuance
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.SystemParameters.ATTRIBUTE_ISSUE)) {
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_library_books_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Successful computation of Proof of Knowledge
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.SystemParameters.PROOF_OF_KNOWLEDGE_SUBMIT)) {
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_lock_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during INS_SET_USER_IDENTIFIER
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.INS_SET_USER_IDENTIFIER)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during INS_GET_USER_IDENTIFIER
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.INS_GET_USER_IDENTIFIER)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during INS_SET_REVOCATION_AUTHORITY_DATA
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.INS_SET_REVOCATION_AUTHORITY_DATA)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during INS_GET_USER_IDENTIFIER_ATTRIBUTES
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.INS_GET_USER_IDENTIFIER_ATTRIBUTES)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during INS_SET_USER_ATTRIBUTES
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.INS_SET_USER_ATTRIBUTES)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during CMD_TEST_BIT_CHECKER
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.CMD_TEST_BIT_CHECKER)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during INS_GET_USER_DISCLOSED_ATTRIBUTES
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.INS_GET_USER_DISCLOSED_ATTRIBUTES)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during INS_COMPUTE_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.INS_COMPUTE_PROOF_OF_KNOWLEDGE_SEQ_DISCLOSED)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during INS_GET_PROOF_OF_KNOWLEDGE
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.INS_GET_PROOF_OF_KNOWLEDGE)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
            //Error during Debug instruction
            else if (sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "").equals(Constants.Errors.DEBUG_T)){
                historyLogsList.add(new HistoryItem(R.drawable.ic_baseline_error_outline_24, sharedPreferences.getString(Constants.SystemParameters.LOG_DATE + i, ""), sharedPreferences.getString(Constants.SystemParameters.LOG_STATE + i, "")));
            }
        }
    }
}