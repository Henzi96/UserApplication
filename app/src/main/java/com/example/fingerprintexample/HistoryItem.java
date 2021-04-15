package com.example.fingerprintexample;

public class HistoryItem {
    private int imageLogStatus;
    private String txtLogDate;
    private String txtLogStatus;

    public HistoryItem(int imageLogStatus, String txtLogDate, String txtLogStatus) {
        this.imageLogStatus = imageLogStatus;
        this.txtLogDate = txtLogDate;
        this.txtLogStatus = txtLogStatus;
    }

    public void change_log_date(String text){
        this.txtLogDate = text;
    }

    public int getImageLogStatus() {
        return imageLogStatus;
    }

    public void setImageLogStatus(int imageLogStatus) {
        this.imageLogStatus = imageLogStatus;
    }

    public String getTxtLogDate() {
        return txtLogDate;
    }

    public void setTxtLogDate(String txtLogDate) {
        this.txtLogDate = txtLogDate;
    }

    public String getTxtLogStatus() {
        return txtLogStatus;
    }

    public void setTxtLogStatus(String txtLogStatus) {
        this.txtLogStatus = txtLogStatus;
    }


}
