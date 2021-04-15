package com.example.fingerprintexample;

public class ApduResponseObject {
    private String DATA, SW1, SW2;

    public ApduResponseObject(String DATA, String SW1, String SW2) {
        if (DATA == null){
            this.DATA = "";}
        else {
            this.DATA = DATA; }
        if (SW1.length() != 2){
            throw new IllegalArgumentException("SW1 has to be one byte!"); }
        else {
            this.SW1 = SW1; }
        if (SW2.length() != 2){
            throw new IllegalArgumentException("SW2 has to be one byte!"); }
        else {
            this.SW2 = SW2; }
    }

    public ApduResponseObject(String DATA, String SW1_SW2) {
        if (DATA == null){
            this.DATA = ""; }
        else {
            this.DATA = DATA; }
        if (SW1_SW2.length() != 4) {
            throw new IllegalArgumentException("Wrong length for SW1_SW2!");
        }
        else {
            this.SW1 = SW1_SW2.substring(0, 2);
            this.SW2 = SW1_SW2.substring(2, 4); }
    }

    public String getDATA() {
        return DATA;
    }

    public void setDATA(String DATA) {
        this.DATA = DATA;
    }

    public String getSW1() {
        return SW1;
    }

    public void setSW1(String SW1) {
        this.SW1 = SW1;
    }

    public String getSW2() {
        return SW2;
    }

    public void setSW2(String SW2) {
        this.SW2 = SW2;
    }

    @Override
    public String toString() {
        return DATA + SW1 + SW2;
    }

}
