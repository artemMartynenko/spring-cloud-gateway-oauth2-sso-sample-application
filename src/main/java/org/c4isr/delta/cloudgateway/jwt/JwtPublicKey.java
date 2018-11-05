package org.c4isr.delta.cloudgateway.jwt;

public class JwtPublicKey {
    private  String alg;
    private  String value;


    public JwtPublicKey() {
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
