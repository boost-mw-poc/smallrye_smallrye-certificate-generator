package io.smallrye.certs.maven;

import org.apache.maven.plugins.annotations.Parameter;

import java.util.List;

public class AliasParameter {

    @Parameter(required = true)
    private String name;
    @Parameter
    private String password;
    @Parameter(defaultValue = "localhost")
    private String cn;
    @Parameter(defaultValue = "false")
    private boolean client;

    @Parameter
    private List<String> subjectAlternativeNames;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public boolean isClient() {
        return client;
    }

    public void setClient(boolean client) {
        this.client = client;
    }

    public void setSubjectAlternativeNames(List<String> subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
    }

    public List<String> getSubjectAlternativeNames() {
        return subjectAlternativeNames;
    }
}
