package org.example.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.ArrayList;
import java.util.List;
@JsonDeserialize(builder = PolicyDocument.Builder.class)
public class PolicyDocument {

    @JsonProperty("Version")
    private final String version = "2012-10-17";
    @JsonProperty("Statement")
    private List<Statement> statement;

    private PolicyDocument(Builder builder) {
        this.statement = builder.statements;
    }

    public List<Statement> getStatement() {
        return statement;
    }
    public String getVersion() {
        return version;
    }

    public static Builder builder(){
        return new Builder();
    }

    @JsonPOJOBuilder(withPrefix = "", buildMethodName = "create")
    public static final class Builder {
        private List<Statement> statements;
        private Builder() {
            statements = new ArrayList<Statement>();
        }
        public Builder statements(List<Statement> statements) {
            this.statements = statements;
            return this;
        }
        public PolicyDocument build() {
            return new PolicyDocument(this);
        }
    }
}
