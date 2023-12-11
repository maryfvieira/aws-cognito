package org.example.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
@JsonDeserialize(builder = Statement.Builder.class)
public class Statement {
    @JsonProperty("Action")
    private final String action = "execute-api:Invoke";

    @JsonProperty("Effect")
    private String effect;

    @JsonProperty("Resource")
    private String resource;

    private Statement(Builder builder) {
        this.effect = builder.effect;
        this.resource = builder.resource;
    }
    public static Builder builder() {
        return new Builder();
    }
    public String getAction() {
        return action;
    }
    public String getEffect() {
        return effect;
    }
    public String getResource() {
        return resource;
    }

    @JsonPOJOBuilder(withPrefix = "", buildMethodName = "create")
    public static class Builder {
        private String effect;
        private String resource;
        private Builder() { }
        public Builder effect(String effect) {
            this.effect = effect;
            return this;
        }
        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }
        public Statement build() {
            return new Statement(this);
        }
    }
}
