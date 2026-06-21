package dev.flamingomg.jarvis.model;

public record VerdictRequest(String ip, String username, boolean bedrock, long timestamp, boolean premium) {}
