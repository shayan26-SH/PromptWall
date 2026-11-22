package com.promptwall;

public final class PromptWallSelfTest {
    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        String quoted = Json.quote("line1\nline2 \"quoted\"");
        assertTrue(quoted.contains("\\n"), "JSON newline escaping");
        assertTrue(Json.stringField("{\"sanitized\":\"hello\"}", "sanitized").equals("hello"),
            "JSON string field parsing");
        System.out.println("PromptWall Java self-tests passed");
    }
}
