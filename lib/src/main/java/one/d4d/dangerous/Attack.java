package one.d4d.dangerous;

import com.google.gson.annotations.SerializedName;

public enum Attack {
    @SerializedName("Known")
    KNOWN("Known"),
    @SerializedName("Fast")
    FAST("Fast"),
    @SerializedName("Balanced")
    Balanced("Balanced"),
    @SerializedName("Deep")
    Deep("Deep");

    public final String name;

    Attack(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
