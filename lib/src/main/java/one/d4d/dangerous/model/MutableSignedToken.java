package one.d4d.dangerous.model;

public class MutableSignedToken {
    private final String original;
    private SignedToken modified;

    public MutableSignedToken(String original, SignedToken modified) {
        this.original = original;
        this.modified = modified;
    }

    public boolean changed() {
        return !original.equals(modified.serialize());
    }

    public void setModified(SignedToken o) {
        modified = o;
    }

    public SignedToken getModified() {
        return modified;
    }

    public String getOriginal() {
        return original;
    }
}
