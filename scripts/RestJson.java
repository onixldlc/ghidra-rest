// The JSON primitives every artifact is written with.
//
// Hand-rolled rather than a library because the artifact set is streamed: a
// program with 40,000 functions is written a field at a time into a
// BufferedWriter and never exists as an object graph.
//
//@category ghidra-rest
import java.io.Writer;

public final class RestJson {

	private RestJson() {
	}

	public static void field(Writer w, String name, String value, boolean first) throws Exception {
		if (!first) {
			w.write(",");
		}
		w.write("\"" + name + "\":\"" + esc(value) + "\"");
	}

	public static void num(Writer w, String name, long value, boolean first) throws Exception {
		if (!first) {
			w.write(",");
		}
		w.write("\"" + name + "\":" + value);
	}

	public static void bool(Writer w, String name, boolean value, boolean first) throws Exception {
		if (!first) {
			w.write(",");
		}
		w.write("\"" + name + "\":" + (value ? "true" : "false"));
	}

	// A bare quoted string, for the places that build an array of them.
	public static String quoted(String s) {
		return "\"" + esc(s) + "\"";
	}

	public static String esc(String s) {
		if (s == null) {
			return "";
		}
		StringBuilder b = new StringBuilder(s.length() + 16);
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"':
					b.append("\\\"");
					break;
				case '\\':
					b.append("\\\\");
					break;
				case '\n':
					b.append("\\n");
					break;
				case '\r':
					b.append("\\r");
					break;
				case '\t':
					b.append("\\t");
					break;
				default:
					// Control characters and lone surrogates would make the
					// output invalid JSON; decompiled C and raw strings from a
					// binary contain both.
					if (c < 0x20 || c == 0x7f || Character.isSurrogate(c)) {
						b.append(String.format("\\u%04x", (int) c));
					}
					else {
						b.append(c);
					}
					break;
			}
		}
		return b.toString();
	}
}
