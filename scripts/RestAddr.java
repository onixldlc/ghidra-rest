// How an address becomes a string, everywhere.
//
// These are the keys the HTTP API resolves paths against, so every task must
// produce exactly the same form. `NormAddr` in src/internal/jobs/artifacts.go
// does the same thing to whatever a client sends, which is what makes
// 0x00401000, 401000 and 00401000 all reach the same function.
//
//@category ghidra-rest
import ghidra.program.model.address.Address;

public final class RestAddr {

	private RestAddr() {
	}

	// Lower case, no 0x, no leading zeros, address space prefix kept when the
	// program has more than the default space.
	public static String key(Address a) {
		if (a == null) {
			return "";
		}
		String s = a.toString().toLowerCase();
		int i = s.lastIndexOf(':');
		String prefix = i >= 0 ? s.substring(0, i + 1) : "";
		String off = i >= 0 ? s.substring(i + 1) : s;
		if (off.startsWith("0x")) {
			off = off.substring(2);
		}
		int z = 0;
		while (z < off.length() - 1 && off.charAt(z) == '0') {
			z++;
		}
		return prefix + off.substring(z);
	}

	// Address keys can carry a space prefix with a colon in it, which is not a
	// portable filename character.
	public static String fileKey(String k) {
		return k.replace(':', '_').replace('/', '_');
	}
}
