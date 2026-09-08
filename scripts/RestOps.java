// The ops.tsv in, result.tsv out protocol every edit task speaks with the Go
// side.
//
// TAB separates fields and newline separates records, so neither may survive
// inside a value -- tsv() is the guard, not an encoding. The server owns the
// durable record of what has been applied; a task is a pure "do these, tell me
// what happened" step and holds no state of its own.
//
//   ops.tsv     <address key><TAB><field>[<TAB><field>...]
//   result.tsv  <address key><TAB>ok|error<TAB><before><TAB><message>
//
//@category ghidra-rest
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class RestOps {

	private RestOps() {
	}

	public static final class Op {
		// The address, as the HTTP API spells it.
		public final String key;
		// Everything after the address, already trimmed. What they mean is the
		// task's business.
		public final String[] cols;

		// Filled in by the task.
		public String before = "";
		public boolean ok;
		public String message = "";

		Op(String key, String[] cols) {
			this.key = key;
			this.cols = cols;
		}

		public String col(int i) {
			return i >= 0 && i < cols.length ? cols[i] : "";
		}
	}

	// maxCols counts the address as one, so a signature op (address,
	// prototype, convention) passes 3.
	//
	// Keyed by address so two ops on one address collapse to the last rather
	// than being applied twice -- which for a patch would mean the second one
	// recording the first one's bytes as the original.
	public static List<Op> read(File f, int maxCols) throws Exception {
		Map<String, Op> byAddr = new LinkedHashMap<String, Op>();
		BufferedReader r = new BufferedReader(
			new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8));
		try {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith("#")) {
					continue;
				}
				int tab = line.indexOf('\t');
				if (tab <= 0) {
					continue;
				}
				String key = line.substring(0, tab).trim();
				String[] raw = line.substring(tab + 1).split("\t", maxCols - 1);
				String[] cols = new String[raw.length];
				for (int i = 0; i < raw.length; i++) {
					cols[i] = raw[i].trim();
				}
				if (key.isEmpty() || cols.length == 0 || cols[0].isEmpty()) {
					continue;
				}
				byAddr.put(key, new Op(key, cols));
			}
		}
		finally {
			r.close();
		}
		return new ArrayList<Op>(byAddr.values());
	}

	// Written even for ops that failed: a caller that sent forty needs forty
	// answers, not a single error.
	public static void writeResult(File f, List<Op> ops) throws Exception {
		Writer w = new BufferedWriter(
			new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8));
		try {
			for (Op op : ops) {
				w.write(tsv(op.key));
				w.write("\t");
				w.write(op.ok ? "ok" : "error");
				w.write("\t");
				w.write(tsv(op.before));
				w.write("\t");
				w.write(tsv(op.message));
				w.write("\n");
			}
		}
		finally {
			w.close();
		}
	}

	public static String tsv(String s) {
		if (s == null) {
			return "";
		}
		return s.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
	}

	public static int countOk(List<Op> ops) {
		int n = 0;
		for (Op o : ops) {
			if (o.ok) {
				n++;
			}
		}
		return n;
	}

	// Ghidra wraps the message worth reading several layers down.
	public static String rootMessage(Throwable t) {
		Throwable c = t;
		while (c.getCause() != null && c.getCause() != c) {
			c = c.getCause();
		}
		String m = c.getMessage();
		if (m == null || m.isEmpty()) {
			m = c.getClass().getSimpleName();
		}
		return m;
	}
}
