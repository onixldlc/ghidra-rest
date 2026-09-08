// Every task this build can run.
//
// This list is the only place a feature is registered. Adding one is a new
// TaskX.java plus one line here; removing one is deleting both. The Dockerfile
// copies the whole scripts directory and warmup.sh asks for `selftest`, so
// neither needs to know a task exists.
//
//@category ghidra-rest
import java.util.ArrayList;
import java.util.List;

public final class RestRegistry {

	private static final List<Task> TASKS = new ArrayList<Task>();

	static {
		TASKS.add(new TaskExport());
		TASKS.add(new TaskSignature());
		TASKS.add(new TaskPatch());
		// <-- a new feature is one line here plus one new file
	}

	private RestRegistry() {
	}

	public static Task get(String name) {
		for (Task t : TASKS) {
			if (t.name().equals(name)) {
				return t;
			}
		}
		return null;
	}

	public static List<Task> all() {
		return TASKS;
	}

	public static String names() {
		StringBuilder b = new StringBuilder();
		for (Task t : TASKS) {
			if (b.length() > 0) {
				b.append(", ");
			}
			b.append(t.name());
		}
		return b.toString();
	}

	// What `RestScript.java tasks` prints. The server reads it to learn what
	// this image can do, instead of keeping its own copy of this list.
	public static String asJson() {
		StringBuilder b = new StringBuilder();
		b.append("{\"tasks\":[");
		boolean first = true;
		for (Task t : TASKS) {
			if (!first) {
				b.append(",");
			}
			first = false;
			b.append("{\"name\":").append(RestJson.quoted(t.name()));
			b.append(",\"usage\":").append(RestJson.quoted(t.usage()));
			b.append("}");
		}
		b.append("]}");
		return b.toString();
	}
}
