// What every task is handed: the program, where to write, how to log, and how
// to notice it has been cancelled.
//
// It exists because a Task is not a GhidraScript. `monitor` is protected on
// GhidraScript and these classes are not in its package, so the monitor is
// passed in explicitly from RestScript, which is a GhidraScript and can reach
// it.
//
//@category ghidra-rest
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class Ctx {

	public final GhidraScript script;
	public final Program program;
	public final File outDir;
	public final TaskMonitor monitor;

	private final String tag;

	public Ctx(GhidraScript script, Program program, File outDir, TaskMonitor monitor,
			String tag) {
		this.script = script;
		this.program = program;
		this.outDir = outDir;
		this.monitor = monitor;
		this.tag = tag;
	}

	// Every line a task prints goes through here, so the prefix a task
	// declares is the prefix that actually reaches the log. See Task.logTag.
	public void log(String message) {
		script.println(tag + ": " + message);
	}

	// Progress markers. Nothing reads these but a human and guttex's loading
	// screen, so they are plain and prefixed: one grep, no format to parse.
	public void stage(String name) {
		log("stage " + name);
	}

	public boolean cancelled() {
		return monitor != null && monitor.isCancelled();
	}

	public Writer open(String rel) throws Exception {
		File f = new File(outDir, rel);
		mkdirs(f.getParentFile());
		return new BufferedWriter(
			new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8), 1 << 16);
	}

	public File dir(String rel) throws Exception {
		File d = new File(outDir, rel);
		mkdirs(d);
		return d;
	}

	public static void mkdirs(File d) throws Exception {
		if (d != null && !d.isDirectory() && !d.mkdirs()) {
			throw new java.io.IOException("cannot create " + d);
		}
	}
}
