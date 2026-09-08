// One thing ghidra-rest can do to a program inside a Ghidra JVM.
//
// Adding a feature is: a new file implementing this, and one line in
// RestRegistry. Nothing else -- not the Dockerfile, not warmup.sh, not the Go
// side, which always invokes `RestScript.java <name> <outdir> ...`.
//
//@category ghidra-rest
public interface Task {

	// The name the server passes as the first script argument.
	String name();

	// Argument list after the task name, for the error message when a caller
	// gets it wrong. Begins with <outdir>, which RestScript consumes itself.
	String usage();

	// The prefix every log line of this task carries.
	//
	// Not cosmetic: guttex's progress bar matches `ExportJSON: stage ...`,
	// `ExportJSON: functions <n>` and five more patterns against the headless
	// log (see guttex `state/progress.svelte.ts`). The export task therefore
	// still logs as "ExportJSON" even though the file is now called
	// TaskExport.java. Changing one of these strings breaks a progress bar in
	// a different repository, silently.
	String logTag();

	// args are what followed <outdir> on the command line.
	void run(Ctx c, String[] args) throws Exception;
}
