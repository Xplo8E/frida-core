namespace Frida.Fruity.Debug {
	private static bool debug_enabled = false;
	private static bool debug_checked = false;

	public static void log (string format, ...) {
		if (!debug_checked) {
			debug_enabled = Environment.get_variable ("FRIDA_FRUITY_DEBUG") != null;
			debug_checked = true;
		}
		if (debug_enabled) {
			var args = va_list ();
			stderr.vprintf (format, args);
		}
	}
}