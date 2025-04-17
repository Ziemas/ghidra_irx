package ghidra_irx;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Hashtable;

public class ModuleDB {
	private Hashtable<String, Hashtable<Integer, String>> db;

	public ModuleDB(File file) throws IOException {
		db = new Hashtable<>();

		BufferedReader reader = new BufferedReader(new FileReader(file));

		String line = "";
		while ((line = reader.readLine()) != null) {
			if (line.trim().length() == 0 || line.charAt(0) == '#') {
				continue;
			}

			String[] entry = line.split(" ");
			if (!db.containsKey(entry[0])) {
				db.put(entry[0], new Hashtable<>());
			}

			Integer index = Integer.parseInt(entry[1]);
			db.get(entry[0]).put(index, entry[2]);

		}

		reader.close();
	}

	public String getEntry(String module, int function) {
		if (db.containsKey(module)) {
			var exports = db.get(module);
			if (exports.containsKey(function)) {
				return exports.get(function);
			}
		}

		return "";
	}
}
