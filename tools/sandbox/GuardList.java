import dev.apkrelab.*;
import java.nio.charset.StandardCharsets; import java.nio.file.*; import java.util.*;

/**
 * 0.69.1: runs the REAL ManifestContext + PermissionGuard (Kotlin, compiled with kotlinc) on a text manifest.
 * Prints every exported component with its guard and writes the signature-guarded ones to the file given as 2nd argument.
 * No PackageManager here: permissions this manifest does not declare are resolved by a small table (every android.permission.BIND_* is
 * signature-level on a device); unknown ones stay WEAK, exactly like PermissionGuard.systemResolver on a device that does not know them.
 */
public class GuardList {
  public static void main(String[] a) throws Exception {
    ManifestContext mc = new ManifestContext(new String(Files.readAllBytes(Paths.get(a[0])), StandardCharsets.UTF_8));
    PermissionGuard pg = new PermissionGuard(mc, n -> n.startsWith("android.permission.BIND_") ? Integer.valueOf(2) : null);
    List<String> out = new ArrayList<>();
    for (ManifestComponent c : mc.getExportedComponents()) {
      String t = mc.smaliTypeOf(c);
      PermissionGuard.Guard g = t.isEmpty() ? PermissionGuard.Guard.NONE : pg.guardFor(t, PermissionGuard.Access.ANY);
      if (g != PermissionGuard.Guard.NONE)
        System.out.println("  " + g + " " + c.getTag() + " " + c.getName() + " perm=" + c.getPermission() + " read=" + c.getReadPermission() + " write=" + c.getWritePermission());
      if (g == PermissionGuard.Guard.SIGNATURE && !t.isEmpty()) out.add(t);
    }
    System.out.println("exported=" + mc.getExportedComponents().size() + " signatureGuarded=" + out.size());
    if (a.length > 1) Files.write(Paths.get(a[1]), out);
  }
}
