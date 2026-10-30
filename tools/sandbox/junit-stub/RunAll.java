import java.lang.reflect.*; import java.nio.file.*; import java.util.*;
public class RunAll { public static void main(String[] a) throws Exception {
  int pass=0, fail=0; List<String> fails=new ArrayList<>();
  try (var s = Files.walk(Paths.get(a[0]))) { for (Path p : (Iterable<Path>) s.filter(x->x.toString().endsWith("Test.class"))::iterator) {
    String cn = Paths.get(a[0]).relativize(p).toString().replace('/', '.').replaceAll("\\.class$","");
    Class<?> c = Class.forName(cn);
    for (Method m : c.getDeclaredMethods()) { if (m.getAnnotation(org.junit.Test.class)==null) continue;
      try { Object o=c.getDeclaredConstructor().newInstance(); m.setAccessible(true); m.invoke(o); pass++; }
      catch (InvocationTargetException e){ fail++; fails.add(cn+"."+m.getName()+": "+e.getCause()); } } } }
  System.out.println("pass="+pass+" fail="+fail); for(String f:fails) System.out.println("FAIL "+f);
} }
