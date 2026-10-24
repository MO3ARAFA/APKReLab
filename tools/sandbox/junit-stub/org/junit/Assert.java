package org.junit;
public class Assert {
  public static void assertTrue(boolean c){ if(!c) throw new AssertionError(); }
  public static void assertTrue(String m, boolean c){ if(!c) throw new AssertionError(m); }
  public static void assertFalse(boolean c){ if(c) throw new AssertionError(); }
  public static void assertFalse(String m, boolean c){ if(c) throw new AssertionError(m); }
  public static void assertNull(Object o){ if(o!=null) throw new AssertionError("expected null: "+o); }
  public static void assertNull(String m, Object o){ if(o!=null) throw new AssertionError(m); }
  public static void assertNotNull(Object o){ if(o==null) throw new AssertionError("null"); }
  public static void assertNotNull(String m, Object o){ if(o==null) throw new AssertionError(m); }
  public static void assertSame(Object a, Object b){ if(a!=b) throw new AssertionError("not same"); }
  private static boolean eq(Object a, Object b){ return a==null? b==null : a.equals(b); }
  public static void assertEquals(Object a, Object b){ if(!eq(a,b)) throw new AssertionError("expected <"+a+"> but was <"+b+">"); }
  public static void assertEquals(String m, Object a, Object b){ if(!eq(a,b)) throw new AssertionError(m+": expected <"+a+"> but was <"+b+">"); }
  public static void assertEquals(long a, long b){ if(a!=b) throw new AssertionError("expected <"+a+"> but was <"+b+">"); }
  public static void assertEquals(String m, long a, long b){ if(a!=b) throw new AssertionError(m+": expected <"+a+"> but was <"+b+">"); }
  public static void assertEquals(double a, double b, double d){ if(Math.abs(a-b)>d) throw new AssertionError("expected <"+a+"> but was <"+b+">"); }
}
