import dev.apkrelab.ElfTestBuilder
import java.io.File
fun main(a: Array<String>) {
    File(a[0], "full.so").writeBytes(ElfTestBuilder.build())
    File(a[0], "e32.so").writeBytes(ElfTestBuilder.build(is64 = false, imports = listOf("__stack_chk_fail", "gets"), needed = listOf("libc.so")))
}
