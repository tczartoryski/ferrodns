"""Single-client UDP cache baseline; never contacts internet authorities."""
import socket, struct, subprocess, time, statistics

server = subprocess.Popen(["./target/release/ferrodns", "sim", "15354"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
try:
    line = server.stderr.readline().decode()
    if "recursive client endpoint" not in line:
        raise RuntimeError(line)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    labels = b"".join(bytes([len(x)]) + x for x in [b"api", b"example", b"com"]) + b"\0"
    packet = struct.pack("!6H", 1234, 256, 1, 0, 0, 0) + labels + struct.pack("!2H", 1, 1)
    def ask():
        begin = time.perf_counter_ns()
        s.sendto(packet, ("127.0.0.1", 15354))
        reply = s.recv(4096)
        ident, flags, _, answers, _, _ = struct.unpack("!6H", reply[:12])
        assert ident == 1234 and flags & 15 == 0 and answers == 2
        return (time.perf_counter_ns() - begin) / 1000
    cold = ask()
    samples = []
    start = time.perf_counter()
    for _ in range(1000):
        samples.append(ask())
    elapsed = time.perf_counter() - start
    samples.sort()
    print("macOS, release build, one serial UDP client, warm api.example.com A")
    print(f"cold_us={cold:.1f} requests=1000 elapsed_s={elapsed:.6f} qps={1000 / elapsed:.1f} p50_us={statistics.median(samples):.1f} p99_us={samples[989]:.1f}")
    print("Client-inclusive baseline, not production capacity or internet performance.")
finally:
    server.terminate()
    server.wait(timeout=5)
